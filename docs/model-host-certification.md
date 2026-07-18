# Model host hardware certification

*Last modified: 2026-07-13*

This page separates evidence already produced by deterministic tests from work
that requires a real accelerator. It is an evidence ledger and a repeatable
procedure. Passing a simulated GPU test is never recorded as live hardware
certification.

## Current evidence

| Target | Status | Evidence |
|---|---|---|
| CPU contracts | covered in CI | Artifact, driver, fit, admission, reconcile, reload, and CLI suites. |
| Apple Silicon Metal | passed 2026-07-11 | Real managed GGUF completion, status and stop truth, cache reuse, maintenance health, and ready-engine Ctrl-C shutdown on Apple M4 Max. |
| NVIDIA CUDA single node | pending final GCP PR | Deterministic T4/L4 descriptors, vLLM plans, and container isolation tests exist. No live claim is made in this PR. |
| NVIDIA multi-GPU | pending final GCP PR | Placement and device-scoping tests only. |
| Local multi-process cluster control | passed 2026-07-11 | Four real processes, enrolled identities, signed gossip and state, node-specific mTLS, controller restart fencing, rolling and recreate transitions, worker loss, post-GC tombstone, partition callout, digest mismatch and recovery, and child cleanup. |
| Local three-process data plane | passed 2026-07-13 | A gateway and two workers prove authenticated HTTP/2 dispatch, logical discovery, unary and SSE responses, coordinated cold start, pre-output failover, no mid-stream replay, cancellation, permit release, and absence of the bearer sentinel from worker logs. |
| Three-node GCP runtime | pending final GCP PR | Local control and data planes are complete. Live GCP networking, NVIDIA engines, and hardware evidence remain pending. |

The generated [capability matrix](model-host-capabilities.md) records Apple
Metal and the deterministic cluster control plane as stable. Remote dispatch,
NVIDIA, and GCP multi-node certification stay at `preview` until their owning
executable and live gates are recorded.

### Local data-plane evidence from 2026-07-13

The hermetic fixture runs a gateway and two worker processes with distinct
gossip, typed-state, admin, model-plane, and loopback engine ports. It uses an
explicit development shared key so it can run in CI without an enrollment
authority. Production mTLS authentication has separate envelope, HTTP/2, TLS,
and peer-identity tests.

```bash
cargo build -p sbproxy
SBPROXY_E2E_BIN=target/debug/sbproxy \
  cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture
```

The gate proves:

- `/v1/models` exposes one logical model with aggregate availability and no
  node ID, endpoint, or loopback address;
- two concurrent cold requests share one assigned engine launch;
- live reload expands the deployment to two current replicas before failure
  drills begin;
- unary and SSE requests traverse a peer, preserve usage and safe route
  headers, and leave no public bearer sentinel in worker stdout or stderr;
- a retryable failure before output selects the other current replica;
- a worker failure after the first SSE frame produces partial output without
  replaying on the second replica;
- dropping a client stream cancels the peer and engine work, then a following
  request proves the admission permit was released;
- graceful fixture shutdown reaps every proxy and engine process.

This is executable local distributed-serving evidence, not live GCP or NVIDIA
certification. The split-role example separately documents the production mTLS
configuration.

### Local multi-process evidence from 2026-07-11

The hermetic fixture runs one authority, one gateway, and two workers as real
`sbproxy` child processes. It uses the production enrollment authority to
create signed per-node identities, unique keys and certificates, an
authenticated gossip key, distinct state and model caches, and temporary
UDP, transport, proxy, admin, and engine ports. A tiny local catalog artifact is
verified through the production artifact manager and launched through the typed
llama.cpp driver into an e2e-only health server.

```bash
cargo build -p sbproxy
SBPROXY_E2E_BIN=target/debug/sbproxy \
  cargo test -p sbproxy-e2e --test model_cluster_control -- --nocapture
```

The gate proves:

- every process converges on the same eligible directory and exact assignment;
- restarting a controller with unchanged desired state preserves deployment
  generation and assignment identity;
- rolling replacement starts and observes the target before removing the prior
  replica, while recreate publishes a drain-only phase before starting the
  target generation;
- the key cache and model controller reuse one gossip and transport mesh;
- a control-only node can retain a non-builtin global catalog without creating
  an engine;
- removing the assigned worker keeps it in the full node roster, excludes it
  from model eligibility, and adds a nonempty `unhealthy_nodes` alert;
- the tombstone and callout remain after the two-second routing-membership GC;
- the remaining worker takes the deterministic replacement assignment and
  reports exact readiness before every surviving admin view converges;
- a signed restart with an unreachable gossip advertisement is called out as a
  partition, while a correct replacement receives the full authenticated
  roster and fences stale dead gossip;
- a file-managed desired-state mismatch excludes unsafe workers, then clears
  when the replacement returns with matching content;
- graceful proxy shutdown releases gossip, transport, admin, and fake-engine
  resources, and the test verifies no child process remains.

Pure placement, directory, and rollout suites additionally prove suspect,
dead, unreachable, stale, malformed, and incompatible exclusion; minimal
movement; partition-local routing; per-deployment generation fencing; and
rolling versus recreate ordering. This is local control-plane certification,
not GCP or remote inference certification.

### Apple Metal evidence from 2026-07-11

The PR gate ran on arm64 macOS 26.5.1 build 25F80, Apple M4 Max, with 36 GiB
of memory. The branch worktree was based on `36d95ddd`; the PR description
records the final review-fix commit that contains the same runtime code.

- Model: `qwen2.5-0.5b-instruct:q4_k_m`
- Managed engine: llama.cpp b9905 on Metal
- Artifact identity: `830f2915ca0008994cbddaeba38634f6e999d34fea89c048ebb73753be0a0591`
- Engine archive SHA-256: `0d3deb02fd7912c8ef360fa33b3b4a8c97967a3ac703c0ed7d5edd3680723ea8`
- Completion content: `Ready`
- Ready status: deployment `local`, state `ready`, top-level `serving: true`, and `local_serving.ready: true`
- Stopped status: deployment `local`, state `stopped`, top-level `serving: false`, and `local_serving.ready: false`
- Cache reuse: the verified engine archive mtime remained `1783790888` across the repeated launch
- Shutdown: Ctrl-C exited the gateway cleanly and the observed ready engine PID `8710` was absent afterward
- Maintenance: repeated health ticks completed without a Tokio panic

## Deterministic gate

These suites run without a GPU and must pass before any hardware run:

```bash
cargo test -p sbproxy-model-host --test engine_drivers
cargo test -p sbproxy-model-host --test cuda_build
cargo test -p sbproxy-model-host --test runtime_reconcile
cargo test -p sbproxy-model-host --test local_admission
cargo test -p sbproxy-core --test model_host_reload
cargo test -p sbproxy --test models_lifecycle_cli
cargo test -p sbproxy-model-host --test placement
cargo test -p sbproxy-model-host --test capability_contract
cargo test -p sbproxy-ai --test managed_replica_routing
cargo test -p sbproxy-core --test cluster_control_plane
cargo test -p sbproxy-core --test model_plane_envelope --test model_plane_transport --test managed_replica_dispatch
cargo test -p sbproxy-e2e --test model_cluster_control -- --nocapture
cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture
```

They prove immutable artifact selection, process argv, container isolation,
source-build publication, per-device capacity, bounded queue behavior, atomic
rollback, status shape, and CLI contracts. They cannot prove a driver loads a
model or returns tokens on real hardware.

## Apple Metal gate for this PR

Use an isolated cache and ports on Apple Silicon:

```bash
export SBPROXY_SMOKE_CACHE="$(mktemp -d)"
sbproxy run qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --cache-dir "${SBPROXY_SMOKE_CACHE}" \
  --port 48123 \
  --admin-port 48124
```

After the ready banner:

```bash
curl http://127.0.0.1:48123/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"qwen2.5-0.5b-instruct","messages":[{"role":"user","content":"Return only the word ready."}]}'

export SB_ADMIN_URL=http://127.0.0.1:48124
export SB_ADMIN_USERNAME=admin
export SB_ADMIN_PASSWORD='paste-the-generated-password'
sbproxy models ps --format json
sbproxy models stop local --format json
```

The completion must contain nonempty assistant content. Status must report
deployment `local`, state `ready`, engine `llama_cpp`, a Metal-selected worker,
and the verified artifact digest. Stop must reach `stopped` without deleting the
snapshot. A second run against the same cache must verify a cache hit without
another weight download.

Record the final binary revision and retained command output in the PR
description. The evidence above promotes the Apple capability from `preview`
to `stable`; regenerate the matrix whenever this record changes.

## Final GCP NVIDIA gate

The user explicitly reserved NVIDIA and live GCP multi-node validation for the
final PR group. Run this procedure only after the distributed data plane,
governance, and operator-product slices have landed.

### Provision an L4 worker

```bash
export SBPROXY_GCP_PROJECT="your-gcp-project-id"
: "${SBPROXY_GCP_PROJECT:?export SBPROXY_GCP_PROJECT first}"
gcloud auth login
scripts/provision-l4.sh up
scripts/provision-l4.sh ssh
```

Set `SBPROXY_GCP_PROJECT` explicitly in every certification shell before using
the provisioning script. Do not rely on the script's development project
default for a billable hardware run.

Check regional quota if provisioning fails:

```bash
gcloud compute regions describe us-central1 \
  --project="${SBPROXY_GCP_PROJECT}" \
  --format='value(quotas)'
```

Tear the VM down after the run:

```bash
: "${SBPROXY_GCP_PROJECT:?export SBPROXY_GCP_PROJECT first}"
scripts/provision-l4.sh down
```

### Single-node vLLM

Use a catalog v2 safetensors artifact and canonical engine policy:

```yaml
proxy:
  model_host:
    engines:
      vllm:
        launch: uv
        version: 0.10.0
        acceleration: cuda
    deployments:
      gpu-qwen:
        model: REPLACE_WITH_CERTIFIED_SAFETENSORS_MODEL
        variant: REPLACE_WITH_PINNED_VARIANT
        pull: on_boot
        warm: true
        engine: vllm
```

The gate must prove all of the following with retained logs and status output:

1. NVML or the `nvidia-smi` fallback reports the exact device and compute
   capability.
2. The artifact downloads once, verifies, and reaches the immutable snapshot.
3. Managed uv provisions the pinned vLLM version and passes Python, torch, and
   CUDA compatibility checks.
4. A chat completion returns nonempty assistant content through the gateway.
5. Status reports selected device, artifact digest, memory breakdown, engine
   port, active and queued counts, and ready state.
6. Stop drains, reaps the engine process tree, and preserves verified bytes.
7. Restart reuses the artifact and managed environment.

Repeat with a digest-pinned container. Inspect the exact Docker or Podman argv,
private network, loopback port, read-only snapshot mount, selected devices, and
shared-memory bound.

### T4 capability refusal

Repeat the compatibility portion on a T4. An FP8-only artifact must fail with a
bounded incompatibility reason, while a compatible int4 or GGUF variant may be
selected. A generic engine error is not acceptable evidence.

### Multi-node gate

Provision three GCP nodes with mixed labels or devices. Record membership
convergence, deterministic placement, peer identity, signed revision
propagation, request dispatch, node loss, replacement, and fleet CLI and admin
status. A worker must never select a variant outside the catalog or receive an
artifact path from another node without passing the peer and artifact trust
boundaries. Capture the complete roster and unhealthy-node alert before and
after recovery.

## Evidence retention

For every live run, retain:

- git revision and dirty status;
- binary version and feature set;
- operating system, kernel, driver, CUDA, container runtime, and engine versions;
- catalog revision, logical model, variant, source revision, and artifact digest;
- generated config with secrets removed;
- readiness, completion, status, stop, and restart output;
- relevant `sbproxy_model_host_*` metrics;
- failure logs for every expected refusal;
- GCP machine type, accelerator type, zone, and teardown confirmation.

Do not promote a capability from this checklist alone. Promotion requires the
recorded output attached to the PR and a deterministic regression test for any
bug found during the hardware run.
