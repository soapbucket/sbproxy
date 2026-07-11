# Model host hardware certification

*Last modified: 2026-07-10*

This page separates evidence already produced by deterministic tests from work
that requires a real accelerator. It is an evidence ledger and a repeatable
procedure. Passing a simulated GPU test is never recorded as live hardware
certification.

## Current evidence

| Target | Status | Evidence |
|---|---|---|
| CPU contracts | covered in CI | Artifact, driver, fit, admission, reconcile, reload, and CLI suites. |
| Apple Silicon Metal | pending before this PR is published | One real managed GGUF completion, status query, stop, and cache reuse on the development Mac. |
| NVIDIA CUDA single node | pending final GCP PR | Deterministic T4/L4 descriptors, vLLM plans, container isolation, and CUDA llama.cpp source-build tests exist. No live claim is made in this PR. |
| NVIDIA multi-GPU | pending final GCP PR | Placement and device-scoping tests only. |
| Three-node GCP runtime | pending final GCP PR | Cluster membership, placement, peer transport, and fleet operations land in later PR groups. |

The generated [capability matrix](model-host-capabilities.md) keeps Apple and
NVIDIA platform claims at `preview` until the corresponding live gate is
recorded.

## Deterministic gate

These suites run without a GPU and must pass before any hardware run:

```bash
cargo test -p sbproxy-model-host --test engine_drivers
cargo test -p sbproxy-model-host --test cuda_build
cargo test -p sbproxy-model-host --test runtime_reconcile
cargo test -p sbproxy-model-host --test local_admission
cargo test -p sbproxy-core --test model_host_reload
cargo test -p sbproxy --test models_lifecycle_cli
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

Record the exact binary revision, macOS version, chip, memory, engine version,
artifact digest, command output, and elapsed times in the PR description. After
that evidence exists, promote the Apple capability from `preview` to `stable`
and regenerate the matrix.

## Final GCP NVIDIA gate

The user explicitly reserved NVIDIA and multi-node validation for the final PR
group. Run this procedure only after the cluster and fleet slices have landed.

### Provision an L4 worker

```bash
gcloud auth login
scripts/provision-l4.sh up
scripts/provision-l4.sh ssh
```

Check regional quota if provisioning fails:

```bash
gcloud compute regions describe us-central1 \
  --format='value(quotas)'
```

Tear the VM down after the run:

```bash
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

### CUDA llama.cpp

On Linux x86-64 with the NVIDIA toolkit installed, configure llama.cpp binary
launch with `acceleration: cuda`. The gate must show the official source archive
digest, shared build lock, successful CMake CUDA build, atomic executable
publication, GGUF load, and a completion through the gateway. Repeat once from
the ready build cache to prove no rebuild occurs.

### T4 capability refusal

Repeat the compatibility portion on a T4. An FP8-only artifact must fail with a
bounded incompatibility reason, while a compatible int4 or GGUF variant may be
selected. A generic engine error is not acceptable evidence.

### Multi-node gate

After cluster authority exists, provision three GCP nodes with mixed labels or
devices. Record membership convergence, deterministic placement, peer identity,
revision propagation, request dispatch, node loss, replacement, and fleet CLI
status. A worker must never select a variant outside the catalog or receive an
artifact path from another node without passing the peer and artifact trust
boundaries.

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
