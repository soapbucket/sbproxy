# Model host hardware certification

*Last modified: 2026-07-30*

This page is the evidence ledger for the self-host matrix, and the procedure
that reproduces it. Passing a simulated GPU test is never recorded as live
hardware certification.

A lane is `passed` only when its command ran on real hardware and succeeded. A
host that cannot provide what a lane needs is recorded `unsupported` with the
reason, and a capability is not promoted to `stable` in the [capability
matrix](model-host-capabilities.md) without a dated record below. Every
selected lane gets a verdict, so a gap in the matrix is visible rather than
absent.

## Running the matrix

`scripts/certify-selfhost.sh` is the runner. One reproducible command per lane,
a recorded expected result, captured host and version metadata, and retained
per-lane logs.

```bash
scripts/certify-selfhost.sh list          # the lane table and what each asserts
scripts/certify-selfhost.sh metadata      # what this host would record
scripts/certify-selfhost.sh run local     # every lane needing no accelerator
scripts/certify-selfhost.sh run all       # add the hardware lanes
scripts/certify-selfhost.sh run apple_metal nvidia_single_gpu
```

Evidence lands in `.cert-evidence/<utc-timestamp>/`: a `metadata.json` with the
git revision and dirty flag, binary version, OS, kernel, driver, CUDA,
container runtime, and visible device count; a `summary.tsv` with one row per
lane; and a `<lane>.log` per lane carrying the exact command, the expected
result, and the full output. The runner exits non-zero if any lane failed. An
`unsupported` lane does not fail the run, because a missing accelerator is a
gap to report, not a regression.

`run local` is the pre-hardware gate. It must be green before a GPU box is
billed.

## Current evidence

| Lane | Status | Recorded |
|---|---|---|
| Deterministic model-host suites | passed 2026-07-30 | Artifact, driver, fit, admission, reconcile, reload, capability, and CLI suites. |
| CPU admission | passed 2026-07-30 | Local admission and cold-start policy on an accelerator-free path. |
| Apple Silicon Metal | **rerun required** | The 2026-07-30 M4 Max run passed 11 of 12 checks. The listener/engine lifecycle defect behind the failed check now has deterministic real-process coverage and a blocking Apple-lane assertion, but the updated lane has not yet run on live Apple hardware. |
| NVIDIA CUDA single GPU | passed 2026-07-30 | Live vLLM container completion on an NVIDIA L4: NVML probe, fit plan, public model echo, full status, and a stop that returned the device to 0 MiB. |
| NVIDIA multi-GPU | unsupported | Needs two visible devices. The billing account this project runs under is capped at one GPU, so the lane has never had hardware to run on. Detail below. |
| Air-gapped | passed 2026-07-30 | Offline, manual, and file pull policies short-circuit transport; a digest mismatch fails closed. |
| Split cluster (gateway plus workers) | passed 2026-07-30 | Authenticated dispatch, logical discovery, unary and SSE, coordinated cold start, pre-output failover. |
| Symmetric cluster | passed 2026-07-30 | Four real processes converge on one directory and assignment, signed gossip, node-specific mTLS, controller restart fencing. |
| Three-node kill test | passed 2026-07-30 | Directory exclusion, roster retention, unhealthy-node alert, and failover before first output. |
| Rolling deployment update | passed 2026-07-30 | Prepare and observe the target before removing the prior replica; no unrelated-engine restart. |
| Clustered key revoke | passed 2026-07-30 | A key revoked on one gateway is refused by a peer within two seconds. |
| Strict budget under concurrency | passed 2026-07-30 | Two gateways never admit more than the shared strict request limit. |
| External provider fallback | passed 2026-07-30 | A managed cold start advances to a cloud provider in the same array. |
| Managed-worker startup gate | passed 2026-07-30 | Refuses an unsatisfiable config with exit 3 and a named blocker per check, on both macOS and NVIDIA hosts. |
| Capability matrix | passed 2026-07-30 | The generated matrix matches the registry. |
| Three-node live GCP runtime | unsupported | Blocked by the same one-GPU cap: a three-worker GPU fleet cannot be provisioned. Local multi-process control and data-plane evidence stands in. |

## Apple Silicon evidence from 2026-07-30

Recorded on arm64 macOS 26.5.2 build 25F84, Apple M4 Max, 36 GiB of memory,
binary `sbproxy 1.9.0` at revision `2ef06ad0`.

```bash
scripts/certify-selfhost.sh run apple_metal
```

Eleven of twelve checks passed at that revision. The failed lifecycle behavior
has since been fixed in code; this historical evidence is not promoted to a
pass until the updated lane reruns on Apple hardware.

- Model: `qwen2.5-0.5b-instruct:q4_k_m`
- Managed engine: llama.cpp b9905 on Metal, selected device `[0]`
- Artifact identity: `830f2915ca0008994cbddaeba38634f6e999d34fea89c048ebb73753be0a0591`,
  identical across both runs
- Start to ready: 8 seconds against a warm artifact cache, 11 seconds on the
  second run; 65 seconds when the first 469 MB weight pull and its digest
  verification are included
- Completion content: `ready`, returned through the gateway
- Echoed `model` field: `qwen2.5-0.5b-instruct`, the public name, never the
  weights path
- Status while ready: `state: ready`, `serving: true`, engine `llama_cpp`
  version `b9905`, a full memory breakdown, and the engine's loopback port
- Status after stop: `state: stopped`, `serving: false`, snapshot preserved
- Stop reaped the engine process
- SIGINT exited the gateway in 1 second with no engine orphaned
- Cache reuse: zero download lines on the second run, same artifact digest
- **Failing check:** the public port was still bound 60 seconds after
  shutdown, by a surviving `sbproxy` process

### Lifecycle fix awaiting live Apple rerun

The four failures from the 2026-07-30 run now have explicit contracts:

- Pingora binds and retains the actual public sockets before `Server::run`.
  Address collisions return a startup error containing the address and OS
  cause; they no longer panic only a background listener task.
- SIGTERM returns through the gateway shutdown guards, verifies the managed
  engine exited, removes its durable ownership record, and releases the public
  listener.
- The launchd bootstrap registers every exact gateway generation before it can
  execute. `service uninstall` holds the same lifecycle lock across unload,
  reads the ownership directory from the service environment file, and keeps
  the plist plus retry state until every registered owner's engine cleanup
  succeeds. A loaded legacy plist without registration fails closed.
- A managed child blocks before `exec` until its owner and engine
  fingerprints are on durable storage. Persistence failure stops the child
  before it can execute. An `exec` failure is reported through the normal
  bounded early-exit diagnostics and clears the durable record. After SIGKILL,
  the next boot reaps an exact stale process group before binding listeners or
  spawning a replacement. A live owner is preserved. A reused engine PID is
  never signalled; when its process group is still occupied, the record stays
  in place because ownership cannot be proved. Linux uses a parent-death
  signal. macOS uses `posix_spawn` plus private atomically close-on-exec gate
  endpoints, so parent exit closes the gate without a concurrent-fork fd leak.

Focused real-process tests cover collision failure, SIGTERM plus same-port
rebind, blocked startup until durable ownership, persistence and exec failure,
process-group reap, live-owner preservation, PID-reuse preservation, safe
concurrent spawn gates, exact launchd generation registration, legacy-plist
refusal, killed-owner recovery, fast-exit diagnostics, and record removal after
normal shutdown. The release Apple lane now derives engine PIDs from those
ownership records, exercises gateway SIGKILL/restart and the real
`service uninstall`, then requires engine cleanup and a same-port bind. That
lane still needs a live Apple runner result.

### Sleep and wake

Not automated: suspending the certification host would end the run that is
recording the evidence. Documented expectation instead. `KeepAlive` restarts
the agent if the process dies across a sleep cycle, and the artifact cache is
content-addressed on disk, so a wake reuses verified weights with no
re-download. Durable ownership recovery runs before a replacement engine
starts.

## NVIDIA CUDA single-GPU evidence from 2026-07-30

Recorded on GCP `g2-standard-8` (8 vCPU, one NVIDIA L4) in `us-east1-b`, Ubuntu
kernel `6.8.0-1063-gcp`, NVIDIA driver `580.159.03`, Docker `29.6.2`, binary
`sbproxy 1.9.0` at revision `2ef06ad0` built from source on the box.

Probe, through sbproxy's own detection rather than parsed `nvidia-smi`:

- Device: NVIDIA L4, `24152899584` bytes total, compute capability 8.9
- FP8 kernels: available
- Memory bandwidth: 300 GB/s
- `/dev/shm`: 16825987072 bytes
- Container runtime: Docker, daemon reachable

Startup gate against a worker config, every check on real values:

```
driver                 pass  NVIDIA driver 580.159.03 present
visible_devices        pass  1 accelerator(s) visible to the probe
cuda_compatibility     pass  all 1 configured serve entries resolve to an engine this host can run
shared_memory          pass  /dev/shm is 15.7 GiB, at or above the 8.0 GiB the config asks for
cache_mount            pass  /home/rick/.cache/sbproxy/models has 64.8 GiB free for the 40 GiB cache budget
model_plane_identity   pass  worker node presents complete shared-key identity material
verdict: pass (no startup blocker on this host)
```

Live serving, digest-pinned vLLM container, raw `hf:Qwen/Qwen3-0.6B`:

- Cold completion: HTTP 200 in 163 seconds, including the weight pull and vLLM
  engine initialization
- Warm completion: HTTP 200 in 0.109 seconds
- Echoed `model` field: `qwen3-06b`, the configured public name, not the
  `hf:` reference
- Engine: vLLM `0.10.1.dev1+gbcc0a3cbe`, image pinned by the
  `sha256:05a31dc4...878271` digest
- Selected device `[0]`, engine loopback port `40855`
- Artifact digest: `2208fff05b0093aa39a82a19ac63fa5062846163e330b99d0ba1fa337b3c5f2d`
- Memory breakdown: 1074528256 weight bytes, 4697620480 KV bytes, 865822310
  runtime overhead, 663797104 safety margin, 7301768150 total
- Device memory in use while ready: 9126 MiB
- Stop: state `stopped`, `serving: false`, container torn down, device memory
  back to 0 MiB

A reconcile refusal was also recorded as legible rather than generic. A
deployment pinning `engine: vllm` against a GGUF-only variant failed at boot
with `model 'qwen3-8b' has no compatible artifact variant: q4_k_m: no
compatible selected engine on worker`, not a stack trace and not a hang.

## NVIDIA multi-GPU: why the lane is unsupported

The lane needs two visible devices. It has never had them.

```
$ gcloud compute regions describe us-east1 --format='value(quotas)'
NVIDIA_L4_GPUS 0.0 / 1.0
$ gcloud compute project-info describe --format='value(quotas)'
GPUS_ALL_REGIONS 0.0 / 1.0
```

The cap is on the billing account, not the project, and it is one GPU. Every
self-service increase request against it has been auto-denied, so switching
project does not route around it. Lifting this needs a billing-side change or
a different established account.

What that leaves:

- Device-set math, disjoint device-group packing for tensor parallelism, and
  the oversubscription refusal are covered deterministically by
  `runtime_replicas` and `placement`, which run in the `deterministic` lane.
- The startup gate's `cuda_compatibility` check reports `skip`, not `pass`, for
  a `proxy.model_host` deployment whose per-device fit it did not evaluate. It
  will not claim a multi-GPU config is servable on evidence it does not have.
- `platform.nvidia_cuda` stays below an unqualified claim in the capability
  matrix while this lane is open.

The epic gate "a 70B model runs on a 2-GPU box" cannot be closed from this
account. It is a hardware-access problem, not a code problem.

## Deterministic gate

These suites run without a GPU and must pass before any hardware run. The
`deterministic`, `cpu`, `air_gapped`, and `rolling_update` lanes cover them;
run them directly when iterating:

```bash
cargo nextest run -p sbproxy-model-host -p sbproxy-capability --no-fail-fast
cargo test -p sbproxy-core --test model_host_reload
cargo test -p sbproxy --test models_lifecycle_cli
cargo test -p sbproxy-ai --test managed_replica_routing
cargo test -p sbproxy-core --test cluster_control_plane
cargo test -p sbproxy-core --test model_plane_envelope --test model_plane_transport --test managed_replica_dispatch
SBPROXY_E2E_BIN=target/debug/sbproxy cargo test -p sbproxy-e2e --test model_cluster_control -- --nocapture
SBPROXY_E2E_BIN=target/debug/sbproxy cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture
```

They prove immutable artifact selection, process argv, container isolation,
source-build publication, per-device capacity, bounded queue behavior, atomic
rollback, status shape, and CLI contracts. They cannot prove a driver loads a
model or returns tokens on real hardware.

## Provisioning a GPU box for the NVIDIA lanes

```bash
export SBPROXY_GCP_PROJECT="your-gcp-project-id"
: "${SBPROXY_GCP_PROJECT:?export SBPROXY_GCP_PROJECT first}"
gcloud auth login
scripts/provision-l4.sh up
scripts/provision-l4.sh ssh
```

Set `SBPROXY_GCP_PROJECT` explicitly in every certification shell. Do not rely
on the provisioning script's development default for a billable run.

Check quota first if provisioning fails, and read both numbers: the
per-region-per-type quota and the global `GPUS_ALL_REGIONS`. Booting N devices
needs both at N or above.

```bash
gcloud compute regions describe us-east1 --project="${SBPROXY_GCP_PROJECT}" \
  --format='value(quotas)'
gcloud compute project-info describe --project="${SBPROXY_GCP_PROJECT}" \
  --format='value(quotas)'
```

Tear the VM down as soon as the run is recorded. A GPU instance left running is
the most expensive way to store evidence.

```bash
: "${SBPROXY_GCP_PROJECT:?export SBPROXY_GCP_PROJECT first}"
scripts/provision-l4.sh down
```

Prefer the digest-pinned container over a host toolchain for vLLM. A host
`uv`/`pip` install resolves to whatever is newest, needs Python headers and a C
toolchain for the Triton JIT, and cascades; the pinned image packages the whole
environment and serves cleanly. `deploy/terraform/l4-demo/bootstrap-generic.sh`
takes the container path by default and boots behind the startup gate.

### T4 capability refusal

Repeat the compatibility portion on a T4. An FP8-only artifact must fail with a
bounded incompatibility reason while a compatible int4 or GGUF variant is
selected. A generic engine error is not acceptable evidence.

## Evidence retention

`scripts/certify-selfhost.sh` records most of this automatically. For every
live run, retain:

- git revision and dirty status;
- binary version and feature set;
- operating system, kernel, driver, CUDA, container runtime, and engine versions;
- catalog revision, logical model, variant, source revision, and artifact digest;
- generated config with secrets removed;
- readiness, completion, status, stop, and restart output;
- relevant `sbproxy_model_host_*` metrics;
- failure logs for every expected refusal;
- GCP machine type, accelerator type, zone, and teardown confirmation.

Do not promote a capability from this checklist alone. Promotion requires
retained output tied to the tested revision, and a deterministic regression
test for any bug the hardware run found.
