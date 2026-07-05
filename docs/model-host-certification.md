# Model host GPU certification

*Last modified: 2026-07-05*

The model host's core is hardware-independent and unit-tested on CPU
(see [model-host.md](model-host.md)). The parts that only a real GPU
and a real engine can prove, that a model loads, serves tokens,
recovers from a crash, and evicts under pressure, are certified on a
cloud GPU with this procedure. It is written for a single NVIDIA L4
(24 GB, Ada, FP8-capable) on GCP, which is the reference certification
target.

The GPU-only code is behind two off-by-default cargo features so the
normal build and CI stay lean and GPU-free:

- `gpu-nvidia` turns on `NvmlGpuProbe` (real VRAM / compute-capability
  discovery via NVML, with an `nvidia-smi` fallback).
- `weights` turns on the Hugging Face weight download.

## 1. Provision an L4

```bash
gcloud auth login                       # interactive, once
scripts/provision-l4.sh up              # g2-standard-8 + 1x L4, CUDA image
scripts/provision-l4.sh ssh
```

Check L4 quota first if `up` fails with a quota error:

```bash
gcloud compute regions describe us-central1 \
  --format="value(quotas)" | tr ',' '\n' | grep -i l4
```

Tear the VM down when finished, so billing stops:

```bash
scripts/provision-l4.sh down
```

## 2. Install the engine and build sbproxy (on the box)

```bash
# vLLM in a uv venv (or a container; see the design doc).
pipx install uv && uv venv && uv pip install vllm

# Build sbproxy with the GPU features on. A from-scratch box also needs
# cmake, clang, protobuf-compiler, and python3-dev (see the test-tier
# note at the end).
cargo build --release -p sbproxy --features gpu-nvidia,model-weights
```

## 3. Run with a serve: config and certify

Point an `ai_proxy` provider at a small model with a `serve:` block
(see [`examples/ai-local-serving`](../examples/ai-local-serving)), start
the proxy, then:

```bash
MODEL=qwen3-8b ENGINE_PID=<engine pid> scripts/certify-model-host.sh
```

The script checks the Definition of Done:

1. the first call returns tokens (cold load allowed a long timeout);
2. the second call is materially faster (model resident);
3. `kill -9` on the engine is recovered from and the next call serves;
4. an FP8 request is accepted on the L4 (and, on a T4, refused with a
   capability message rather than a generic error).

A second model larger than the remaining VRAM should evict the idle
one rather than OOM; drive that by requesting two models in sequence
and watching `sbproxy_model_host_evictions_total` and
`sbproxy_model_host_resident_models`.

## 4. Lower-end card (optional)

To certify the capability gate on Turing, repeat on a T4 (16 GB, no
FP8): an FP8-only model must be refused with a capability message and
the planner must fall back to an int4 / GGUF quant. The `nvidia-l4`
accelerator in `provision-l4.sh` becomes `nvidia-tesla-t4` with an
`n1` machine type.

## What this certifies

Passing this closes the hardware-gated half of the model-host epic: the
`NvmlGpuProbe`, the weight download, and the launcher driving a real
vLLM, end to end. The CPU-tested planner, supervisor state machine,
residency manager, and metrics do not change; this proves they hold
against real hardware.

## Test tiers (the CI matrix)

The model host is tested in two tiers, because the interesting parts
split cleanly into "runs anywhere" and "needs a real GPU."

**Tier 0, CPU, every push (CI).** The whole crate except the two
GPU/network cargo features. This is the bulk of the coverage and runs
in the normal workspace gate (`cargo nextest run --workspace`): the fit
planner and capability gate (synthetic T4/L4 descriptors via
`StaticGpuProbe`), the KV-quant lever, the supervisor state machine and
backoff, the residency/eviction solver (evict-large-idle, pinned
protection, reload-cost tiebreak), the launch-spec argv templates, the
metadata parser, the sleep/wake client (against a mock endpoint), the
`ModelHostRuntime` orchestration (with a fake launcher), the metrics
observer seam, and the request-path resolution (`resolve_served_base_url`
against a fake engine that binds a real loopback endpoint). The
`gpu-nvidia` and `weights` features are off here, so CI needs no GPU,
no CUDA, and no network.

**Tier 1, real GPU, manual.** The code Tier 0 cannot exercise: NVML
discovery, the Hugging Face weight pull, and a launcher spawning a real
vLLM / llama-server. This is the procedure above, driven by the
`gpu_cert` example built with `--features gpu-nvidia,weights`. Its modes
map to what each certifies: `probe` (NVML + capability gate + throughput),
`weights` (HF pull), `runtime` (spawn to tokens, evict-reap-reload),
`sleepwake` (vLLM sleep/wake), `llamacpp` (llama.cpp GGUF serve),
`translators` (structured-output / tool-calling / Open-Responses through
the served engine), and the full binary end-to-end (a `serve:`-only
config, `POST /v1/chat/completions`, `/admin/model-host/status`,
`/metrics`).

There is no cloud-GPU CI runner today, so Tier 1 is run by hand on an L4
(and a T4 for the capability-refusal path) at feature-complete points,
not per push. A fresh Deep Learning image also needs `cmake`, `clang`,
`protobuf-compiler`, and `python3-dev` for the full binary and for
vLLM's runtime `torch.compile`; the `gpu_cert` example alone needs none
of these.

## Embedded engine (mistral.rs)

The in-process embedded engine (WOR-1658, `engine: embedded`) runs a
model inside the gateway with no subprocess, behind the off-by-default
`embedded` cargo feature. It has its own cert mode, since it neither
spawns a process nor uses the Hugging Face weight-pull path (mistral.rs
does its own download):

```bash
# HF_TOKEN is required for gated repos such as Gemma.
HF_TOKEN=hf_... cargo run --release --example gpu_cert \
  --features embedded,gpu-nvidia -- embedded google/gemma-2-2b-it
```

This loads the model with mistral.rs (in-situ 4-bit quantized), serves
it on a loopback OpenAI endpoint, and asserts a `/v1/chat/completions`
request returns tokens. It certifies the whole embedded path:
`ModelBuilder` load, the axum server, and the runtime routing to it like
any other engine. Repeat with a Qwen or Llama id to confirm other
architectures. Gemma is Hugging Face-gated, so accept the license and
set `HF_TOKEN`; without it the load fails with an auth error. The
`embedded` feature pulls the (large) mistral.rs + candle trees, so build
it only for this cert, not in the default binary.
