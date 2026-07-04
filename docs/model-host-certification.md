# Model host GPU certification

*Last modified: 2026-07-04*

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

# Build sbproxy with the GPU features on.
cargo build --release -p sbproxy \
  --features sbproxy-model-host/gpu-nvidia,sbproxy-model-host/weights
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
