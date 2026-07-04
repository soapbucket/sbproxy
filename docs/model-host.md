# Model host

*Last modified: 2026-07-04*

The model host lets the gateway run the model itself, not just proxy to
a model server someone else started. You name a model in a provider's
`serve:` block, and sbproxy resolves it to weights, fits an inference
engine to the local GPU, spawns and supervises that engine, and
registers it as a local provider that sits ahead of any cloud fallback
in the same routing, guardrail, budget, and usage-ledger planes every
other provider uses. It is single-node and Apache-2.0; fleet placement
across many nodes is separate work.

## Status

This is landing in phases. What ships today is the hardware-independent
core: the model catalog and its resolver, the `serve:` config surface,
the GPU fit planner (which quant fits and runs on a given card), and
the engine-supervisor state machine. The pieces that need real hardware
or a real engine, GPU discovery, Hugging Face weight download, and
spawning vLLM or llama.cpp, plug in behind the traits this core defines
(`GpuProbe`, `EngineLauncher`) and are certified against actual GPUs in
later phases. On a host with no GPU or no engine binary, a `serve:`
block parses and validates but starts no engine.

## The `serve:` block

`serve:` hangs off an `ai_proxy` provider:

```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: local
          base_url: http://127.0.0.1:8000/v1
          allow_private_base_url: true
          default_model: qwen3-14b
          models: [qwen3-14b]
          serve:
            eviction: lru          # or `never`
            cache_budget_gib: 200
            models:
              - model: qwen3-14b   # a catalog id
                engine: vllm
                keep_alive: 30m
              - model: hf:Qwen/Qwen3-8B-GGUF:Q4_K_M  # explicit ref
                engine: llama_cpp
                keep_alive: 15m
```

A model is either a catalog id (see below) or an explicit
`hf:Org/Repo:QUANT` reference that bypasses the catalog. `engine` is an
allowlisted enum (`vllm`, `llama_cpp`), never a command string: config
picks an engine and its knobs, and the runtime owns the argument
template. `keep_alive` is the idle time before the engine unloads to
free VRAM; `eviction` decides what happens under VRAM pressure, `lru`
evicts the least-recently-used idle model, `never` pins residency and
refuses a new model when full. See
[`examples/ai-local-serving`](../examples/ai-local-serving).

## The catalog

The catalog maps a short, stable id like `qwen3-32b` to a Hugging Face
repo, its official quant variants, the parameter shape, license,
family, and a coarse VRAM hint. A committed default catalog seeds the
certified-first models so a stock deployment resolves them with no
external fetch; an operator can supply their own catalog file, and can
always skip the catalog with an `hf:` reference. The catalog is data
only: it says what exists, and the fit planner decides what runs.

## The fit planner

The planner answers two questions the naive "does it fit VRAM" check
misses. First, capability: a Turing card (a cloud T4) has no FP8
kernels, so an FP8 quant that would fit by size still cannot run there.
The planner gates on the card's compute capability, so a T4 refuses FP8
with a clear message and falls back to an int4 or GGUF quant, while an
Ada card (an L4) accepts FP8. Second, size: it estimates VRAM as the
weight bytes for the chosen quant plus the KV-cache bytes at the
planned context length, `2 x layers x kv_heads x head_dim x bytes x
seq_len`, times a framework-overhead headroom, and refuses a quant that
would not fit the free VRAM. It walks the catalog's quant list in
preference order and returns the first quant that both runs and fits.

## Metrics

The model host publishes `sbproxy_model_host_*` metrics: engine
time-to-ready, launch and eviction counts, resident-model and
load-queue-depth gauges, and per-device `gpu_vram_bytes` plus
`gpu_utilization`. The utilization gauge is the signal the `gpu-aware`
routing strategy already reads. See
[`metrics-stability.md`](metrics-stability.md).

## Security

The gateway holds provider keys, so spawning subprocesses from config
is a real surface and is constrained deliberately: engines are an
allowlisted enum with runtime-owned argument templates (no arbitrary
`cmd:`), weights verify against a sha256, and engine binaries come from
`PATH` or pinned releases. The dedicated security review is tracked
with the epic.

## Related

- [local-inference.md](local-inference.md) - running embeddings and
  prompt-injection classify on local ONNX models (the sidecar
  precedent this generalizes).
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and
  ledger planes local models plug into.
