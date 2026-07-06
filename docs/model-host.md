# Model host

*Last modified: 2026-07-06*

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
the GPU fit planner (which quant fits and runs on a given card), the
engine-supervisor state machine, the process launcher (it builds the
engine argv, spawns the subprocess, polls a loopback readiness probe,
and kills it), the VRAM-budget residency manager (LRU eviction under a
byte budget), and the hybrid pieces (model aliases and the dollars-saved
math). GPU discovery, Hugging Face weight download, and a real vLLM /
llama.cpp bring-up plug in behind the traits this core defines
(`GpuProbe`, `EngineLauncher`) and are certified against actual GPUs in
later phases. The launcher's spawn / probe / kill machinery is tested
against a fake process; what it cannot prove without hardware is that a
real engine boots and serves tokens. On a host with no GPU or no engine
binary, a `serve:` block parses and validates but starts no engine.

The real GPU bindings ship in the released binary: `gpu-nvidia` (an
NVML `GpuProbe` with an `nvidia-smi` fallback) and `model-weights`
(Hugging Face weight download) are default features of the `sbproxy`
binary, so the artifact you download adapts to its host at runtime. The
NVIDIA driver library is loaded with `dlopen` when present, never
linked, so the same binary runs on a GPU-free host (the probe reports
zero GPUs and `serve:` admission rejects cleanly) and discovers real
devices on a GPU host with no rebuild. Run `sbproxy doctor` to see what
the current host supports: compiled features, visible GPUs, engines on
`PATH`, container runtime, and the `serve:` readiness verdict; add
`--install vllm` or `--install llama-cpp` to acquire a missing engine
(package manager first, or a pinned sha256-verified release for
llama.cpp; see [manual.md](manual.md)). The same prerequisites are
checked when a config loads: a `serve:` block on a host with no
visible GPU, or a serve entry whose engine has no binary and no
container runtime, logs a warning at startup and on every hot reload
naming the model and the blocker. Library consumers of the workspace
crates still opt into these features per crate. The bindings are exercised on
a GPU host; see
[model-host-certification.md](model-host-certification.md) for the
provisioning and Definition-of-Done run on a cloud L4.

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

## The model manifest

Beyond a throwaway model, an operator keeps a manifest: one reviewable
file that says which models exist and everything needed to fetch and
verify them. Point `serve.catalog_file` at it. It is the fleet fact
sheet; `sb.yml` is the box fact sheet (what this box serves, where its
cache lives). Each entry carries a `source` (`hf:Org/Repo`, an
air-gapped `file:` path, or `ms:` reserved for ModelScope), a pinned
`revision`, per-file `sha256` digests (a curated manifest doubles as a
supply-chain allowlist), a gated-repo `hf_token` as a secret reference,
a default `engine`, and a `pull` policy (`on_boot`, `on_demand`,
`manual`). The weight cache defaults to `/var/lib/sbproxy/models` for a
service, honors `$HF_HOME` when set, and is overridable with
`cache_dir`. See [`examples/model-manifest`](../examples/model-manifest).

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
