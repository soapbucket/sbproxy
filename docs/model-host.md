# Model host

*Last modified: 2026-07-09*

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
math). GPU discovery, Hugging Face weight download, and real vLLM /
llama.cpp bring-up plug in behind the traits this core defines
(`GpuProbe`, `EngineLauncher`). These are certified on real GPUs: a GGUF
model serves on Metal on an Apple Silicon Mac, and a safetensors model
serves on an NVIDIA L4 through vLLM with the weights resident in GPU
memory. The launcher's spawn / probe / kill machinery is also tested
against a fake process so the lifecycle is exercised with no hardware. On
a host with no GPU or no engine binary, a `serve:` block parses and
validates but starts no engine.

The real GPU bindings ship in the released binary: `gpu-nvidia` (an
NVML `GpuProbe` with an `nvidia-smi` fallback) and `model-weights`
(Hugging Face weight download) are default features of the `sbproxy`
binary, so the artifact you download adapts to its host at runtime. The
NVIDIA driver library is loaded with `dlopen` when present, never
linked, so the same binary runs on a GPU-free host (the probe reports
zero GPUs and `serve:` admission rejects cleanly) and discovers real
devices on a GPU host with no rebuild. Run `sbproxy doctor` to see what
the current host supports: compiled features, visible GPUs, engines on
`PATH`, container runtime, and the `serve:` readiness verdict, plus the
acquisition options viable here for each engine. The runtime then
acquires the engine on first use rather than leaving you to install it:
it fetches the pinned llama.cpp release binary, or fetches `uv` and runs
vLLM through `uv tool run` (see [Inference engines](#inference-engines)).
The same prerequisites are checked when a config loads: a `serve:` block
on a host with no visible GPU, or a serve entry whose engine cannot be
acquired here, logs a warning at startup and on every hot reload naming
the model and the blocker. Library consumers of the workspace
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
        # No base_url: the gateway resolves the engine's loopback port
        # itself once the engine is ready.
        - name: local
          default_model: qwen3-14b
          models: [qwen3-14b, qwen3-8b]
          serve:
            eviction: lru          # or `never`
            cache_budget_gib: 200
            models:
              # Catalog id: the repo, quant list, and GGUF file come
              # from the catalog entry.
              - model: qwen3-14b
                engine: vllm
                keep_alive: 30m
              # Explicit ref: names the repo, quant, and file directly,
              # belt-and-braces when you want zero catalog indirection.
              - model: hf:Qwen/Qwen3-8B-GGUF:Q4_K_M
                name: qwen3-8b
                gguf_file: Qwen3-8B-Q4_K_M.gguf
                engine: llama_cpp
                keep_alive: 15m
                # llama-server applies the GGUF's embedded chat template.
                extra_args: ["--jinja"]
```

A model is either a catalog id (see below) or an explicit
`hf:Org/Repo:QUANT` reference that bypasses the catalog; both forms
serve. A raw `hf:` entry needs a `name:` (the model id every other
plane sees; a catalog entry borrows its id), and a GGUF entry from a
multi-file repo should pin `gguf_file:` so the runtime never guesses
the quant. `engine` is an
allowlisted enum (`vllm`, `llama_cpp`), never a command string: config
picks an engine and its knobs, and the runtime owns the argument
template; `extra_args` appends engine flags one argv element at a
time, no shell. `keep_alive` is the idle time before the engine
unloads to free VRAM; `eviction` decides what happens under VRAM
pressure, `lru`
evicts the least-recently-used idle model, `never` pins residency and
refuses a new model when full. See
[`examples/ai-local-serving`](../examples/ai-local-serving) and
[`examples/use-case-local-first`](../examples/use-case-local-first).

## Inference engines

The model host runs the model through one of two engines. You pick one
per serve entry with `engine:`, or leave it `auto` and the host chooses
by model format. Either way sbproxy acquires the engine for you, so a
bare box serves without a manual install.

| | llama.cpp | vLLM |
|---|---|---|
| Model format | GGUF | safetensors (the Hugging Face default) |
| How sbproxy gets it | fetches a pinned ggml-org prebuilt binary | fetches `uv`, runs vLLM through `uv tool run` |
| GPU | Metal on Apple Silicon, Vulkan on Linux | CUDA, NVIDIA only |
| Host prerequisites | none beyond the GPU driver | NVIDIA driver, `build-essential`, `python3-dev` |
| Good for | a Mac, a laptop, a CPU box, one GGUF file | an NVIDIA GPU serving a safetensors model at throughput |

### llama.cpp (GGUF)

llama.cpp serves GGUF weights. sbproxy fetches a pinned ggml-org prebuilt
`llama-server` for the host platform (a `.tar.gz` release asset), so
there is no build step and no compiler on the box. On an Apple Silicon
Mac it uses Metal and the unified memory. On a CPU-only box it runs on
the CPU against a slice of system RAM. On Linux with an NVIDIA GPU it
uses the Vulkan build.

One caveat on that last case: a stock cloud image such as the GCP Deep
Learning VM often ships no working NVIDIA Vulkan driver, so the model
serves on the CPU there even though the GPU is present and `sbproxy
doctor` detects it. Two ways to get the GPU on Linux with an NVIDIA card:

- Serve a safetensors model on vLLM (below), which uses CUDA.
- Or put a CUDA-built `llama-server` on `PATH`. sbproxy prefers a
  `PATH` binary over the fetched Vulkan prebuilt, so this takes over with
  no config change. `sbproxy doctor` prints these same commands under the
  llama.cpp acquisition options:

```bash
git clone https://github.com/ggml-org/llama.cpp
cmake llama.cpp -B build -DGGML_CUDA=ON
cmake --build build -j --target llama-server
export PATH="$PWD/build/bin:$PATH"   # or install it somewhere on PATH
```

  Building needs the CUDA toolkit (`nvcc`) and a C++ compiler; the Deep
  Learning VM already carries them.

The Metal path is certified: a GGUF model serves on Metal on an M4 Max,
the engine fetched and spawned by sbproxy.

### vLLM (safetensors, via uvx)

vLLM serves safetensors weights, the format most Hugging Face models
publish, and it is the throughput path on an NVIDIA GPU. vLLM is a Python
package rather than a single binary, so sbproxy acquires it with `uv`: it
fetches `uv` (Astral's single static binary, a pinned GitHub release like
the llama.cpp one) and runs vLLM through `uv tool run`, also known as
`uvx`. uv provisions and caches the environment on first use and brings
its own Python, so the box does not need one. The default vLLM wheel is
CUDA-enabled, so the model offloads to the GPU.

Opt in with `engines.vllm.acquire.source: uvx`, or let `sbproxy run
<model>` set it for you:

```yaml
serve:
  models:
    - model: hf:Qwen/Qwen2.5-0.5B-Instruct   # a safetensors repo
      name: qwen
      engine: vllm
  engines:
    vllm:
      acquire:
        source: uvx          # fetch uv, run vLLM via `uv tool run`
        # version: 0.24.0    # pin the vLLM package version (optional)
```

The host needs two things: the NVIDIA driver, and a C toolchain plus the
Python headers (`build-essential`, `python3-dev`). vLLM's Triton
JIT-compiles a small CUDA helper at engine startup, and that compile
fails without them, so the engine core will not initialize. The
Terraform demo installs both on the release path.

This is certified: on an L4, sbproxy fetched `uv`, ran vLLM through
`uv tool run`, and served a safetensors model with the weights resident
in GPU memory (about 21 GiB, 84% GPU utilization). vLLM is Linux and CUDA
only; a Mac has no GPU passthrough for it.

### Choosing an engine

`engine: auto` is the default, and it is what `sbproxy run` uses. It
picks by model format and host: a GGUF reference goes to llama.cpp, a
safetensors model goes to vLLM. Set `engine:` on a serve entry to force
one. `sbproxy doctor` reports which engines the host can run, and for one
it cannot, the single thing to install.

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
`gpu_utilization`. The utilization gauge is the observability view of
that signal; the `gpu-aware` routing strategy reads a
`gpu_utilization` entry in each target's metadata, which operators
feed from a metrics scrape or a sidecar. See
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
