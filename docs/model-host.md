# Model host

*Last modified: 2026-07-10*

The model host lets the gateway run the model itself, not just proxy to
a model server someone else started. You name a model in a provider's
`serve:` block, and sbproxy resolves it to weights, fits an inference
engine to the local GPU, spawns and supervises that engine, and
registers it as a local provider that sits ahead of any cloud fallback
in the same routing, guardrail, budget, and usage-ledger planes every
other provider uses. It is single-node and Apache-2.0; fleet placement
across many nodes is separate work.

## Status

The single-node path is executable end to end. Catalog v2 resolves one
immutable variant for the current worker, the artifact service stages
and resumes downloads under cross-process locks, verifies every exact
size and SHA-256, and atomically publishes a content-addressed
snapshot. Startup blocks on `pull: on_boot`; `on_demand` verifies before
fit or residency planning; `manual` requires `sbproxy models pull` on a
miss. A managed engine receives only the verified local snapshot or
GGUF path. It never falls back to a repository after exact resolution.

The GPU fit planner, supervised process launcher, VRAM residency
manager, local-provider routing, and governance path then run as before.
Real GGUF on Apple Metal and safetensors through vLLM on an NVIDIA L4
have hardware certification. GCP validation for this foundation series
is intentionally deferred to the final integration PR. Legacy catalog
v1 and raw `hf:` entries remain a documented preview compatibility path
and do not have the complete atomic artifact contract. Multi-node
placement, admin mutation, and UI management are later PRs; the
[capability matrix](model-host-capabilities.md) is the exact status
source.

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
          default_model: qwen2.5-0.5b-instruct
          models: [qwen2.5-0.5b-instruct, qwen3-8b]
          serve:
            eviction: lru          # or `never`
            cache_dir: /var/lib/sbproxy/models
            models:
              # Managed catalog v2: exact source revision, file, size,
              # digest, format, and requirements come from the catalog.
              - model: qwen2.5-0.5b-instruct
                variant: q4_k_m
                keep_alive: 30m
              # Legacy preview compatibility. It lacks the complete
              # catalog v2 artifact contract.
              - model: hf:Qwen/Qwen3-8B-GGUF:Q4_K_M
                name: qwen3-8b
                gguf_file: Qwen3-8B-Q4_K_M.gguf
                engine: llama_cpp
                keep_alive: 15m
                # llama-server applies the GGUF's embedded chat template.
                extra_args: ["--jinja"]
```

A managed model is a catalog v2 logical ID plus an optional exact
`variant:` pin. With no pin, resolution deterministically chooses the
first compatible safe variant for this worker. Raw
`hf:Org/Repo:QUANT` and catalog v1 entries still serve through the
preview migration path. A raw `hf:` entry needs a `name:` and a GGUF
entry from a multi-file repo should pin `gguf_file:`. `engine` is an
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

## Managed artifacts

Catalog v2 is the stable artifact boundary. Resolution returns one
typed artifact identity containing the catalog revision, logical model,
variant, format, quant, engine, source revision, complete file list,
context, license, and support state. A canonical SHA-256 of that
identity addresses the cache.

Acquisition uses this order:

1. Lock the artifact across processes and inspect any existing state.
2. Enforce pull intent, `pull` policy, and offline policy before a
   transport can run.
3. Resume only when URL, entity tag, expected digest, expected size, and
   completed byte count still match.
4. Stage every file under `partials/`, verify exact lengths and hashes,
   and scan opted-in pickle files before finalization.
5. Publish blobs and the immutable snapshot atomically, then record a
   durable ready job.
6. Hand only verified local paths to vLLM, llama.cpp, or the embedded
   engine.

The cache root contains `blobs/sha256`, `snapshots`, `metadata`,
`partials`, `locks`, and `jobs`. Credentials are transport-only,
redacted in formatted errors, zeroized on drop, and absent from disk
metadata. A failed digest or unsafe pickle never creates a ready
snapshot.

Pull policy is explicit:

- `on_boot` is acquired and verified before the request pipeline is
  published. Warming starts no engine and allocates no serving port.
- `on_demand` is acquired before metadata fit, residency, or launch on
  the first request.
- `manual` refuses startup and runtime cache misses. Use an explicit
  pull.

```bash
# With sb.yml, the default selects configured models plus catalog
# entries marked on_boot and inherits catalog/cache policy.
sbproxy models pull -f sb.yml

# Without sb.yml, no model arguments selects the on_boot set.
sbproxy models pull --catalog-file models.yaml

# Pull one exact variant with human progress on stderr.
sbproxy models pull qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --catalog-file models.yaml \
  --cache-dir /var/lib/sbproxy/models

# Permit only verified hits or file: sources.
sbproxy models pull offline-coder \
  --variant q4_k_m \
  --catalog-file models.yaml \
  --offline
```

`-f/--config` resolves `catalog_file` relative to `sb.yml`, inherits
`cache_dir`, variant and engine choices, and applies `cache_budget_gib`
after successful pulls. `--all` pulls every catalog v2 model compatible
with the current worker and reports incompatible variants as skips. `--engine` can force
`vllm`, `llama-cpp`, or `embedded`. JSON output includes the selected
variant, engine, artifact digest, verified byte count, snapshot path,
and durable job ID. `HF_TOKEN` and `HUGGING_FACE_HUB_TOKEN` are accepted
for explicit gated pulls. Runtime secret-reference wiring is not yet a
stable capability, so pre-pull gated artifacts before startup.

`sbproxy models list` shows the selected worker-compatible variant,
format, exact size, engine, fit, and verified cache state. Incomplete v1
entries say `preview-incomplete` instead of inferring readiness from a
nonempty legacy directory. `models show <id>` emits the catalog
revision and every exact variant, including requirements and files.

The artifact service also provides protected LRU collection. It never
deletes resident, pinned, locked, downloading, verifying, or already
deleting artifacts, and it accounts for shared physical blobs. The
`models pull -f` enforces `cache_budget_gib` after a successful pull.
Automatic server-side enforcement on every on-demand acquisition is
not wired yet, so the field remains `config_only` in the capability
matrix and should not be treated as a continuous disk quota in this PR.

## Priority lanes and admission

A local engine has a hard concurrency ceiling in a way a cloud API does
not, so the serve block can cap in-flight requests and queue the rest:

```yaml
serve:
  # At most 4 requests inside the engine at once; more wait in a
  # priority queue. Omit (or 0) to disable the gate entirely.
  max_concurrent_requests: 4
  # How long a queued request waits before failing over to the next
  # provider in the array. Default 30000.
  queue_timeout_ms: 30000
```

The queue is ordered by the calling key's `priority` lane
(`interactive`, `standard`, or `batch`; unset means standard). A freed
slot always goes to the highest lane first, oldest request first
within a lane, so a flood of batch traffic cannot starve an
interactive key. Two behaviors follow from the lane:

- **Spill sooner:** when the lane is full and the provider array has a
  non-served provider later in it, an `interactive` request overflows
  to that fallback immediately instead of queuing. Standard and batch
  requests wait.
- **Timeout equals failover:** a request that exhausts
  `queue_timeout_ms` fails over like any other failed attempt; with no
  fallback it surfaces the usual no-provider error.

The lane rides on the key record, never on a client header, so a
caller cannot self-promote. Admission decisions land on the
`sbproxy_serve_lane_admissions_total{priority, decision}` counter and
each request's lane is attributed in the usage ledger's `priority`
field.

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

The catalog maps a stable logical ID to immutable executable variants.
Catalog v2 requires a nonempty `catalog_revision`; logical models carry
shape, license, family, and context; variants carry exact format,
quant, engines, source revision, files, hardware requirements, support
level, and certification evidence. Variant order is deterministic and
safe tensor formats outrank pickle. Pickle is refused unless the
logical model explicitly opts in and the bytes pass opcode scanning.

The built-in catalog contains one real pinned bootstrap GGUF while
older entries migrate from v1. Operator catalogs replace the built-in
catalog for that `serve:` block. A relative `catalog_file` resolves
from the directory containing the active `sb.yml`, so startup, reload,
doctor, and runtime do not depend on the shell's working directory.

## The model manifest

Beyond a throwaway model, keep one reviewable catalog v2 manifest. It
is the fleet fact sheet; `sb.yml` is the node fact sheet that selects
logical IDs and variants. `hf:` and `file:` sources are executable;
ModelScope remains reserved and fails closed. Stable Hugging Face
variants require a 40-character commit revision. Every file requires a
safe relative path, positive exact size, and lowercase SHA-256.

The cache honors an explicit `cache_dir`, then `$HF_HOME`, then the
platform default. See
[`examples/model-manifest`](../examples/model-manifest) for a real
pinned artifact and [`examples/use-case-air-gapped`](../examples/use-case-air-gapped)
for an offline `file:` pull.

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
