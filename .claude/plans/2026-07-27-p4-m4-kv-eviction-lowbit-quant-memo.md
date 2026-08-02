# P4 M4 spike: KV-eviction / low-bit quant integration

Ticket: WOR-1933 (Backlog, Priority 4). Self-hosted only. AC: a short recommendation
memo, no shipping code required.

## Question

Should sbproxy integrate a KV-cache eviction or low-bit quantization scheme
beyond what vLLM already ships (`--kv-cache-dtype fp8`, already wired in
`launch.rs`), and if so, by forking an existing implementation or waiting
for upstream vLLM to merge one.

## Landscape

Query-aware eviction (drop cache entries the model is unlikely to attend to
again) and low-bit KV quantization are two different levers, both aimed at
the same problem: KV cache is the dominant VRAM cost at long context and
high concurrency.

**Eviction methods** (SnapKV 2404.14469, H2O 2306.14048, PyramidKV
2406.02069): score cached tokens by attention weight over a recent window
and drop the low-scoring tail. None of these are merged into vLLM core as
of this review. H2O's reference implementation falls back to eager
attention to materialize the full score matrix, which is incompatible with
FlashAttention/FlashInfer kernels vLLM depends on for throughput; that is
the likely reason none of the eviction papers have landed upstream despite
being 1-2 years old. Ada-KV (2407.11550) addresses the same problem with
adaptive per-head budgets and is the closest to a production-shaped
implementation.

**Production paths that exist today:**
- `IsaacRe/vllm-kvcompress` on GitHub: a fork of vLLM v0.6.0 implementing
  KV-Compress (2410.00161), variable compression rates per attention head,
  claiming up to 5.18x throughput on memory-constrained deployments. It is
  a fork pinned to an old vLLM minor version, not a plugin; adopting it
  means running a divergent vLLM fork, which conflicts with sbproxy's
  container-first default (pinned upstream vLLM images) and would need
  re-basing onto every vLLM version bump by hand.
- TensorRT-LLM ships RocketKV and StreamingLLM-style attention sinks
  (2309.17453) as first-party features, but sbproxy does not use
  TensorRT-LLM as a managed engine, so this path is not reachable without
  adding a new engine driver, a much larger undertaking than this spike.
- **KIVI** (2402.02750, 2-bit asymmetric KV quantization) is a research
  implementation (a patched transformers/vLLM branch), not a maintained
  fork with release discipline comparable to `vllm-kvcompress`.

**Low-bit quant status inside vLLM itself:** vLLM's native `--kv-cache-dtype`
already supports fp8 (wired in sbproxy today). Sub-fp8 (int4/int8) KV quant
is not a first-party vLLM flag as of this review; sbproxy currently maps
`KvCacheQuant::Int8`/`Int4` to vLLM's `fp8` dtype as the nearest supported
value (`launch.rs::vllm_kv_cache_dtype`), which is already the honest
answer here: there is no native lower-precision KV dtype to route to yet.

## Recommendation

**Wait for upstream, do not fork.** None of SnapKV/H2O/PyramidKV/Ada-KV
have a vLLM-native implementation with release discipline sbproxy can pin
to as a digest, and the one available fork (`vllm-kvcompress`) is frozen at
vLLM v0.6.0, multiple major releases behind what sbproxy currently ships.
Adopting it would mean sbproxy silently stops receiving every vLLM
upstream fix and feature (including the container-first default this
crate just shipped) in exchange for an eviction scheme whose accuracy
tradeoffs have not been validated against sbproxy's own served model
catalog. That is a bad trade for a Priority 4 spike.

The lower-risk lever already available is: raise `swap_space_gib` /
`cpu_offload_gib` (shipped) and `enable_prefix_caching` (this workstream)
before reaching for lossy eviction, since both are reversible, native, and
already wired.

**Re-check trigger:** vLLM's own roadmap issues (`vllm-project/vllm`
GitHub, tagged `[Roadmap]`) periodically list KV cache compression as a
candidate quarter's theme; re-run this spike whenever a KV-eviction PR
opens against vLLM core, or every two quarters, whichever comes first.
