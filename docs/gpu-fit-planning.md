# GPU fit planning

*Last modified: 2026-07-06*

When you name a model, the fit planner decides which quantization to
run on the GPU you have, and it refuses a configuration the card cannot
serve before an engine ever starts. The goal is a useful message at
config time instead of an out-of-memory crash at 2am.

## What it answers

Two questions, in order:

1. Can this card even run the quant? A quant that fits by size can
   still be a kernel the hardware lacks. A Turing card (a cloud T4) has
   16 GB but no FP8 and no Marlin int4 kernels, so an FP8 model that
   would fit is still unrunnable there. The planner reads CUDA compute
   capability, not just free VRAM, and skips a quant the card cannot
   execute.
2. Does it fit VRAM at the context you asked for? The estimate is the
   weight bytes for the chosen quant plus the KV cache at the planned
   sequence length, times a headroom factor for the CUDA context,
   activations, and the engine working set.

It walks the model's quant list in preference order and returns the
first quant that both runs and fits. If none run, the error says so and
names the capability gap. If they run but none fit, the error says that
instead, with the smallest estimate it found.

## The VRAM math

Weights are the parameter count times bytes per parameter for the
quant. FP16 is 2.0 bytes, FP8 is 1.0, and the GGUF K-quants carry block
overhead, so Q4_K_M is about 0.56 bytes per weight rather than the
nominal 0.5.

The KV cache is `2 x layers x kv_heads x head_dim x bytes x seq_len`.
The 2 is key plus value. `bytes` is 2 for an f16 cache and 1 for an fp8
cache. Two consequences worth internalizing: KV grows linearly with
context, so a long context can cost more than the weights, and models
with grouped-query attention (a small `kv_heads`) have a much cheaper
KV cache than their parameter count suggests. That is why the A3B-class
mixture-of-experts models are the self-hosting sweet spot: total
parameters set the VRAM, active parameters set the speed.

KV-cache quantization is a lever here. Dropping the cache to int4
roughly quarters the KV term, which can be the difference between
fitting your context and not. It trades a little quality for capacity,
so it is opt-in.

## Capability tiers

The planner gates FP8 on the compute capability the card reports.

| Card | VRAM | Compute capability | FP8 | Typical auto pick |
|---|---|---|---|---|
| T4 (Turing) | 16 GB | 7.5 | no | int4 / GGUF, <=14B |
| L4 (Ada) | 24 GB | 8.9 | yes | FP8 for a 30B-A3B at short context |
| A10G (Ampere) | 24 GB | 8.6 | no | int4 / AWQ |
| A100 (Ampere) | 40 or 80 GB | 8.0 | no | int4 or f16 |
| H100 (Hopper) | 80 GB | 9.0 | yes | FP8 |

The two cheap cloud GPUs, the T4 and the L4, are the first-class
lower-end target. On a T4 the planner refuses FP8 with a capability
message and falls back to an int4 or GGUF quant that the card can run.
On an L4 it accepts FP8.

## Throughput, not just fit

A quant can fit and still be too slow to be useful. The planner also
estimates decode throughput from the card's memory bandwidth, since
single-stream decode is memory-bandwidth bound: roughly the achievable
bandwidth divided by the bytes read per generated token. That catches
"this fits but will crawl" before you wait for a load, and it lets the
planner prefer the faster of two quants that both fit.

## Why did it pick this, or refuse

Every decision is meant to be legible. When it refuses, the message
distinguishes the two failure modes: a capability refusal names the
kernel the card lacks (FP8 on a Turing T4), and a size refusal reports
the free VRAM and the smallest estimate it could find. When it picks,
it reports the quant and the estimated VRAM at your context. The engine
doctor in `sbproxy plan` shows the same resolution per model before
anything spawns.

## A worked example

The built-in catalog lists `qwen3-14b` with its quants in preference
order, `[FP8, Q4_K_M]`. Name it in a `serve:` block (the shape is the
same as [`examples/ai-local-serving`](../examples/ai-local-serving)):

```yaml
origins:
  "ai.local":
    action:
      type: ai_proxy
      providers:
        - name: local
          default_model: qwen3-14b
          models: [qwen3-14b]
          serve:
            eviction: lru
            cache_budget_gib: 200
            models:
              - model: qwen3-14b   # catalog id; the quant list comes from the catalog
                engine: vllm
                keep_alive: 30m
```

On an L4 the planner takes the first quant that both runs and fits.
FP8 passes the capability gate (compute 8.9), and 14B parameters at
1.0 bytes per weight is about 13 GiB of weights, plus the KV cache at
the planned context and the 1.15x headroom factor, inside the card's
24 GB. The plan records the chosen quant, the estimated VRAM, and the
context length the estimate assumed.

On a T4 the FP8 candidate is skipped at the capability gate and the
walk continues to `Q4_K_M`, roughly 7.3 GiB of weights, which runs and
fits in 16 GB. You only see a refusal when every candidate fails, and
the message says which gate failed:

```text
no candidate quant runs on Tesla T4: FP8 needs FP8 kernels but Tesla T4 (compute 7.5) has none
no candidate quant fits 15.0 GiB free on Tesla T4: smallest estimate was 18.2 GiB
```

The first is a capability refusal: nothing in the quant list can
execute on this card. The second is a size refusal: everything could
execute, nothing fits, and the planner reports the smallest estimate
it found so you know how far off you are.

## Related

- [model-host.md](model-host.md) - the subsystem this is part of.
- [self-hosting.md](self-hosting.md) - the getting-started guide.
- [model-host-certification.md](model-host-certification.md) - the
  T4/L4 certification the tiers above are checked against.
