# Serving engine benchmark: vLLM vs SGLang on an L4

*Last modified: 2026-07-16*

SBproxy serves GPU models through digest-pinned engine containers, and vLLM and
SGLang are both first-class. This page is the head-to-head that decides which one
the gateway reaches for by default and when to switch. It ran on one real NVIDIA
L4, not a simulation, so the numbers are small in scale but honest.

The short version: on general chat traffic the two engines tie, so vLLM stays the
default for its coverage and its zero-config container path. On prefix-heavy,
agent-style traffic (a long shared system prompt, a tool loop replaying the same
context) SGLang held the load better, so it is a one-line opt-in for that shape.

## The setup

| | |
|---|---|
| Box | GCP `g2-standard-8`, one NVIDIA L4 (24 GB), `us-east1-b` |
| Model | `Qwen2.5-7B-Instruct`, bf16 (unquantized) |
| vLLM | `vllm/vllm-openai@sha256:05a31dc4...878271`, the shipped `DEFAULT_VLLM_IMAGE`; args `--gpu-memory-utilization 0.85 --max-model-len 8192 --enable-prefix-caching` |
| SGLang | `lmsysorg/sglang@sha256:f3b48b0e...c6d43`, the shipped `DEFAULT_SGLANG_IMAGE` (v0.5.2); args `--mem-fraction-static 0.85 --context-length 8192` (RadixAttention prefix caching is on by default) |
| Client | one async OpenAI streaming client, 24 concurrent, 96 requests per run, `temperature 0`, `stream: true` with usage accounting |

Both engines ran from the exact images SBproxy provisions by default, so this
measures what an operator gets rather than a hand-tuned build. Prefix caching was
on for both.

## Two workloads

The client drives each engine through two shapes:

- **Throughput** sends 96 diverse short prompts, 128 max tokens each. Nothing is
  shared between prompts, so the KV cache does not help. This is the "many
  unrelated chats at once" case.
- **Prefix-heavy** sends 96 requests that share a long (about 2,000 token) common
  prefix with a tiny unique suffix, 64 max tokens each. This is the "agent with a
  big fixed system prompt, or a tool loop replaying the same context" case, where
  prefix caching should pay off.

## Results

### Throughput (no shared prefix)

| Metric | vLLM | SGLang |
|---|---|---|
| Output tokens/s | **266.6** | 264.9 |
| Requests/s | **3.81** | 3.64 |
| TTFT p50 / p99 (ms) | **150 / 194** | 189 / 259 |
| Latency mean (s) | **5.12** | 5.72 |
| Completed | 96 / 96 | 96 / 96 |

A tie on raw throughput, inside 1%, with vLLM a touch ahead on time to first token
and tail latency.

### Prefix-heavy (shared 2k-token prefix)

| Metric | vLLM | SGLang |
|---|---|---|
| Output tokens/s | 242.7 | **275.1** |
| Requests/s | 16.18 | **18.34** |
| TTFT p50 / p99 (ms) | **210 / 291** | 355 / 376 |
| Latency mean (s) | 1.33 | 1.31 |
| Completed | 72 / 96 | **96 / 96** |

SGLang finished every request and pushed about 13% more requests per second. vLLM
answered faster on the requests it did finish, with a lower TTFT, but dropped 24
of the 96 under this specific shared-prefix burst.

### Cold start

vLLM's first bring-up took about six minutes because it included the model
download. SGLang reused the cached weights and was ready in about 170 seconds.
Read the 170 seconds as the fair cold-start number for either engine once the
weights are on disk.

## Reading the numbers

General chat is a wash. 266.6 against 264.9 tokens per second is inside the noise,
so if your traffic is many unrelated conversations, either engine serves it at the
same rate, and vLLM's slightly lower TTFT is the only separation.

Prefix-heavy traffic is where SGLang pulls ahead. On the workload that mimics an
agent with a large fixed system prompt, it sustained the burst more completely: it
finished all 96 requests to vLLM's 72 and moved more requests per second. That
tracks with its design, since RadixAttention is built to share the KV cache across
requests with a common prefix, which is exactly this shape. It is also SBproxy's
own sweet spot, because a gateway sitting in front of an agent fleet sees the same
system prompt over and over.

The one number that needs a caveat is vLLM's 72-of-96 completion. It is a real
result, not a typo, but it is one run on one card, and a 25% drop under a
synthetic prefix burst reads more like a saturation or config edge on this exact
image than proof that vLLM cannot do prefix work. vLLM had prefix caching enabled
and its TTFT was lower. Read it as "SGLang was more robust here," not "vLLM failed
here," and a second run with a larger request budget would settle it.

Then the scope, plainly: one L4, one 7B model, one concurrency point (24), single
runs. The numbers are directional, good enough to pick a default, and no
substitute for benchmarking your own model against your own traffic.

## How to pick

The gateway already encodes this choice, so mostly you leave it alone. With
`engine: auto` (or no engine set) the fit planner chooses vLLM for safetensors on
a capable GPU and llama.cpp for GGUF, and `auto` never resolves to SGLang. That
default is right for most estates: model and quant coverage is widest on vLLM,
throughput is tied, and when a container runtime is present SBproxy provisions the
pinned vLLM image with no further config. The policy is in
[model-host.md](model-host.md#managed-engines).

Reach for SGLang on prefix-heavy or agent traffic. It is a one-line opt-in per
deployment:

```yaml
proxy:
  model_host:
    deployments:
      agent-qwen:
        model: qwen2.5-7b-instruct
        engine: sglang
```

With a container runtime present, that pulls the pinned SGLang image
automatically, the same digest this benchmark used. Because the advantage is
workload-specific rather than universal, `engine: auto` will never select SGLang
on its own; it is always a deliberate choice.

## Why both engines run in containers

Both engines here came from digest-pinned containers, and that is not incidental.
Standing vLLM or SGLang up from a bare host environment means reproducing the
engine's entire build toolchain: matching Python headers, `ninja`, and a CUDA
developer toolkit, and a stock GPU box fails that in a cascade. The digest-pinned
image ships the whole environment, so the host needs only a container runtime and
an NVIDIA driver. That is why container provisioning is the default whenever a
runtime is present, and why the `install.sh` GPU path lays down Docker and the
NVIDIA container toolkit for you. The full policy, including how to pin your own
image, is in [model-host.md](model-host.md#vllm-in-a-container-default).

## What else this L4 pass checked

The same afternoon on the L4 exercised the parts of the model host that only a
real accelerator can prove out, separate from the formal certification gate:

- the NVML probe read the card correctly: L4, about 22 GiB usable, compute 8.9,
  FP8 kernels present;
- the fit planner's FP8 estimate and its refusal to oversubscribe held against
  real VRAM;
- the throughput predictor ran on the card and produced a sane single-stream
  estimate, about 26 tokens/s decode for a 7B at this precision, in the right
  range for this hardware;
- every engine that failed to boot surfaced a legible early-exit with a reason,
  never a hang.

This is validation, not promotion. The hardware evidence ledger and the strict
single-node and multi-node certification procedure live in
[model-host-certification.md](model-host-certification.md), and nothing on this
page promotes a capability in that ledger.

## Reproduce it

Serve each engine from its pinned image, one at a time, against a shared weights
cache:

```bash
MODEL=Qwen/Qwen2.5-7B-Instruct
HFCACHE=$HOME/hf-cache; mkdir -p "$HFCACHE"

# vLLM
docker run --rm --gpus all -v "$HFCACHE":/root/.cache/huggingface -p 8000:8000 \
  vllm/vllm-openai@sha256:05a31dc4185b042e91f4d2183689ac8a87bd845713d5c3f987563c5899878271 \
  --model "$MODEL" --max-model-len 8192 --gpu-memory-utilization 0.85 --enable-prefix-caching

# SGLang (same port; stop the vLLM container first)
docker run --rm --gpus all -v "$HFCACHE":/root/.cache/huggingface -p 8000:8000 \
  --entrypoint python3 \
  lmsysorg/sglang@sha256:f3b48b0e06ba98f2fa1dcf62254f14573af8ce7d9d3b519e771ee77a473c6d43 \
  -m sglang.launch_server --model-path "$MODEL" \
  --host 0.0.0.0 --port 8000 --mem-fraction-static 0.85 --context-length 8192
```

Wait for `GET /health` to return 200, then drive both workloads with the client
below:

```bash
python3 bench_client.py --base http://localhost:8000 --model "$MODEL" \
  --mode throughput --concurrency 24 --num 96 --max-tokens 128 --label vLLM
python3 bench_client.py --base http://localhost:8000 --model "$MODEL" \
  --mode prefix     --concurrency 24 --num 96 --max-tokens 64  --label vLLM
```

The client is a single async streaming benchmark that talks the OpenAI chat API,
so it runs unchanged against either engine. It measures output tokens per second
from the streamed deltas, request throughput, time to first token, and end-to-end
latency, and it prints one JSON line per run. Save it as `bench_client.py`:

```python
#!/usr/bin/env python3
# Fair OpenAI-endpoint benchmark: throughput + TTFT, streaming.
# One client, run against any /v1/chat/completions server.
import argparse, asyncio, json, time, statistics
import aiohttp

async def one(session, url, model, prompt, max_tokens):
    body = {"model": model, "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens, "temperature": 0.0, "stream": True,
            "stream_options": {"include_usage": True}}
    t0 = time.perf_counter(); ttft = None; out_toks = 0
    try:
        async with session.post(url, json=body,
                                timeout=aiohttp.ClientTimeout(total=300)) as r:
            async for raw in r.content:
                line = raw.decode("utf-8", "ignore").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except Exception:
                    continue
                ch = (obj.get("choices") or [{}])[0]
                delta = (ch.get("delta") or {}).get("content")
                if delta:
                    if ttft is None:
                        ttft = time.perf_counter() - t0
                    out_toks += 1
                u = obj.get("usage")
                if u and u.get("completion_tokens"):
                    out_toks = max(out_toks, u["completion_tokens"])
    except Exception:
        return None
    lat = time.perf_counter() - t0
    return {"ttft": ttft if ttft is not None else lat, "lat": lat, "out": out_toks}

async def worker(q, session, url, model, max_tokens, results):
    while True:
        try:
            prompt = q.get_nowait()
        except asyncio.QueueEmpty:
            return
        res = await one(session, url, model, prompt, max_tokens)
        if res:
            results.append(res)

async def run(base, model, prompts, concurrency, max_tokens):
    url = base.rstrip("/") + "/v1/chat/completions"
    q = asyncio.Queue()
    for p in prompts:
        q.put_nowait(p)
    results = []
    conn = aiohttp.TCPConnector(limit=concurrency + 8)
    async with aiohttp.ClientSession(connector=conn) as s:
        t0 = time.perf_counter()
        await asyncio.gather(*[worker(q, s, url, model, max_tokens, results)
                               for _ in range(concurrency)])
        wall = time.perf_counter() - t0
    total_out = sum(r["out"] for r in results)
    ttfts = sorted(r["ttft"] * 1000 for r in results)
    def pct(a, p):
        return a[min(len(a) - 1, int(len(a) * p))] if a else 0.0
    return {"completed": len(results), "wall_s": round(wall, 2),
            "output_toks_per_s": round(total_out / wall, 1) if wall else 0,
            "req_per_s": round(len(results) / wall, 2) if wall else 0,
            "ttft_ms_mean": round(statistics.mean(ttfts), 1) if ttfts else 0,
            "ttft_ms_p50": round(pct(ttfts, 0.50), 1),
            "ttft_ms_p99": round(pct(ttfts, 0.99), 1),
            "lat_s_mean": round(statistics.mean([r["lat"] for r in results]), 2)
            if results else 0}

def build_prompts(mode, n):
    if mode == "throughput":
        base = ["Explain {} in three sentences.".format(t) for t in
                ["photosynthesis", "the water cycle", "supply and demand",
                 "TCP handshakes", "black holes", "mitosis", "inflation",
                 "gradient descent", "DNS resolution", "the Krebs cycle",
                 "RSA encryption", "plate tectonics"]]
        return [base[i % len(base)] + " (variant {})".format(i) for i in range(n)]
    # prefix-cache-heavy: a long shared prefix + tiny unique suffix.
    shared = ("You are a meticulous assistant. Here is a reference document you "
              "must use.\n"
              + ("The quick brown fox jumps over the lazy dog near the riverbank. "
                 * 120)
              + "\nAnswer strictly from the document above.\n")
    return [shared + "Question {}: reply with one short sentence.".format(i)
            for i in range(n)]

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--num", type=int, default=64)
    ap.add_argument("--max-tokens", type=int, default=128)
    ap.add_argument("--mode", choices=["throughput", "prefix"], default="throughput")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    prompts = build_prompts(a.mode, a.num)
    await run(a.base, a.model, prompts[:4], 2, 8)  # warmup
    r = await run(a.base, a.model, prompts, a.concurrency, a.max_tokens)
    r["label"] = a.label; r["mode"] = a.mode; r["concurrency"] = a.concurrency
    print("RESULT " + json.dumps(r))

if __name__ == "__main__":
    asyncio.run(main())
```

The client needs only `aiohttp` (`pip install aiohttp`). It warms up with four
short requests before the measured run so the first-token numbers are not skewed
by the first allocation.

## See also

- [model-host.md](model-host.md) - the catalog, managed engines, the container default, and deployment fields
- [use-case-serve-on-l4.md](use-case-serve-on-l4.md) - the end-to-end walkthrough from `gcloud` to a first completion on an L4
- [gpu-fit-planning.md](gpu-fit-planning.md) - the VRAM math and capability tiers behind `engine: auto`
- [model-host-certification.md](model-host-certification.md) - the hardware evidence ledger and certification procedure
- [ai-lb-benchmark.md](ai-lb-benchmark.md) - the router load-balancing benchmark, for the routing layer in front of these engines
