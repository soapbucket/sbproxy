# You bought a GPU. Prove it pays for itself.

*Last modified: 2026-07-06*

![Provider failover: the primary provider fails and the fallback chain serves the request from the backup](assets/ai-fallback.gif)

The recording above shows provider failover between two hosted providers, the closest recorded behavior to this story's local-to-cloud spill. The local-first recording lands with GPU certification.

The card is racked, the driver loads, and most of your prompts would run fine on it. But traffic spikes past what one GPU can serve, a few requests genuinely need a frontier model, and finance keeps asking whether the hardware was worth it. SBproxy's pitch is "Call any model. Serve your own. Govern both.": one Apache-2.0 binary that routes to 66 providers or runs the weights on your own GPUs. This page uses both halves at once, and the ledger that comes with them answers the finance question.

## What you will build

An OpenAI-compatible endpoint backed by a single provider array. Provider zero is a `serve:` entry: the gateway resolves `qwen3-14b` to weights, fits an inference engine to your GPU, spawns and supervises it, and routes to it. Behind it sits a hosted provider that catches overflow and outages. A request flagged as training-sensitive routes only to providers marked safe, so those prompts stay on the box. Every completed call from either lane lands in one hash-chained usage ledger, and a short `jq` query over that file prices the local lane at hosted rates: the dollars the GPU displaced. llama-swap and Paddler stop at the local box, and LocalAI's cloud passthrough carries no budgets and writes no ledger; no other tool tells this whole story in a single config file.

## Prerequisites

- A Linux host with an NVIDIA GPU for the local lane. This story was written against an L4-class card. The released binary adapts at runtime: on a GPU-free host the same config validates and boots, but the `serve:` block starts no engine and every request spills to the cloud lane.
- An inference engine the box can run: a prebuilt `llama-server` on `PATH`, or vLLM via a container runtime. `sbproxy doctor` reports what it found and names every blocker.
- An OpenAI API key (`OPENAI_API_KEY`) for the spill lane.
- `curl` for sending requests, `jq` for reading responses and the ledger.

One caveat. The model host is landing in phases. The catalog, the fit planner, the engine supervisor, and the `serve:` config surface ship today, and the real vLLM and llama.cpp bring-up is certified against actual GPUs in later phases. [model-host.md](model-host.md) says exactly where that stands; run `sbproxy doctor` before trusting a box.

## Install

```bash
# Linux / macOS, single static binary:
curl -fsSL https://download.sbproxy.dev | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker:
docker pull ghcr.io/soapbucket/sbproxy:latest
```

The full install matrix, including packages and Kubernetes, is in the [manual](manual.md).

## Minimal config

Save this as `sb.yml`, or start from [`examples/use-case-local-first/`](../examples/use-case-local-first/), which is the same file plus a compose setup. First the skeleton:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "ai.local":
    action:
      type: ai_proxy
      routing:
        strategy: fallback_chain
```

`fallback_chain` tries providers in priority order. The chain advances when an attempt fails at the transport level, returns a retriable 5xx, or, for a served provider, when the local engine cannot be brought up. The client sees none of this; one request either succeeds on some lane or fails once.

Now the local lane:

```yaml
      providers:
        - name: local
          priority: 1
          no_prompt_training: true
          default_model: qwen3-14b
          models:
            - qwen3-14b
          serve:
            models:
              - model: qwen3-14b
                keep_alive: 30m
```

The `serve:` block is the part that makes this box a provider. There is no `base_url`: the gateway spawns the engine and resolves its loopback port itself. The engine defaults to `auto`, which reads the weights and the host (GGUF or no container runtime picks llama.cpp, safetensors picks vLLM), and the fit planner picks a quant the card can actually run, so an L4 takes FP8 and a T4 falls back to an int4 GGUF. `keep_alive: 30m` unloads an idle engine to free VRAM.

The `no_prompt_training: true` flag matters more than it looks. Tokens served here never leave the box, so the local lane is safe for prompts that opt out of training. The flag is also load-bearing: a request that opts out routes only to providers marked this way, so leaving it off would exclude the local lane from exactly the prompts it should keep.

Then the spill lane:

```yaml
        - name: openai
          provider_type: openai
          api_key: ${OPENAI_API_KEY}
          priority: 2
          default_model: gpt-4o-mini
          models:
            - qwen3-14b
          model_map:
            qwen3-14b: gpt-4o-mini
```

Two things are deliberate here. The provider declares `qwen3-14b` in its `models` list so it stays eligible when the chain advances for that model, and `model_map` renames it to `gpt-4o-mini` on the way out, which is what the upstream actually serves. The response's `model` field therefore tells you which lane answered: `qwen3-14b` means your GPU, `gpt-4o-mini` means the spill. And this provider is not marked `no_prompt_training`, so a flagged prompt pins to the local lane and fails closed rather than spilling. If your cloud account has a written no-training or zero-data-retention agreement, mark it too and flagged prompts may spill.

Last, the ledger:

```yaml
      usage_sinks:
        - type: ledger
          path: /tmp/sb-local-first-ledger.jsonl
```

Both lanes append to the same file: one entry per completed call with provider, model, token counts, cost, and latency, each entry hash-chained to the one before it so editing any past record breaks every link after it. Add a `signing_seed_hex` to also Ed25519-sign each entry; [ai-usage-ledger.md](ai-usage-ledger.md) covers that and the tamper test.

## Run it

Check the box, then start the gateway:

```bash
export OPENAI_API_KEY=sk-...
sbproxy doctor
sbproxy serve -f sb.yml
```

`doctor` prints the visible GPUs, the engines it found, and a readiness verdict for `serve:`, with every blocker named. Fix what it flags before going further; a missing engine is much cheaper to learn about now than at the first request. `sbproxy validate sb.yml` checks the config itself without starting anything.

Send a request. The first call pays the engine spawn, so give it time; after that the model is resident until `keep_alive` expires:

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"In one sentence, what is a reverse proxy?"}]}' \
  | jq -r '.model, .choices[0].message.content'
qwen3-14b
A reverse proxy is a server that sits in front of backends and forwards client requests to them.
```

`qwen3-14b` in the `model` field means your GPU answered. Now flag a prompt as training-sensitive:

```console
$ curl -s http://127.0.0.1:8080/v1/chat/completions \
    -H 'Host: ai.local' \
    -H 'Content-Type: application/json' \
    -H 'x-sbproxy-disallow-prompt-training: true' \
    -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Summarize this internal memo in one line: Q3 margins improved."}]}' \
  | jq -r '.model'
qwen3-14b
```

Same answer path, but the routing set was different: only providers marked `no_prompt_training` were eligible. That has teeth when things go wrong. With the local engine down, this request fails with a 502 rather than spilling to the unmarked cloud lane, and if no configured provider is marked at all, the gateway rejects it up front with `HTTP 400` and `"type": "no_compliant_provider"` in the body. Either way the prompt never reaches a training-eligible upstream.

You can watch the spill itself without contriving an outage. Run the same config on a box with no GPU: the log prints `AI proxy: local engine unavailable, failing over` on each attempt, the chain advances, and the response's `model` field reads `gpt-4o-mini`. On the GPU host, the same thing happens per request whenever the local lane is saturated or its engine is down.

Now the money question. Count the lanes, verify the record, and price what the GPU displaced:

```console
$ jq -r '.event.provider' /tmp/sb-local-first-ledger.jsonl | sort | uniq -c
   2 local

$ sbproxy ai ledger verify /tmp/sb-local-first-ledger.jsonl
ledger verify: OK (2 entries, chain only)

$ jq -s '[ .[] | select(.event.provider=="local") | .event ]
    | {local_calls: length,
       displaced_usd: ((map(.prompt_tokens) | add // 0) / 1e6 * 0.15
                     + (map(.completion_tokens) | add // 0) / 1e6 * 0.60)}' \
    /tmp/sb-local-first-ledger.jsonl
{
  "local_calls": 2,
  "displaced_usd": 3.3e-05
}
```

The `0.15` and `0.60` are gpt-4o-mini's list prices per million prompt and completion tokens; swap in the price of whatever hosted model this GPU replaces for you. Two toy requests displace three thousandths of a cent, which is exactly right. Point the same query at a month of production ledger and the output is the number you put in the spreadsheet next to the card's cost, with the cloud lane's real spend sitting in the same file as `cost_usd` on the `openai` entries. The model host also carries this math built in (each local completion priced at the hosted equivalent); the report surface for it is part of the phased rollout, so today the ledger file is the source of truth and `jq` is the report.

## You are done when

- The plain request returns `200` with `model` reading `qwen3-14b`, confirming the local lane answered.
- The flagged request also returns `qwen3-14b`, and it never spills: with the local engine down it fails (a 502, or a 400 with `"type": "no_compliant_provider"` when no provider is marked) instead of landing on the unmarked cloud lane.
- `/tmp/sb-local-first-ledger.jsonl` holds entries whose `.event.provider` is `local`, `sbproxy ai ledger verify` prints `ledger verify: OK` and exits 0, and the displaced-cost query prints a number.

## Next steps

- [self-hosting.md](self-hosting.md) - the wider self-hosting story: manifests, Claude Code against your own GPU, the OpenRouter parity map
- [model-host.md](model-host.md) - the reference for `serve:`, the catalog, the fit planner, and exactly which phase has shipped
- [model-host-certification.md](model-host-certification.md) - provisioning a cloud GPU and certifying the engine bring-up
- [ai-usage-ledger.md](ai-usage-ledger.md) - the ledger format, signing, and the verify command
- [routing-strategies.md](routing-strategies.md) - fallback chains and the other routing strategies
- [ai-gateway.md](ai-gateway.md) - guardrails, budgets, and virtual keys, all of which apply to the local lane unchanged
