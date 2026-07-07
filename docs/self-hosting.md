# Self-hosting SBproxy

*Last modified: 2026-07-06*

One binary to self-host your AI gateway, and the same binary runs the
models. OpenRouter proved that teams want unified routing, fallbacks,
virtual keys, and spend accounting in front of every model they call.
That product is pure brokerage: it forwards your request to whoever
hosts the model. SBproxy brings the same feature surface inside your
network and adds the half a hosted router cannot: the weights run on
your GPUs, and the tokens never leave the box.

If you only take one thing from this page: a provider whose entire body
is a `serve:` block with one model line boots to a first token, and
then every plane you already rely on (keys, budgets, guardrails, the
usage ledger) applies to that local model unchanged.

## Install

Configuration-first, no build step.

```bash
# curl installer
curl -fsSL https://download.sbproxy.dev | sh

# Homebrew
brew install soapbucket/tap/sbproxy

# Docker
docker run --rm -p 8080:8080 -v "$PWD/sb.yml:/etc/sbproxy/sb.yml" \
  ghcr.io/soapbucket/sbproxy:latest
```

Binary downloads and the rest of the install matrix are in the
[runtime manual](manual.md#1-installation).

## Serve a model

The model host runs an inference engine (vLLM or llama.cpp) as a
supervised subprocess and registers it as a local provider. You name a
model; sbproxy resolves it, fits an engine and quant to the GPU, spawns
it, and routes to it.

```yaml
origins:
  "gateway.internal":
    action:
      type: ai_proxy
      providers:
        - name: local
          serve:
            models:
              - model: qwen3-14b
```

That is the whole provider. The engine defaults to `auto`, which reads
the weights and the box: GGUF or no container runtime picks llama.cpp,
safetensors picks vLLM. The fit planner picks the quant the card can
run, so an L4 takes FP8 and a T4 falls back to an int4 GGUF instead of
a kernel the hardware lacks.

## The model manifest

For more than a throwaway model, keep a manifest: one reviewable file
that says which models exist, where their weights come from, and the
digests to verify them against. Point `serve.catalog_file` at it. See
[`examples/model-manifest`](../examples/model-manifest). A manifest
entry carries the source (`hf:` or an air-gapped `file:` path), a
pinned revision, per-file sha256 digests, a gated-repo token as a
secret reference, the default engine, and a pull policy (`on_boot`,
`on_demand`, or `manual`). A curated manifest with digests doubles as a
supply-chain allowlist.

Weight acquisition happens under the serve lifecycle, driven by each
entry's pull policy. To warm the cache ahead of a first request (or
bake weights into a container image), set `pull: on_boot` on the entry
and boot the proxy once; the download runs at startup instead of on
the first call. `on_demand` pays the download when the first request
arrives, and `manual` never downloads: it expects the weights already
present in the cache directory, which is the right setting for
air-gapped hosts.

## Check the box before it serves

`sbproxy doctor` answers "can this host serve models" with no config
at all: build capabilities, visible GPUs, engines on PATH, container
runtime, the model cache, and a serve-readiness verdict with every
blocker listed. For a missing engine it prints the prerequisites and
the manual steps to install one (a prebuilt release on PATH, or a
container runtime); sbproxy diagnoses, it does not install engines
for you. A missing dependency is a doctor-time message, not a spawn
failure at 2am on the first request.

`sbproxy validate <path>` parses and validates the config offline,
and `sbproxy plan -f sb.yml [--against baseline.yml]` diffs it: it
prints the added, changed, and removed origins plus a max-blast-radius
line, and exits 0 when the config is a no-op, 2 when there are
changes, and 3 on semantic errors. Wire that exit code into CI so a
rollout that touches more origins than you expected stops before it
ships.

The proxy also re-checks the doctor's prerequisites every time a
config with `serve:` loads, and logs a warning per missing piece, so a
freshly-imaged box that lost its engine or driver tells you at boot,
not at the first request.

## Point Claude Code at your own GPU

The format bridges already speak both the OpenAI and Anthropic wires,
so an alias maps a hosted model name to a local one. Map
`claude-sonnet-4-5` to a local GLM and your existing Claude Code setup
runs against your hardware with a one-line change.

```yaml
serve:
  models:
    - model: glm-4-flash
      name: claude-sonnet-4-5
```

One caveat before you bet a workflow on this: the serving path is
landing in phases, and real-GPU engine bring-up is certified per
hardware target, so check the
[model host status](model-host.md#status) for what is proven on your
card today.

## Spill to cloud, with policy attached

Put a hosted provider after the local one in the same fallback array.
When the local engine is saturated or a request carries a strict TTFT
need, the request overflows to the cloud, with zero data retention
still enforceable per request: mark the providers that are safe for
training-sensitive prompts with the provider-level
`no_prompt_training: true` flag, and a request carrying the
`x-sbproxy-disallow-prompt-training: true` header only routes to
providers with that flag. If no provider in the chain is marked, the
request gets a 400 rather than landing somewhere you did not approve.

```yaml
providers:
  - name: local
    serve:
      models: [{ model: qwen3-14b }]
  - name: openai
    api_key: ${OPENAI_API_KEY}
    default_model: gpt-4o-mini
```

## Grown-up auth in front of local inference

Ollama's own FAQ tells you to put nginx in front of it. SBproxy is that
front, with a ledger and a policy engine behind it: virtual keys,
per-team quotas, hierarchical budgets, and the guardrail mesh all apply
to the local model the same way they apply to a hosted one. The usage
ledger prices each local completion at what the equivalent hosted API
would have charged and reports dollars saved per model per month, which
is the number that justifies the GPU.

## OpenRouter parity map

What OpenRouter offers, the SBproxy equivalent, and what the enterprise
tier adds on top. Honest about the gap: OpenRouter brokers a
400-plus-model hosted marketplace; we route to 66 hosted providers plus
your own GPUs.

| OpenRouter | SBproxy | Enterprise adds |
|---|---|---|
| Unified API across providers | One OpenAI/Anthropic-shaped API across 66 providers plus local engines | Same |
| Model catalog | Model manifest (source, pinning, digests, pull policy) | Curated allowlist, signed |
| Fallback + provider routing preferences | Fallback chain, cost/latency routing, prefix-affinity, least-token-usage | GPU-aware and prefix-cache-aware routing across a node fleet |
| Virtual keys | Virtual keys with per-key scopes | Tenants, RBAC |
| Spend limits and accounting | Budgets, hierarchical quotas, usage ledger, dollars-saved report | Audit trail, per-tenant accounting |
| Zero-data-retention routing | `no_prompt_training` provider flag + `x-sbproxy-disallow-prompt-training` request header | Air-gapped: guardrails, redaction, and generation all local |
| Bring your own key | Provider keys plus a credential resolver (env, secret stores, vault) | Managed key rotation, mesh-distributed key cache |
| 400-plus hosted-model marketplace | 66 hosted providers plus models on your GPUs | Same providers, fleet placement |

## Related

- [model-host.md](model-host.md) - the reference: catalog, fit planner,
  supervisor, engine matrix.
- [model-host-certification.md](model-host-certification.md) -
  provisioning a cloud GPU and running the certification.
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and
  ledger planes local models plug into.
