# Self-hosting SBproxy

*Last modified: 2026-07-04*

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
curl -fsSL https://sbproxy.dev/install.sh | sh

# Homebrew
brew install soapbucket/tap/sbproxy

# Docker
docker run --rm -p 8080:8080 -v "$PWD/sb.yml:/etc/sbproxy/sb.yml" \
  ghcr.io/soapbucket/sbproxy:latest
```

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

Warm the cache ahead of a first request, or in a container build, with
the pull command instead of paying the download on the first call:

```bash
sbproxy models pull -f sb.yml
```

## Check the box before it serves

`sbproxy plan` runs an engine doctor: for each model it reports what
`auto` resolved to and why, and whether the box can actually run it
(binary on PATH, container runtime present, GPU found). A missing
dependency is a plan-time message, not a spawn failure at 2am on the
first request.

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

## Spill to cloud, with policy attached

Put a hosted provider after the local one in the same fallback array.
When the local engine is saturated or a request carries a strict TTFT
need, the request overflows to the cloud, and it honors `zdr` and
`no_prompt_training` per request so a training-sensitive prompt only
lands on providers you marked safe.

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
| Zero-data-retention routing | `zdr` / `no_prompt_training` per-request routing | Air-gapped: guardrails, redaction, and generation all local |
| Bring your own key | Provider keys plus a credential resolver (env, secret stores, vault) | Managed key rotation, mesh-distributed key cache |
| 400-plus hosted-model marketplace | 66 hosted providers plus models on your GPUs | Same providers, fleet placement |

## Related

- [model-host.md](model-host.md) - the reference: catalog, fit planner,
  supervisor, engine matrix.
- [model-host-certification.md](model-host-certification.md) -
  provisioning a cloud GPU and running the certification.
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and
  ledger planes local models plug into.
