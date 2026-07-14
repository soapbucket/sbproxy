# Self-hosting SBproxy

*Last modified: 2026-07-10*

One binary to self-host your AI gateway, and the same binary runs the
models. OpenRouter proved that teams want unified routing, fallbacks,
virtual keys, and spend accounting in front of every model they call.
That product is pure brokerage: it forwards your request to whoever
hosts the model. SBproxy brings the same feature surface inside your
network and adds the half a hosted router cannot: the weights run on
your GPUs, and the tokens never leave the box.

The stable single-node shape is `proxy.model_host` plus a
`provider_type: managed_model` provider. Every plane you already rely on
(keys, budgets, guardrails, and the usage ledger) applies to that local model.
Provider `serve:` blocks remain a compatibility path for the migration window.

## Install

Configuration-first, no build step.

```bash
# curl installer
curl -fsSL https://download.sbproxy.dev | sh

# Homebrew
brew install soapbucket/tap/sbproxy

# Docker
docker run --rm -p 8080:8080 -v "$PWD/sb.yml:/etc/sbproxy/sb.yml" \
  soapbucket/sbproxy:latest
```

Binary downloads and the rest of the install matrix are in the
[runtime manual](manual.md#1-installation).

## Serve a model

The model host runs llama.cpp or vLLM as a supervised process and registers a
configured deployment as a local provider.

```yaml
proxy:
  http_bind_port: 8080
  model_host:
    cache:
      directory: /var/lib/sbproxy/models
    deployments:
      local-qwen:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        pull: on_boot
        warm: true
        engine: llama_cpp

origins:
  "gateway.internal":
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: local-qwen
          models: [qwen]
```

The deployment owns artifact, engine, admission, and lifecycle policy. The
provider owns the public model name and normal gateway policy. Engine `auto`
chooses a compatible managed driver from the exact artifact format. See
[model-host.md](model-host.md#managed-engines) for availability states,
acquisition, and the current hardware evidence boundary.

## The model manifest

Catalog v2 is the reviewable file that says which models exist, where their
weights come from, and which digests must match. Canonical deployments in this
PR use the built-in catalog. An operator catalog is available through the
compatibility `serve.catalog_file` path; moving custom catalog selection into
the managed admin plane is later work. See
[`examples/model-manifest`](../examples/model-manifest). A manifest
entry carries the source (`hf:` or an air-gapped `file:` path), a
pinned revision, per-file sha256 digests, a gated-repo token as a
secret reference, the default engine, and a pull policy (`on_boot`,
`on_demand`, or `manual`). A curated manifest with digests doubles as a
supply-chain allowlist.

Weight acquisition follows each canonical deployment's `pull` policy. Use
`on_boot` to verify during candidate preparation, `on_demand` to defer the work
to the first request, or `manual` to require a prior `sbproxy models pull`.

## Check the box before it serves

`sbproxy doctor` answers "can this host serve models" with no config
at all: build capabilities, visible devices, engines on PATH, container
runtime, the model cache, and a local-runtime verdict with every
blocker listed. For each engine it names the acquisition options viable
here (a pinned llama.cpp release, or vLLM via uvx), and the runtime then
acquires the engine on first use. What doctor still cannot supply is a
host prerequisite it can only report: a GPU driver, or the
`build-essential` and `python3-dev` that vLLM's Triton compile needs. A
missing prerequisite is a doctor-time message, not a spawn failure at
2am on the first request.

`sbproxy validate <path>` parses and validates the config offline,
and `sbproxy plan -f sb.yml [--against baseline.yml]` diffs it: it
prints the added, changed, and removed origins plus a max-blast-radius
line, and exits 0 when the config is a no-op, 2 when there are
changes, and 3 on semantic errors. Wire that exit code into CI so a
rollout that touches more origins than you expected stops before it
ships.

The proxy rechecks those prerequisites during startup and reload preparation.
A bad candidate never replaces the last good runtime.

## Point Claude Code at your own GPU

The format bridges already speak both the OpenAI and Anthropic wires,
so an alias maps a hosted model name to a local one. Map
`claude-sonnet-4-5` to a local GLM and your existing Claude Code setup
runs against your hardware with a one-line change.

```yaml
proxy:
  model_host:
    deployments:
      local-coder:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m

providers:
  - name: local
    provider_type: managed_model
    deployment: local-coder
    models: [claude-sonnet-4-5]
```

Check the [model host boundary](model-host.md#current-boundary) before choosing
hardware. Apple Metal is the live gate for this PR; NVIDIA remains pending the
final GCP integration run.

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
    provider_type: managed_model
    deployment: local-qwen
    models: [qwen]
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

## A public endpoint with Let's Encrypt

Nothing on this page requires staying on a private network. Give the
origin a real hostname, open ports 80 and 443, and enable ACME: the
gateway answers the http-01 challenge itself, obtains a certificate
from Let's Encrypt (or any ACME-compatible CA), and renews it before
expiry. Issued certificates persist in a local store, so a restart
reuses the certificate instead of asking the CA for a fresh one.

```yaml
proxy:
  http_bind_port: 80
  https_bind_port: 443
  acme:
    enabled: true
    email: ops@example.com
  model_host:
    deployments:
      local-qwen:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m

origins:
  "ai.example.com":
    force_ssl: true
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: local-qwen
          models: [qwen]
```

That is a governed, OpenAI-compatible endpoint on your own GPU with
real TLS, reachable by your team, your customers, or any agent you
hand a key to. Put virtual keys and budgets in front before you expose
it; a public `/v1/chat/completions` with no auth is an open GPU. The
field reference, other ACME directories, and the shared certificate
stores a fleet needs are in
[configuration.md](configuration.md#acme--auto-tls).

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
  the hardware evidence ledger and final GCP procedure.
- [ai-gateway.md](ai-gateway.md) - the routing, guardrail, budget, and
  ledger planes local models plug into.
