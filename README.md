<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>

*Last modified: 2026-07-06*

<h3 align="center">Call any model. Serve your own. Govern both.</h3>

<p align="center">The open-source OpenRouter alternative: one Apache-2.0 binary that routes to 66 providers or serves the weights on your GPUs.</p>

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/releases"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy" alt="Release"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/stargazers"><img src="https://img.shields.io/github/stars/soapbucket/sbproxy" alt="Stars"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.82+-orange.svg" alt="Rust 1.82+"></a>
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#serve-your-own-model">Serve your own model</a> &middot;
  <a href="#solve-a-problem">Solve a problem</a> &middot;
  <a href="examples/">Examples</a> &middot;
  <a href="docs/README.md">Docs</a>
</p>

<p align="center">
  <img src="docs/assets/ai-gateway.gif" alt="One OpenAI-compatible request routed to OpenAI, Anthropic, and Google through sbproxy" width="900">
</p>

---

## Why SBproxy

Most teams stitch AI infrastructure together from an LLM proxy, a local inference server, an API gateway, a key store, a guardrail service, and a dashboard they have to trust for spend. SBproxy is one process that does the three jobs that stack was hired for.

**Call any model.** 66 providers behind one endpoint that speaks both the OpenAI and Anthropic wire formats, with fallback chains, outcome-aware routing, predictive budgets, and per-error retry policies. A local semantic cache replays near-duplicate prompts with no per-call cost, and the prompt never leaves your network. Coming from LiteLLM? `sbproxy config import-litellm` [converts your config](docs/migration-litellm.md).

**Serve your own.** The same binary runs the models. `proxy.model_host` declares verified local deployments; `provider_type: managed_model` exposes them through the same OpenAI-compatible gateway as hosted providers. SBproxy resolves immutable artifacts, fits the selected device, supervises llama.cpp or vLLM, and keeps request admission and reload atomic. Provider-level `serve:` remains a migration path. Apple Metal is validated before the local-runtime PR ships, while live NVIDIA and multi-node GCP certification is reserved for the final integration PR.

**Govern both.** Govern the AI you call, the AI that calls you, and the AI you run, with one policy plane. Virtual keys are minted, rotated, and revoked at runtime, hashed at rest, and carry their own budgets and model pins. The guardrail mesh screens prompts and responses for every provider type, local or hosted, and can redact a streaming completion mid-flight. Inbound AI is governed too: charge crawlers per request with Pay Per Crawl, verify signed agents (RFC 9421), negotiate Markdown so agents stop paying for HTML. Every request can emit a hash-chained, Ed25519-signed usage receipt you can verify offline.

Under it all sits a real reverse proxy built on Pingora: auth (JWT, OIDC, mTLS), automatic TLS via ACME, WAF, DDoS, CSRF, SSRF guards, rate limiting, caching, and hot reload with no dropped connections. Sub-millisecond p99 overhead, idle RSS in single-digit megabytes. Run one binary or point a fleet of replicas at a shared store; the mesh that keeps keys, budgets, and spend counters coherent is open source here, no external Redis and no vendor control plane required.

New here and weighing the options? See [how SBproxy compares](docs/comparison.md).

---

## Install

curl (macOS / Linux):

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

The script detects your OS and architecture, fetches the matching release binary from GitHub, and drops it in `~/.local/bin`. Override with `SBPROXY_INSTALL=<dir>` for a custom location or `SBPROXY_VERSION=<tag>` to pin a release.

Homebrew (macOS / Linux):

```bash
brew tap soapbucket/tap
brew install sbproxy
```

Docker:

```bash
docker pull ghcr.io/soapbucket/sbproxy:latest
```

From source (needs Rust 1.82+):

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
```

---

## Serve your own model

This is the shortest path from a GPU to a governed OpenAI-compatible endpoint. Drop this into `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

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

Check the box, then run:

```bash
sbproxy doctor            # what this host can serve: GPUs, engines on PATH, readiness verdict
sbproxy validate sb.yml   # fail fast on a bad config
sbproxy sb.yml
```

First token:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "Host: gateway.internal" -H "Content-Type: application/json" \
  -d '{"model":"qwen3-14b","messages":[{"role":"user","content":"Say hello from my GPU."}]}'
```

Every plane the gateway has (virtual keys, budgets, guardrails, the usage ledger) applies to that local model unchanged. The walkthroughs go deeper: [serve an open-weight model on a cloud L4](docs/use-case-serve-on-l4.md), [point your coding assistant at your own GPU](docs/use-case-coding-assistant.md), [local first with cloud spillover](docs/use-case-local-first.md), and the [self-hosting overview](docs/self-hosting.md).

---

## Solve a problem

Each of these walks one problem end to end: a story doc, a runnable example, a `docker compose up`, and a recording of the outcome.

| Your problem | Walkthrough |
|---|---|
| API keys scattered across teams, no accounting | [Stand up your own OpenRouter](docs/use-case-own-openrouter.md) |
| You want your coding assistant on hardware you control | [Point Claude Code at your own GPU](docs/use-case-coding-assistant.md) |
| GCP credits and an afternoon | [Serve Qwen, GLM, or Gemma on a cloud L4](docs/use-case-serve-on-l4.md) |
| A GPU that has to pay for itself | [Local first, spill to cloud](docs/use-case-local-first.md) |
| Weights and prompts that must never leave the network | [Air-gapped and sovereign AI](docs/use-case-air-gapped.md) |
| A LiteLLM proxy you want off of | [Migrate off LiteLLM in an afternoon](docs/migration-litellm.md) |
| Shadow Ollama under someone's desk | [Guardrails on every prompt, local or hosted](docs/use-case-guardrails-everywhere.md) |
| AI crawlers eating your content for free | [Meter and monetize the AI that calls you](docs/use-case-meter-crawlers.md) |
| It works on your laptop and on-call starts Monday | [Run it in production](docs/use-case-production-ops.md) |

---

## Quick start

We host a public HTTP echo service at `test.sbproxy.dev` (request inspection, like httpbin) so you can wire up a real upstream without leaving the SoapBucket ecosystem. Try it directly:

```bash
curl https://test.sbproxy.dev/get
```

Now run the gateway in front of it. Drop this into `sb.yml`:

```yaml
proxy:
  http_bind_port: 8080

origins:
  "myapp.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

```bash
sbproxy sb.yml
curl -H "Host: myapp.example.com" http://127.0.0.1:8080/get
```

`myapp.example.com` is the host your client sees; SBproxy matches it against `origins:` and forwards to the upstream. Use any hostname you want here; `example.com` is reserved (RFC 2606), so it never collides with anything real.

That's a reverse proxy. Add AI routing, auth, and rate limiting in the same file. See [`examples/`](examples/) for runnable end-to-end configurations covering each feature.

---

## See it in action

Each clip is recorded against the release binary running a real example config. Regenerate them with [`scripts/record-tapes.sh`](scripts/record-tapes.sh).

**Failover across providers:** the primary is down, the backup answers, transparently. ([config](examples/ai-routing-fallback/))

![Multi-provider failover](docs/assets/ai-fallback.gif)

**Semantic cache:** a reworded prompt is served from cache (`x-semcache: HIT`), skipping the billable completion. ([config](examples/semantic-cache-openai/))

![Semantic cache hit](docs/assets/semantic-cache.gif)

**Guardrails:** prompt-injection and PII are blocked before any provider is called. ([config](examples/ai-guardrails/))

![Guardrails blocking injection and PII](docs/assets/ai-guardrails.gif)

**Governed keys:** mint a virtual key at runtime, then revoke it and watch the next request stop. No reload, no plaintext on disk. ([config](examples/ai-dynamic-keys/), [cluster](examples/ai-dynamic-keys-cluster/))

```bash
# Mint a key (the plaintext token is returned exactly once)
curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys \
  -d '{"name":"ci-runner","max_requests_per_minute":60}'

# Revoke it; the next request carrying it is denied on every replica
curl -s -u admin:admin -X POST http://127.0.0.1:9090/admin/keys/<key_id>/revoke
```

---

## Documentation

The full documentation lives in [`docs/README.md`](docs/README.md): manual, configuration reference, AI gateway guide, self-hosting, scripting reference, performance, troubleshooting, architecture, and more. Running the operator for the first time? Start with [`docs/quickstart-operator.md`](docs/quickstart-operator.md).

For contributors: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Community

- [Issue Tracker](https://github.com/soapbucket/sbproxy/issues) for bug reports and feature requests.
- Looking for a managed offering? [SBproxy Enterprise](https://sbproxy.dev/enterprise).

---

## License

Licensed under the [Apache License 2.0](LICENSE). Free for any use, including production and commercial, with no field-of-use restriction.

See also [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md). A [Soap Bucket LLC](https://www.soapbucket.com) project.
