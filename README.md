<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>

*Last modified: 2026-07-14*

<h3 align="center">Take control of your AI traffic.</h3>

<p align="center">Route the AI you call: 200+ models across 66 providers plus open-weight models on your own GPUs, picked by prompt difficulty and rerouted on live cost-per-success. Gate the AI that calls you: verified agents, metered crawlers, and your APIs served over MCP. <a href="https://sbproxy.dev">sbproxy.dev</a></p>

<p align="center">
  <a href="https://sbproxy.dev"><img src="https://sbproxy.dev/sbproxy-flow.gif" alt="SBproxy routing live traffic in both directions: apps, pipelines, crawlers, and MCP clients through one gateway to your GPUs, hosted providers, and your own APIs" width="820"></a>
</p>

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/releases"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy" alt="Release"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/stargazers"><img src="https://img.shields.io/github/stars/soapbucket/sbproxy" alt="Stars"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.82+-orange.svg" alt="Rust 1.82+"></a>
</p>

<p align="center">
  <a href="#getting-started">Getting started</a> &middot;
  <a href="#serve-your-own-model">Serve your own model</a> &middot;
  <a href="#solve-a-problem">Solve a problem</a> &middot;
  <a href="examples/">Examples</a> &middot;
  <a href="docs/README.md">Docs</a> &middot;
  <a href="https://sbproxy.dev">Website</a>
</p>

<p align="center">
  <img src="docs/assets/ai-gateway.gif" alt="One OpenAI-compatible request routed to OpenAI, Anthropic, and Google through sbproxy" width="900">
</p>

---

## Why SBproxy

Cloudflare's AI Gateway and Vercel's got a lot right: one endpoint in front of every model, caching, budgets, failover. SBproxy hands you the whole thing to run yourself, in your VPC or air-gapped, on your own keys at your providers' prices. It also does the two things a hosted edge can't: serve the weights on your own GPUs, and gate the AI traffic coming *into* your APIs. One Rust binary, Apache 2.0.

**Call any model.** 200+ models across 66 providers behind one endpoint that speaks the OpenAI and Anthropic wire formats. Sixteen routing strategies, predictive budgets, per-error retries, and a semantic cache that can run its embeddings on-box. Coming from LiteLLM? `sbproxy config import-litellm` [converts your config](docs/migration-litellm.md).

**Serve your own.** The same binary runs the models: a `serve:` block resolves the weights, fits an engine and quantization to your card, and supervises vLLM or llama.cpp to a governed endpoint. Local models get the same keys, budgets, and failover as hosted ones, so open-weight vs hosted is a one-line swap.

**Govern both.** Virtual keys mint and revoke at runtime, guardrails screen prompts and completions and can redact a streaming response mid-flight, and every request can emit a signed usage receipt you can verify offline. Inbound, federate your MCP tools behind OAuth2, verify signed agents (RFC 9421), and meter AI crawlers with HTTP 402 Pay Per Crawl.

Underneath sits a real reverse proxy on Pingora: auth, automatic TLS, WAF, rate limiting, and hot reload with no dropped connections. [50,713 rps through the full policy chain at 0.6 ms p99](docs/performance.md). The admin console ships in the binary, and replicas cluster over a built-in gossip mesh, no external Redis.

Weighing the options? See [how SBproxy compares](docs/comparison.md) and the [benchmark methodology](https://sbproxy.dev/benchmark).

---

## Getting started

### Install

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
docker pull soapbucket/sbproxy:latest
```

From source (needs Rust 1.82+):

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
```

### Quick start

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

New to SBproxy? The [Getting Started guide](docs/getting-started.md) walks through installing, validating a config, running your first proxy, and where to go next in more depth.

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
| API keys scattered across teams, no accounting | [One endpoint for every provider, on your keys](docs/use-case-own-openrouter.md) |
| You want your coding assistant on hardware you control | [Point Claude Code at your own GPU](docs/use-case-coding-assistant.md) |
| GCP credits and an afternoon | [Serve Qwen, GLM, or Gemma on a cloud L4](docs/use-case-serve-on-l4.md) |
| A GPU that has to pay for itself | [Local first, spill to cloud](docs/use-case-local-first.md) |
| Weights and prompts that must never leave the network | [Air-gapped and sovereign AI](docs/use-case-air-gapped.md) |
| A LiteLLM proxy you want off of | [Migrate off LiteLLM in an afternoon](docs/migration-litellm.md) |
| Shadow Ollama under someone's desk | [Guardrails on every prompt, local or hosted](docs/use-case-guardrails-everywhere.md) |
| AI crawlers eating your content for free | [Meter and monetize the AI that calls you](docs/use-case-meter-crawlers.md) |
| Internal MCP servers multiplying without an owner | [Federate your MCP tools behind one gateway](docs/mcp.md) |
| It works on your laptop and on-call starts Monday | [Run it in production](docs/use-case-production-ops.md) |

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

The full documentation lives in [`docs/README.md`](docs/README.md): manual, configuration reference, AI gateway guide, self-hosting, scripting reference, performance, troubleshooting, architecture, and more. The same guides are browsable at [sbproxy.dev/docs](https://sbproxy.dev/docs). Running the operator for the first time? Start with [`docs/quickstart-operator.md`](docs/quickstart-operator.md).

For contributors: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Community

- [Issue Tracker](https://github.com/soapbucket/sbproxy/issues) for bug reports and feature requests.
- Looking for a managed offering? [SBproxy Enterprise](https://sbproxy.dev/enterprise).

---

## License

Licensed under the [Apache License 2.0](LICENSE). Free for any use, including production and commercial, with no field-of-use restriction.

See also [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md). A [Soap Bucket LLC](https://www.soapbucket.com) project.
