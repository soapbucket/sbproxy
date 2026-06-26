<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>

*Last modified: 2026-06-25*

<h3 align="center">Govern the AI you call and the AI that calls you.</h3>

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/releases"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy" alt="Release"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/stargazers"><img src="https://img.shields.io/github/stars/soapbucket/sbproxy" alt="Stars"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.82+-orange.svg" alt="Rust 1.82+"></a>
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="examples/">Examples</a> &middot;
  <a href="docs/README.md">Docs</a>
</p>

<p align="center">
  <img src="docs/assets/ai-gateway.gif" alt="One OpenAI-compatible request routed to OpenAI, Anthropic, and Google through sbproxy" width="900">
</p>

---

## Why SBproxy

SBproxy governs AI traffic in both directions: the calls your apps and agents make out to models and MCP tools, and the calls AI agents and crawlers make in to your APIs and content. It is a real reverse proxy built on Pingora, so the same runtime also handles the rest of your API traffic, as one binary in your VPC. Most teams stitch this together from an LLM proxy, an API gateway, a key store, a guardrail service, and a dashboard they have to trust for spend. This is one process.

- **The AI you call.** 200+ models behind one OpenAI-compatible API, with fallback chains, outcome-aware routing, predictive budgets, and per-error retry policies. Guardrails screen the prompt and the model's response, blocking or redacting a streaming completion mid-flight. A local semantic cache replays near-duplicate prompts with no per-call cost, and the prompt never leaves your network.
- **The AI that calls you.** Charge AI crawlers per request with Pay Per Crawl (x402 or Stripe), verify signed agents with Web Bot Auth (RFC 9421), and negotiate Markdown so agents stop paying for HTML they cannot use. Inbound AI is governed by the same gateway, not a separate product.
- **Govern every key.** Inbound virtual keys are hashed at rest (HMAC-SHA256 plus a server pepper) and minted, rotated, and revoked at runtime through an admin API. A revoke takes effect on the next request, not the next reload. Per-key policy travels with the key: models, budgets, rate, required redaction, model pinning. Upstream credentials are encrypted at rest. See [key management](docs/key-management.md).
- **A real proxy for the rest.** Auth (JWT, OIDC, mTLS), automatic TLS via ACME, WAF, DDoS, CSRF, SSRF guards, and PII redaction. Prompt-injection detection runs on an on-box ONNX model, so it adds no per-call cost and nothing leaves your network, even air-gapped. Guardrails run as a quorum mesh on a latency budget. The proxy that fronts your models is the security layer, not a thing you bolt on after it.
- **Run as a fleet without Redis.** Point every replica at a shared store and a key minted on one works on all, with a revoke seen across the fleet. The mesh that keeps the cache, budgets, and per-key spend counters coherent (gossip, CRDTs, a consistent-hash ring) is open source here, so the cluster coordinates itself without an external Redis or a vendor's control plane.
- **Prove the spend.** Every request can emit a hash-chained, Ed25519-signed usage receipt with token counts and USD cost that you re-derive and verify offline. Metrics, logs, and OpenTelemetry GenAI traces come from the same process, ready for Phoenix, Langfuse, Grafana, or Datadog.
- **Stay fast, stay yours.** Sub-millisecond p99 overhead, idle RSS in single-digit megabytes, hot reload with no dropped connections. One binary, Apache 2.0, in your VPC.

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
make run CONFIG=sb.yml
curl -H "Host: myapp.example.com" http://127.0.0.1:8080/get
```

`myapp.example.com` is the host your client sees; SoapBucket matches it against `origins:` and forwards to the upstream. Use any hostname you want here; `example.com` is reserved (RFC 2606), so it never collides with anything real.

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

The full documentation lives in [`docs/README.md`](docs/README.md): manual, configuration reference, AI gateway guide, scripting reference, performance, troubleshooting, architecture, and more. Running the operator for the first time? Start with [`docs/quickstart-operator.md`](docs/quickstart-operator.md).

For contributors: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Community

- [Issue Tracker](https://github.com/soapbucket/sbproxy/issues) for bug reports and feature requests.
- Looking for a managed offering? [SBproxy Enterprise](https://sbproxy.dev/enterprise).

---

## License

Licensed under the [Apache License 2.0](LICENSE). Free for any use, including production and commercial, with no field-of-use restriction.

See also [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md). A [Soap Bucket LLC](https://www.soapbucket.com) project.
