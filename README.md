<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>

*Last modified: 2026-06-24*

<h3 align="center">The AI gateway built like a real proxy.</h3>

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

Most teams run one tool for HTTP traffic and another for LLM traffic, then bolt on a third for keys, a fourth for guardrails, and a dashboard they have to trust for spend. SBproxy is one binary that does all of it, built on Pingora so the proxy in front of your models is a real proxy.

- **Route every model.** 200+ models behind one OpenAI-compatible API, with fallback chains, outcome-aware routing, predictive budgets, and per-error retry policies.
- **Govern every key.** Inbound virtual keys are hashed at rest (HMAC-SHA256 plus a server pepper) and minted, rotated, and revoked at runtime through an admin API. A revoke takes effect on the next request, not the next reload. Upstream provider credentials are encrypted at rest. See [key management](docs/key-management.md).
- **Secure in the same process.** Auth (JWT, OIDC, mTLS), WAF, DDoS, CSRF, SSRF guards, PII redaction, and prompt-injection detection on a local model. Guardrails run as a quorum mesh on a latency budget. The proxy that fronts your models is the security layer, not a thing you bolt on after it.
- **Prove the spend.** Every request can emit a hash-chained, Ed25519-signed usage receipt with token counts and USD cost that you re-derive and verify offline.
- **Run as a fleet.** Point every replica at a shared key store and a key minted on one works on all, with a revoke invalidated across the fleet. The clustering substrate for a distributed cache and per-key spend counters (gossip, CRDTs, a consistent-hash ring) is open source here, so you do not need a vendor's control plane.
- **Keep cost and prompts on-box.** A local semantic cache replays near-duplicate prompts with no per-call cost, and the prompt never leaves your network. Metrics, logs, and OpenTelemetry GenAI traces with token and USD cost come from the same process, ready for Phoenix, Langfuse, Grafana, or Datadog.
- **Stay fast.** Sub-millisecond p99 overhead, idle RSS in single-digit megabytes, hot reload with no dropped connections.

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

## Upgrading from v0.1.x (Go)

SBproxy v1.0 is a Rust rewrite. The Go implementation that previously occupied this repository is archived at [soapbucket/sbproxy-go](https://github.com/soapbucket/sbproxy-go) and tagged `v0.1.2-go-final`. New work happens here. See [MIGRATION.md](./MIGRATION.md) for the upgrade path; existing `sb.yml` files should compile unchanged.

---

## License

Licensed under the [Apache License 2.0](LICENSE). Free for any use, including production and commercial, with no field-of-use restriction.

See also [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md). A [Soap Bucket LLC](https://www.soapbucket.com) project.
