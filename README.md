<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

# SBproxy

*Last modified: 2026-09-05*

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/releases/latest"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy?color=157A5B" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache 2.0 license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.95%2B-orange.svg" alt="Rust 1.95 or newer"></a>
  <a href="https://hub.docker.com/r/soapbucket/sbproxy"><img src="https://img.shields.io/badge/docker-soapbucket%2Fsbproxy-2496ED.svg" alt="Docker image"></a>
  <a href="https://sbproxy.dev"><img src="https://img.shields.io/badge/docs-sbproxy.dev-16150F.svg" alt="Documentation"></a>
</p>

SBproxy is a single Rust binary that puts one policy engine in front of three kinds of traffic: HTTP APIs, AI model calls across 70 native providers reaching 200+ models through one OpenAI-compatible endpoint, and MCP or agent-to-agent tool calls. All three run through the same request pipeline, so a rate limit, a guardrail, a budget cap, and an audit record behave the same way no matter which traffic type triggered them. Every feature in this repository ships under Apache-2.0.

## Why sbproxy

- **Extension without a sidecar.** Five engines run in the same process as the request pipeline: CEL for one-line gates, Rego via the Regorus interpreter for teams migrating policies they already wrote for OPA, Lua and JavaScript for stateful transforms, and sandboxed WebAssembly for anything those can't express. There is no OPA server to run alongside the proxy and no separate plugin daemon. Extension bundles add a hook (action, auth, policy, or transform) from a local directory or a git checkout pinned to a commit SHA plus a content digest (the entry file by default, the whole bundle on request), with optional signature verification, hot-reloaded with no rebuild. See [Extending sbproxy](docs/plugins.md).

- **A verifiable audit trail.** Security, config, key-mutation, and admin-action records each append to their own hash-chained, Ed25519-signed file when you opt the channel in, and `sbproxy audit verify` re-derives the chain from genesis to catch a tampered entry. Policy and guardrail decisions also publish as typed records to your SIEM. Every category of the OWASP LLM Top 10 (2026 edition) is graded enforced, enforced with named limits, or out of gateway scope, each against a named test or a stated reason, alongside eight gateway-layer controls no published list covers. See [AI gateway security coverage](docs/ai-gateway-security-coverage.md).

- **Spend and egress that fail closed.** Budgets deny at the cap across seven scopes instead of logging past it. Every outbound destination the gateway reaches is recorded in a running inventory across ten traffic purposes; a default-deny allowlist arms six of the ten, and engine artifact downloads are the one purpose it can't reach yet. See [AI gateway security coverage](docs/ai-gateway-security-coverage.md).

- **An MCP gateway built for an upstream you don't control.** Tool contracts are pinned by digest in a committed lockfile and re-checked on every catalog refresh; a definition that moved is graded by a compatibility oracle and either reported or blocked, a rename is caught by re-digesting the old name, and a version bump that understates a breaking change fails a linter check before it ships. Tool access is scoped per caller, default-deny. See [MCP and agents](docs/mcp-and-agents.md).

- **Serve models locally, on the same binary.** `sbproxy run` starts a managed local model and hands it the same keys, budgets, and usage ledger that govern requests routed to a hosted provider. A semantic cache serves near-duplicate prompts from an embedding index; run it fully local with the sidecar or in-process source. Metered requests cut Ed25519-signed, hash-chained receipts a buyer can re-derive and verify without trusting your dashboard. See [Run your first managed model](docs/quickstart-serve.md), [Self-hosting](docs/self-hosting.md), and [Attested metering](docs/metering.md).

## Start here

Install a release on Linux or Apple Silicon macOS:

```bash
curl -fsSL https://download.sbproxy.dev | sh
export PATH="$HOME/.local/bin:$PATH"
sbproxy --version
```

The installer writes to `~/.local/bin` by default. Keep the `export` in your
shell profile if that directory was not already on `PATH`. Linux amd64, Linux
arm64, and Apple Silicon macOS arm64 have release archives. Intel Macs can use
the Linux image in Docker or build from source. See the
[runtime manual](docs/manual.md#1-installation) for the complete install matrix
and checksums.

Run the credential-free gateway example next. It starts a local upstream, puts an API behind the gateway, adds an MCP tool, then sends a local OpenAI-compatible completion through the same listener.

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
for config in upstream.yml api.yml mcp.yml sb.yml; do
  sbproxy validate "examples/enterprise-ai-gateway/$config"
done
```

[Follow the getting-started guide.](docs/getting-started.md)

## Choose your job

| If you need to | Start with |
|---|---|
| Understand the parts of a gateway | [Core concepts](docs/core-concepts.md) |
| Trace a request stage by stage, hook by hook | [Request flow](docs/request-flow.md) |
| Put an existing HTTP API behind policy | [API gateway guide](docs/api-gateway.md) |
| Run a local model | [Run your first managed model](docs/quickstart-serve.md) |
| Route to hosted models | [AI gateway reference](docs/ai-gateway.md) |
| Expose or federate MCP tools | [MCP and agents](docs/mcp-and-agents.md) |
| Add policy or transform logic without a rebuild | [Extending sbproxy](docs/plugins.md) |
| Prove what the gateway enforces | [Security](docs/security.md) |
| Run the Kubernetes operator | [Operator quickstart](docs/quickstart-operator.md) |
| Upgrade a running deployment | [Upgrade guide](docs/upgrade.md) |

## Install alternatives

Homebrew:

```bash
brew install soapbucket/tap/sbproxy
```

Docker. The published image has no default configuration command, so mount the file and name the command:

```bash
docker pull soapbucket/sbproxy:latest
docker run --rm -p 8080:8080 \
  -v "$PWD/sb.yml:/etc/sbproxy/sb.yml:ro" \
  soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

Build from source when you need a local development binary:

```bash
make build-release
target/release/sbproxy --version
```

## Documentation and examples

[Documentation index](docs/README.md) groups the guides by first run, traffic type, operations, and reference material. The [`examples/`](examples/) directory contains complete configurations. For the configuration schema, use [configuration.md](docs/configuration.md); for the command surface, use [manual.md](docs/manual.md).

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow. SBproxy is released under [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md).
