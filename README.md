<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

# SBproxy

*Last modified: 2026-08-03*

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml"><img src="https://github.com/soapbucket/sbproxy/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/soapbucket/sbproxy/releases/latest"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy?color=157A5B" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache 2.0 license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.82%2B-orange.svg" alt="Rust 1.82 or newer"></a>
  <a href="https://hub.docker.com/r/soapbucket/sbproxy"><img src="https://img.shields.io/badge/docker-soapbucket%2Fsbproxy-2496ED.svg" alt="Docker image"></a>
  <a href="https://sbproxy.dev"><img src="https://img.shields.io/badge/docs-sbproxy.dev-16150F.svg" alt="Documentation"></a>
</p>

SBproxy is an open source Enterprise AI Gateway for API, MCP and agent, and AI model traffic. Every feature in this repository ships under Apache-2.0.

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
```

[Follow the getting-started guide.](docs/getting-started.md)

## Choose your job

| If you need to | Start with |
|---|---|
| Understand the parts of a gateway | [Core concepts](docs/core-concepts.md) |
| Put an existing HTTP API behind policy | [API-estate guide](docs/getting-started-api-estate.md) |
| Run a local model | [Run your first managed model](docs/quickstart-serve.md) |
| Route to hosted models | [AI gateway reference](docs/ai-gateway.md) |
| Expose or federate MCP tools | [MCP gateway](docs/mcp.md) |
| Run the Kubernetes operator | [Operator quickstart](docs/quickstart-operator.md) |
| Upgrade a running deployment | [Upgrade guide](docs/upgrade.md) |

## Install alternatives

Homebrew:

```bash
brew tap soapbucket/tap
brew install sbproxy
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
