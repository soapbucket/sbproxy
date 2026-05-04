<p align="center">
  <img src="https://sbproxy.dev/logo.svg" alt="SBproxy" width="80" height="80">
</p>

<h1 align="center">SBproxy</h1>

*Last modified: 2026-04-28*

<h3 align="center">The AI gateway built like a real proxy.</h3>

<p align="center">
  <a href="https://github.com/soapbucket/sbproxy/releases"><img src="https://img.shields.io/github/v/release/soapbucket/sbproxy" alt="Release"></a>
  <a href="https://mariadb.com/bsl11/"><img src="https://img.shields.io/badge/License-BUSL_1.1-orange.svg" alt="License"></a>
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

---

## Why SBproxy

Most teams run one tool for HTTP traffic and another for LLM traffic. That's two systems to configure, deploy, and monitor. SBproxy handles both in one binary.

- **One config file** replaces your reverse proxy, AI gateway, and the middleware glue between them.
- **200+ LLM models** behind an OpenAI-compatible API, with fallback chains, guardrails, and budgets.
- **Secure by default.** Auth, rate limiting, WAF, DDoS, and CSRF are built in.
- **Hot reload** with no dropped connections.
- **Sub-millisecond p99 overhead.** Idle RSS in single-digit megabytes.

---

## Install

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

## Documentation

The full documentation lives in [`docs/README.md`](docs/README.md): manual, configuration reference, AI gateway guide, scripting reference, performance, troubleshooting, architecture, and more.

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

Licensed under [BSL 1.1](LICENSE). Source available on GitHub. Production use is permitted for everything except offering SBproxy as a competing hosted or managed service.

For commercial licensing inquiries, contact `legal@soapbucket.com`. See also [NOTICE](NOTICE) and [TRADEMARKS](TRADEMARKS.md). A [Soap Bucket LLC](https://www.soapbucket.org) project.
