# Changelog

All notable changes to SBproxy v1.x. Versions before v1.0 shipped as the
Go implementation and now live in the archived
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository.

## [1.0.0] - 2026-05-03

First Rust release of SBproxy on this repository.

### What changed

- **Implementation**: SBproxy is now written in Rust on Cloudflare's
  Pingora. The Go implementation that previously occupied this repo
  (`v0.1.0` through `v0.1.2`) has moved to
  [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go),
  preserved as the `v0.1.2-go-final` branch and tag, and is now in
  maintenance-only mode.
- **Data plane**: routing, AI gateway, MCP gateway, guardrails, security
  policies, and scripting (CEL, Lua, JavaScript, WebAssembly) all ship
  open source in this release. See [`docs/architecture.md`](docs/architecture.md)
  for the request pipeline shape.
- **Enterprise tier**: see [`docs/enterprise.md`](docs/enterprise.md) for
  what enterprise adds on top of the OSS data plane and how to request
  access.

### Upgrading from v0.1.x (Go)

The internal config schema (`schema-v1`) is supported by both the Go
`v0.1.x` line and this Rust `v1.x` line, so existing `sb.yml` files
should compile unchanged. See [`MIGRATION.md`](MIGRATION.md) for the
full upgrade path.
