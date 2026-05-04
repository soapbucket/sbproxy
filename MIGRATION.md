# Migrating from v0.1.x (Go) to v1.0 (Rust)

*Last modified: 2026-04-28*

SBproxy v1.0 replaces the Go implementation with a Rust rewrite built on Cloudflare's Pingora. This document covers what changes for operators upgrading from a v0.1.x Go binary to a v1.0 Rust binary.

The v0.1.x Go binary continues to be available at `github.com/soapbucket/sbproxy-go` (archived, read-only) at the `v0.1.2` release tag. New development happens only on v1.0 and later.

## TL;DR

- Your `sb.yml` is mostly portable. Field names match. Most operators upgrade by swapping the binary and re-deploying.
- The install command and binary name are unchanged (`sbproxy`, `brew install sbproxy`, `ghcr.io/soapbucket/sbproxy:latest`).
- A handful of v0.1.x flags were renamed or removed in v1.0. See `Breaking changes` below.
- Performance improves substantially (3x throughput, 3-4x lower p99 on the AI path) with no config changes required.

## What's the same

- **Config language**. `sb.yml` field names, structure, and semantics are preserved across the proxy, AI gateway, auth, policy, transform, and modifier surfaces.
- **Binary name and install paths**. The binary is still `sbproxy`. `brew install sbproxy/sbproxy` and `docker pull ghcr.io/soapbucket/sbproxy:latest` continue to work.
- **Hot reload**. Send `SIGHUP` (or save the config file when watcher mode is on) and the new pipeline atomically swaps in.
- **Admin endpoint**. `/api/health`, `/api/metrics`, `/api/openapi.{json,yaml}` work the same way.
- **CEL and Lua scripts**. Existing CEL expressions and Lua transform scripts run unchanged on the Rust extension engine.
- **Provider catalog**. The 90+ AI provider catalog is the same data file; existing AI routes continue to resolve providers by the same names.

## What's new in v1.0

These are additive and do not require config changes:

- **Cloudflare-style edge security policies**: `ai_crawl_control` (Pay Per Crawl), `exposed_credentials`, `page_shield`, `bulk_redirects`, `cache_reserve`, `dlp_catalog`, `web_bot_auth`. See `docs/` for each.
- **OpenAPI emission**. The gateway publishes its live config as OpenAPI 3.0 at `/api/openapi.json` (admin) and per-host `/.well-known/openapi.json` (opt-in via `expose_openapi: true` on the origin).
- **Storage action with real backends**. The `storage` action now drives S3, GCS, Azure Blob, or local filesystem via `object_store`.
- **JavaScript and WASM scripting** alongside CEL and Lua.
- **Pattern-aware PII redaction at the request boundary** for AI routes.
- **Single-digit-MB idle RSS** and sub-millisecond p99 added latency.
- **Hierarchical budgets across team/project/user/model** with downgrade-on-exceed.

## Breaking changes

### Removed

- No CLI flags or environment variables from v0.1.x have been removed in v1.0. If your v0.1.x deployment uses a non-default flag and you cannot find the equivalent in v1.0, file an issue tagged `migration`.

### Renamed

- No `sb.yml` field renames between the v0.1.x Go config schema and the v1.0 Rust config schema. (The internal config schema is also referred to as `schema-v1`; that label has not changed.) The compatibility promise is pinned by the `v1_compat::v1_fixtures_compile_unmodified` test in `crates/sbproxy-config/`. If a real-world v0.1.x config fails to compile under v1.0, that is a bug; file an issue tagged `migration`.

### Default changes

- The upstream `Host` header now defaults to the upstream URL's hostname (matching nginx and Envoy `auto_host_rewrite`). Set `host_override: <value>` per action to keep the v0.1.x client-Host pass-through behavior.
- `proxy.trusted_proxies` is now strictly enforced. When the immediate TCP peer is not in the trust list, inbound `X-Forwarded-*` headers are stripped on ingress (forgery defense). v0.1.x had a more permissive default.

## Recommended upgrade procedure

1. **Read `CHANGELOG.md`** for the full list of changes between your starting v0.1.x version and v1.0.0.
2. **Stage v1.0 alongside v0.1.x** in a non-production environment. Point a copy of your `sb.yml` at the v1.0 binary and run `sbproxy validate sb.yml`. Address any validation errors.
3. **Run a smoke test** against a small percentage of real traffic. Observe `/api/metrics` and `/api/health/targets` for any regressions in 4xx/5xx rates or upstream latency.
4. **Verify signed binary** before promoting to production. v1.0 ships with cosign signatures and an SBOM; see `SUPPLY-CHAIN.md` for the verification commands.
5. **Promote to production** once smoke is clean.
6. **Keep v0.1.x available for rollback** for at least one full deployment cycle. The v0.1.x binary at the `v0.1.2` tag of `github.com/soapbucket/sbproxy-go` is the recommended rollback target.

## Help

- File migration questions as an issue tagged `migration` on `github.com/soapbucket/sbproxy`.
- Security-sensitive issues go through `SECURITY.md`.
- For paid migration support (e.g., enterprise customers with non-trivial v0.1.x customizations), contact support@soapbucket.dev.
