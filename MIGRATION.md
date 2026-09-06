# Migrating from v0.1.x (Go) to v1.0 (Rust)

*Last modified: 2026-09-05*

SBproxy v1.0 replaces the Go implementation with a Rust rewrite built on Cloudflare's Pingora. This document covers what changes for operators upgrading from a v0.1.x Go binary to a v1.0 Rust binary.

The v0.1.x Go binary remains available in the archived, read-only
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository at the `v0.1.2` release tag. New development happens only on v1.0
and later.

## TL;DR

- Your `sb.yml` field names carry over, but the file's *shape* may not. A v0.1.x config that declared its single origin at the top level (`hostname:`, `action:`, `authentication:`, ...) must be rewritten under `origins:`. v1.14.0 rejects thirteen legacy root keys; the next release also rejects the other misplaced origin fields. See [Config file shape](#config-file-shape) below.
- The install command and binary name are unchanged (`sbproxy`, `brew install sbproxy`, `soapbucket/sbproxy:latest`).
- A handful of v0.1.x flags were renamed or removed in v1.0. See `Breaking changes` below.
- Performance improves substantially (3x throughput, 3-4x lower p99 on the AI path) with no config changes required.

## What's the same

- **Config language**. `sb.yml` field names and semantics are preserved across the proxy, AI gateway, auth, policy, transform, and modifier surfaces. The blocks themselves are unchanged; where they sit in the file is not, and that is covered under [Config file shape](#config-file-shape).
- **Binary name and install paths**. The binary is still `sbproxy`. `brew install sbproxy/sbproxy` and `docker pull soapbucket/sbproxy:latest` continue to work.
- **Hot reload**. Send `SIGHUP` (or save the config file when watcher mode is on) and the new pipeline atomically swaps in.
- **Admin endpoint**. `/api/health`, `/api/metrics`, `/api/openapi.{json,yaml}` work the same way.
- **CEL and Lua scripts**. Existing CEL expressions and Lua transform scripts run unchanged on the Rust extension engine.
- **Provider catalog**. The 70-provider AI catalog is the same data file; existing AI routes continue to resolve providers by the same names.

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

- No `sb.yml` field renames between the v0.1.x Go config schema and the v1.0 Rust config schema. (The internal config schema is also referred to as `schema-v1`; that label has not changed.) A block that worked in v0.1.x works in v1.0 with the same key names and the same meaning. Where it has to sit in the file is the part that changed; see below.

### Config file shape

Go compatibility is deprecated. v1.0 does not translate the flat v0.1.x file shape, and it never did.

A v0.1.x config could describe a single origin by putting `hostname`, `action`, `authentication`, and other origin blocks at the top level. The Rust line reads these blocks under `origins.<hostname>:`.

Through v1.13, the compiler dropped flat origin blocks with a warning. v1.14.0 rejects thirteen legacy keys, but still accepts misplaced fields such as `auth`, `transforms`, and `threat_protection`. The next release extends the refusal to every misplaced field and alias accepted by an origin, including those three. Fields with a valid top-level meaning keep that meaning. It also keeps the legacy `hostname` and `ai_proxy` refusals.

This matters for a partially migrated file: a valid `origins:` block can serve traffic while authentication or protection blocks left at the root are dropped. `serve`, `validate`, and hot reload reject the misplaced blocks in the next release and name them in the error.

Two ways forward:

- **Rewrite the file.** Nest the origin's blocks under `origins:` keyed by the hostname the file used to declare at the top level. Nothing inside the blocks changes.

  ```yaml
  # v0.1.x (refused by v1.14.0 and later)
  hostname: api.example.com
  action:
    type: proxy
    url: https://upstream.example.com
  authentication:
    type: api_key
    api_keys: [key-001]
  ```

  ```yaml
  # v1.0
  origins:
    api.example.com:
      action:
        type: proxy
        url: https://upstream.example.com
      authentication:
        type: api_key
        api_keys: [key-001]
  ```

- **Stay on the Go binary.** The archived [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go) repository is public and its `v0.1.2` tag runs the flat config as written. It is maintenance only: read-only source, no new features, and no security patches (see `SECURITY.md`). Treat it as a way to schedule the rewrite, not to avoid it.

Descriptive leftovers are unaffected. A v1.0 config that still carries `config_version`, `id`, `workspace_id`, `version`, `environment`, `tags`, or `debug` at the top level boots, with a warning naming them, because dropping them changes nothing about how the proxy behaves.

### Default changes

- The upstream `Host` header now defaults to the upstream URL's hostname (matching nginx and Envoy `auto_host_rewrite`). Set `host_override: <value>` per action to keep the v0.1.x client-Host pass-through behavior.
- `proxy.trusted_proxies` is now strictly enforced. When the immediate TCP peer is not in the trust list, inbound `X-Forwarded-*` headers are stripped on ingress (forgery defense). v0.1.x had a more permissive default.

## Recommended upgrade procedure

1. **Read `CHANGELOG.md`** for the full list of changes between your starting v0.1.x version and v1.0.0.
2. **Stage the target Rust release alongside v0.1.x** in a non-production environment. Run that binary's `sbproxy validate sb.yml` against a copy of your configuration. Move origin blocks under `origins:` as [Config file shape](#config-file-shape) describes, even when an older validator accepts them. Validation through v1.13 does not catch the flat shape, and v1.14.0 only catches thirteen legacy root keys.
3. **Run a smoke test** against a small percentage of real traffic. Observe `/metrics` on the data-plane listener and `/api/health/targets` on the admin listener for regressions in 4xx/5xx rates or upstream latency.
4. **Verify signed binary** before promoting to production. v1.0 ships with cosign signatures and an SBOM; see `SUPPLY-CHAIN.md` for the verification commands.
5. **Promote to production** once smoke is clean.
6. **Keep v0.1.x available for rollback** for at least one full deployment cycle. The v0.1.x binary at the `v0.1.2` tag of the archived [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go) repository is the recommended rollback target.

## Help

- File migration questions as an issue tagged `migration` on `github.com/soapbucket/sbproxy`.
- Security-sensitive issues go through `SECURITY.md`.
- For migration support with non-trivial v0.1.x customizations, contact support@soapbucket.dev.
