# OSS Distributed Semantic Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the canonical OSS embedding semantic cache with memory, Redis, and current OSS mesh backends while preserving existing memory configurations, preventing cross-tenant or cross-policy replay, and making distributed failures observable cache misses.

**Architecture:** `sbproxy-ai` owns typed semantic-cache configuration, hardened embedding clients, deterministic namespace and LSH logic, the backend-neutral async store contract, exact cosine reranking, wire validation, and the memory store. Standalone OpenAI-compatible embeddings use the bounded `sbproxy-httpkit` client and `sbproxy-security` DNS pinning instead of constructing a raw reqwest client. `sbproxy-core` owns Redis and mesh adapters because it already depends on `sbproxy-platform` and `sbproxy-mesh`. Core builds an immutable semantic-cache registry for each compiled origin and forward rule. Redis reuses the validated `proxy.l2_cache_settings` connection and `AsyncRedisKVStore`. Mesh extends the current OSS cache transport with one bounded routed-prefix snapshot operation, gates it through the authenticated fleet-capability state, and never imports the historical mesh implementation.

**Tech Stack:** Rust 2021 with MSRV 1.82, Tokio, async-trait, serde, schemars, postcard, SHA-256, `lru`, `bytes`, `futures`, `sbproxy-httpkit::OutboundClientBuilder`, `sbproxy-security` URL and DNS checks, `AsyncRedisKVStore`, Redis Lua scripts, `DistributedCache<Bytes>`, authenticated typed cluster state, Prometheus metrics, Cargo nextest, local RESP fixtures, disposable Redis, and two-node OSS mesh transport fixtures

## Global Constraints

- All implementation in this pull request ships in the Apache-2.0 repository.
- Do not copy historical semantic-cache, Redis, mesh, admin, purge, classifier-hook, or configuration files. Reimplement the approved behavior against current OSS interfaces.
- Do not copy a file with a Proprietary or BUSL header. Do not add credentials, PEM fixtures, signing seeds, generated secrets, or raw production configuration.
- The existing action-level `semantic_cache:` block remains canonical. Do not revive top-level or origin `extensions.semantic_cache` configuration.
- `backend` defaults to `memory`. An existing valid semantic-cache configuration that omits `backend` retains process-local LRU lookup, TTL, threshold, embedding source, response replay, and fail-open behavior.
- An omitted `max_response_bytes` preserves the current memory behavior. Redis
  and mesh still enforce the fixed 8 MiB wire-entry ceiling. Operators may
  set a smaller positive cap for any backend.
- `max_entries` remains the memory LRU capacity. Redis and mesh accept the
  field for configuration compatibility but use TTL plus bounded LSH
  manifests instead of pretending to enforce a process-wide distributed
  entry count.
- The memory backend retains the current full same-namespace cosine scan. LSH narrows candidates only for Redis and mesh, so adding distributed backends does not reduce the recall of existing memory deployments.
- Redis uses the already validated `proxy.l2_cache_settings` Redis connection. Do not add another DSN, password, TLS, or pool block beneath `semantic_cache`.
- Mesh uses `crate::cluster::current_cluster_handle()`, `ClusterHandle::mesh_node()`, and the current `sbproxy-mesh` transport. Do not read `CompiledConfig.mesh` and do not start a second gossip or transport listener.
- No new Cargo feature controls semantic-cache backends. `sbproxy-core` already links `sbproxy-platform` and `sbproxy-mesh`; the runtime `backend` enum selects memory, Redis, or mesh.
- The standalone OpenAI-compatible embedding source uses
  `sbproxy-httpkit::OutboundClientBuilder`, disables redirects for every
  request because credentials may live in either auth fields or static
  headers, resolves and pins every hostname before connecting, applies the
  configured bounded timeout, and reads at most 1 MiB of response data.
  Public destinations are the default. Private destinations require the
  explicit `allow_private_base_url: true` opt-in and remain DNS-pinned.
- The sidecar embedding source is local by contract. Its TCP endpoint must be
  an absolute HTTP or HTTPS URL with an explicit literal loopback address and
  port. Hostnames, public addresses, arbitrary private addresses, userinfo,
  query strings, fragments, and non-root paths are rejected before a runtime
  is built.
- All backend operations use one async semantic store contract. Do not wrap the synchronous Redis store in `spawn_blocking`.
- Semantic lookup errors, Redis errors, peer errors, isolation, malformed records, and incompatible records become cache misses on the request path. Admin purge returns a partial or failed result instead of claiming success.
- A hit must match tenant, credential identity, origin, requested model, API
  surface, normalized request context, concrete request host, embedding
  identity and dimensions, compiled semantic-configuration digest,
  response-policy identity, and semantic wire version.
- Cache keys contain only fixed ASCII labels and SHA-256 digests. They never contain raw prompts, tenant IDs, subjects, API key IDs, authorization values, model names, hostnames, URLs, paths, or policy JSON.
- Cache values contain model output, response headers, and embeddings and are sensitive operator data. Never log, trace, meter, or return these values through the admin API. Redis TLS and cluster transport security remain operator requirements.
- Treat Redis and authenticated cluster peers as trusted cache
  infrastructure. This pull request adds defensive validation, but it does
  not add value encryption, signatures, or a MAC that could make a malicious
  backend safe to replay.
- Strip hop-by-hop, framing, cookie, authentication, request-correlation, and rate-limit headers before storage. Reconstruct current request-specific route metadata on replay.
- LSH is candidate generation only. Every candidate passes schema, namespace, expiry, dimension, finite-vector, and exact cosine checks before replay.
- Multi-table index writes may complete partially. A payload without an index or an index without a payload is a safe miss. No partial write may create a false hit.
- Mesh owner failure is not durable cache replication. A failed owner produces a miss. After membership removes that owner, the next write routes to the new owner and warms the new shard.
- `CacheOp` and `CacheResult` use postcard enum discriminants. Append new mesh
  variants at the end. The existing authenticated typed cluster-state
  capability plane advertises `semantic_cache_snapshot_v1`. Runtime
  construction rejects mesh semantic bindings unless every live member has a
  current authenticated declaration. Unknown, mixed, suspect, or unreachable
  membership fails closed. A bound store also rejects a changed membership
  snapshot before sending a new snapshot operation, so a joining or restarted
  node requires capability verification and pipeline reload.
- Reversible PII continues to disable semantic caching for that action. Do not weaken the existing protection.
- Use `/Users/rick/projects/soapbucket/sbproxy/target` as
  `CARGO_TARGET_DIR` for every local Rust command. Workflow snippets use the
  CI runner's ordinary target directory.
- Use focused tests while implementing. Run the broader affected-crate gate once in Task 11.
- Add concise rustdoc to every new public type, variant, field, constant, and
  method. The affected crates warn on missing documentation and the final
  Clippy gate promotes warnings to errors.
- Stage only the exact files named by each task. Never use a broad directory
  add in a shared or dirty worktree.
- Public prose uses direct language and contains no em dash or en dash.
- Broad documentation consolidation, new golden walkthroughs, and VHS recording changes remain in the final documentation pull request. This pull request updates only the generated schema and the narrow operator references required to configure and operate the feature.

---

## File Structure

Create, change, or directly verify these units:

```text
crates/sbproxy-ai/src/semantic_cache.rs
    Canonical cache orchestration, embedding clients, exact reranking, and
    compatibility entry points.
crates/sbproxy-ai/src/semantic_cache/config.rs
    Typed backend and LSH configuration, redacted Debug, endpoint policy,
    defaults, validation, and schema.
crates/sbproxy-ai/src/semantic_cache/identity.rs
    Fixed digest namespaces, prompt digests, and internal key construction.
crates/sbproxy-ai/src/semantic_cache/lsh.rs
    Deterministic multi-table random projection candidate buckets.
crates/sbproxy-ai/src/semantic_cache/store.rs
    Async store contract, entries, queries, writes, purge, health, and stats.
crates/sbproxy-ai/src/semantic_cache/memory.rs
    Full-scan LRU memory backend preserving current behavior.
crates/sbproxy-ai/src/semantic_cache/wire.rs
    Versioned bounded postcard encoding and defensive decoding.
crates/sbproxy-ai/src/bin/generate-ai-semantic-cache-schema.rs
schemas/ai-semantic-cache.schema.json
    Generated action.semantic_cache field contract.

crates/sbproxy-core/src/semantic_cache_runtime.rs
    Origin and forward-rule registry plus runtime and validation assembly.
crates/sbproxy-core/src/semantic_cache_runtime/redis.rs
    Async Redis payloads, bounded atomic Lua indexes, health, and purge.
crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs
    Thin adapter over the current OSS mesh node and transport, plus
    authenticated live-member capability evidence.
crates/sbproxy-core/src/key_capability.rs
    Advertise and verify semantic_cache_snapshot_v1 through current typed
    cluster state.
crates/sbproxy-core/src/cluster.rs
    Publish the shared capability list from one process-monotonic generation
    source before periodic refresh.
crates/sbproxy-core/src/server/ai_support.rs
    Canonical semantic prompt extraction and non-prompt request-context digest.
crates/sbproxy-core/src/server/ai_dispatch.rs
crates/sbproxy-core/src/server.rs
    Async lookup, replay, write-on-miss, and fail-open behavior.
crates/sbproxy-core/src/pipeline.rs
    Immutable semantic-cache registry in each compiled pipeline.
crates/sbproxy-core/src/admin_cache.rs
crates/sbproxy-core/src/admin.rs
    Async semantic status and scoped purge behind existing operator controls.
crates/sbproxy-core/src/admin_compression.rs
    Update the one direct CompiledPipeline fixture for the new registry field.
crates/sbproxy-core/src/hooks.rs
crates/sbproxy-core/tests/hooks.rs
    Remove unused semantic lookup and stream cache recorder seams.

crates/sbproxy-mesh/src/state/distributed_cache.rs
crates/sbproxy-mesh/src/transport/frame.rs
crates/sbproxy-mesh/src/transport/client.rs
crates/sbproxy-mesh/src/transport/server.rs
    Bounded routed-prefix snapshot over the existing authenticated transport.

crates/sbproxy-ai/src/ai_metrics.rs
crates/sbproxy-observe/src/metric_registry.rs
docs/metrics-stability.md
    Closed-label backend operation metrics.

crates/sbproxy-config/src/compiler.rs
crates/sbproxy-config/src/types.rs
    Remove stale semantic-cache extension examples and comments.
.github/workflows/ci.yml
    Run the disposable Redis semantic Lua contract in the existing Redis lane.

e2e/tests/semantic_cache_e2e.rs
e2e/tests/semantic_cache_sidecar_e2e.rs
    Existing real proxy memory-path regression tests.
e2e/tests/semantic_cache_distributed_e2e.rs
    One two-process Redis hit and one two-process OSS mesh hit through the
    public AI request path.
docs/ai-gateway.md
docs/admin.md
docs/admin-api-reference.md
docs/architecture.md
docs/observability.md
examples/semantic-cache-local/README.md
examples/semantic-cache-openai/README.md
schemas/README.md
scripts/check-config-schema.sh
    Minimal field, backend, admin, and failure documentation.
```

### Task 1: Type and Validate the Semantic Cache Configuration

**Files:**
- Create: `crates/sbproxy-ai/src/semantic_cache/config.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache.rs`
- Modify: `crates/sbproxy-ai/src/handler.rs`
- Modify: `crates/sbproxy-ai/src/lib.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Create: `crates/sbproxy-ai/src/bin/generate-ai-semantic-cache-schema.rs`
- Create: `schemas/ai-semantic-cache.schema.json`
- Modify: `schemas/README.md`
- Modify: `scripts/check-config-schema.sh`
- Modify: `crates/sbproxy-config/src/litellm.rs`

**Interfaces:**
- Consumes: the current action-level `AiHandlerConfig.semantic_cache`.
- Reuses the existing `sbproxy-httpkit` and `sbproxy-security` dependencies
  already declared by `sbproxy-ai`. Do not add a second HTTP client crate,
  resolver crate, Cargo feature, or lockfile change in this task.
- Produces:

```rust
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCacheBackend {
    #[default]
    Memory,
    Redis,
    Mesh,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticLshConfig {
    #[serde(default = "default_lsh_tables")]
    pub tables: u8,
    #[serde(default = "default_lsh_planes")]
    pub planes: u8,
    #[serde(default = "default_candidates_per_bucket")]
    pub candidates_per_bucket: usize,
    #[serde(default = "default_lsh_seed")]
    pub seed: String,
}

impl Default for SemanticLshConfig {
    fn default() -> Self {
        Self {
            tables: default_lsh_tables(),
            planes: default_lsh_planes(),
            candidates_per_bucket: default_candidates_per_bucket(),
            seed: default_lsh_seed(),
        }
    }
}

#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: SemanticCacheBackend,
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    #[serde(default)]
    pub lsh: SemanticLshConfig,
    #[serde(default)]
    pub source: EmbeddingSource,
    #[serde(default)]
    pub embedding: Option<EmbeddingProviderConfig>,
    #[serde(default)]
    pub sidecar: Option<SidecarEmbeddingConfig>,
    #[serde(default)]
    pub inprocess: Option<InprocessEmbeddingConfig>,
    #[serde(default)]
    pub openai: Option<OpenAiEmbeddingConfig>,
}

impl EmbeddingCacheConfig {
    pub fn validate(&self) -> Result<(), SemanticCacheConfigError>;
}
```

- Adds this field to `OpenAiEmbeddingConfig`:

```rust
/// Permit a private or loopback embedding destination. Public-only by default.
#[serde(default)]
pub allow_private_base_url: bool,
```

- Produces:

```rust
pub const MAX_EMBEDDING_TIMEOUT_MS: u64 = 60_000;
pub const MAX_EMBEDDING_RESPONSE_BYTES: usize = 1024 * 1024;
```

- Produces these exact defaults and limits:

```rust
pub const DEFAULT_LSH_TABLES: u8 = 8;
pub const MAX_LSH_TABLES: u8 = 16;
pub const DEFAULT_LSH_PLANES: u8 = 6;
pub const MAX_LSH_PLANES: u8 = 63;
pub const DEFAULT_CANDIDATES_PER_BUCKET: usize = 32;
pub const MAX_CANDIDATES_PER_BUCKET: usize = 256;
pub const MAX_SEMANTIC_CACHE_ENTRIES: usize = 1_000_000;
pub const MAX_SEMANTIC_ENTRY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SEMANTIC_RESPONSE_BYTES: usize = 7 * 1024 * 1024;
pub const MAX_EMBEDDING_DIMENSIONS: usize = 8_192;
pub const DEFAULT_LSH_SEED: &str = "sbproxy-semantic-v2";
```

- Changes `AiHandlerConfig.semantic_cache` from
  `Option<serde_json::Value>` to `Option<EmbeddingCacheConfig>`.
- Keeps the existing private
  `embedding_cache: OnceLock<Option<Arc<EmbeddingCache>>>` and
  `embedding_cache()` memory constructor temporarily. Task 8 removes both
  after the compiled registry is available.

- [ ] **Step 1: Write failing typed-configuration tests**

Add tests in `semantic_cache/config.rs`:

```rust
#[test]
fn existing_config_defaults_to_memory_without_changing_cache_tuning() {
    let config: EmbeddingCacheConfig = serde_json::from_value(json!({
        "enabled": true,
        "threshold": 0.9,
        "ttl_secs": 60,
        "max_entries": 64,
        "embedding": {
            "provider": "openai",
            "model": "text-embedding-3-small"
        }
    }))
    .unwrap();
    assert_eq!(config.backend, SemanticCacheBackend::Memory);
    assert_eq!(config.source, EmbeddingSource::Provider);
    assert_eq!(config.threshold, 0.9);
    assert_eq!(config.ttl_secs, 60);
    assert_eq!(config.max_entries, 64);
    assert_eq!(config.lsh.tables, 8);
    assert_eq!(config.lsh.planes, 6);
    assert_eq!(config.lsh.candidates_per_bucket, 32);
}

#[test]
fn all_three_backends_parse_as_closed_values() {
    for (value, expected) in [
        ("memory", SemanticCacheBackend::Memory),
        ("redis", SemanticCacheBackend::Redis),
        ("mesh", SemanticCacheBackend::Mesh),
    ] {
        let config = parse_backend(value).unwrap();
        assert_eq!(config.backend, expected);
    }
    assert!(parse_backend("custom").is_err());
}

#[test]
fn stale_streaming_and_key_template_fields_are_rejected() {
    assert!(parse_extra("streaming", json!({"enabled": true})).is_err());
    assert!(parse_extra("key_template", json!("{tenant}:{prompt}")).is_err());
}
```

Also test:

```text
threshold rejects NaN, infinity, less than 0.0, and greater than 1.0
ttl_secs rejects 0
max_entries rejects 0 and values above 1,000,000
max_response_bytes rejects 0 and values above 7 MiB when present
lsh.tables rejects 0 and 17
lsh.planes rejects 0 and 64
lsh.candidates_per_bucket rejects 0 and 257
lsh.seed rejects empty and values longer than 128 bytes
enabled false accepts a missing source-specific block
enabled provider without embedding remains inert for compatibility
enabled sidecar without sidecar remains inert for compatibility
enabled inprocess without inprocess remains inert for compatibility
enabled openai without openai remains inert for compatibility
sidecar accepts only an explicit literal IPv4 or IPv6 loopback URL and port
sidecar rejects localhost, public, RFC1918, link-local, userinfo, query,
fragment, non-root path, missing port, and non-HTTP schemes
sidecar rejects zero or above-60-second timeouts
openai rejects zero or above-60-second timeouts
openai rejects invalid, non-HTTP, userinfo, query, and fragment-bearing base URLs
openai rejects literal or DNS-resolved private targets by default
openai accepts a private target only with allow_private_base_url true
unknown fields fail instead of silently becoming unused extension policy
reversible PII still clears the typed semantic_cache field
generated schema closes backend and source enums
generated_schema_matches_every_runtime_numeric_and_length_bound
embedding_cache_debug_redacts_every_endpoint_path_key_header_and_credential
ai_handler_debug_redacts_every_endpoint_path_key_header_and_credential
```

Keep the source-specific inert behavior because the LiteLLM converter currently
emits `semantic_cache: { enabled: true }` without enough information to choose
an embedding provider. Do not turn that existing generated configuration into
a load-time failure in this pull request. Surface the inert reason through
admin status in Task 9.

- [ ] **Step 2: Run the configuration tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai -E 'test(semantic_cache::config)'
```

Expected: compile failure because `SemanticCacheBackend`,
`SemanticLshConfig`, and the typed handler field do not exist.

- [ ] **Step 3: Move wire configuration into the config module**

Create the module directory first:

```bash
mkdir -p crates/sbproxy-ai/src/semantic_cache
```

Move `EmbeddingCacheConfig`, `EmbeddingSource`,
`EmbeddingProviderConfig`, `SidecarEmbeddingConfig`,
`InprocessEmbeddingConfig`, and `OpenAiEmbeddingConfig` into
`semantic_cache/config.rs`. Re-export their current public names from
`semantic_cache.rs` and `lib.rs` so existing crate users keep compiling.

Derive `JsonSchema` on every wire type. Apply `deny_unknown_fields` to structs.
Keep `EmbeddingSource` spellings `provider`, `sidecar`, `inprocess`, and
`openai`. Do not add a legacy compatibility variant.

Apply matching `schemars` range and length annotations for every bound in
`validate()`. Generated JSON Schema must reject the same out-of-range values
as runtime construction rather than advertising a wider contract.

Do not derive `Debug` for `EmbeddingCacheConfig`,
`OpenAiEmbeddingConfig`, `SidecarEmbeddingConfig`, or
`InprocessEmbeddingConfig`. Each of those types is secret-bearing directly or
through a nested field. Give each one a manual redacted implementation.
`EmbeddingCacheConfig` may report backend, source, thresholds, numeric bounds,
and whether each source block exists. Nested implementations may report the
source kind, safe model identifier, timeout, credential presence, and static
header count. They must never report a URL, hostname, userinfo, filesystem
path, API key, auth-header name, auth prefix, static-header name, or
static-header value. The top-level implementation must call only those
redacted nested implementations. Test formatted `EmbeddingCacheConfig` and
`AiHandlerConfig` with distinct sentinel values in every forbidden field and
assert that none of them appears. Keep `SemanticCacheBackend`,
`EmbeddingSource`, `EmbeddingProviderConfig`, and `SemanticLshConfig`
derivable only because they contain no endpoint, path, or credential field.

`validate()` enforces all limits before a runtime is built. Its error display
names only the invalid field and safe bound. It must not print OpenAI API keys,
auth-header names, auth prefixes, static-header names or values, URLs,
hostnames, paths, or environment-expanded values.

- [ ] **Step 4: Harden standalone OpenAI and sidecar endpoints**

Remove the raw `reqwest::Client::builder()` path from
`compute_embedding_openai_impl`. Add one private parsed-endpoint helper and an
injectable resolver seam used only by focused tests. Production resolution
uses `sbproxy_security::ssrf::resolve_host_addrs`; literal IPs use the parsed
URL directly. Reject an empty resolution. When `allow_private_base_url` is false,
reject the complete address set if any address fails
`sbproxy_security::is_private_ip`. When it is true, permit those addresses but
still pin them.

Immediately before the request, pass the single validated address set to:

```rust
let http = sbproxy_httpkit::OutboundClientBuilder::new()
    .request_timeout(Duration::from_millis(config.timeout_ms))
    .no_redirects()
    .into_inner()
    .resolve_to_addrs(host, &resolved_addrs)
    .build()
    .map_err(|_| EmbeddingEndpointError::Client)?;
```

The request must connect through those pins and must not ask the system
resolver for the hostname again. Resolve and pin on each standalone embedding
call so a later DNS change receives a fresh public/private decision instead
of riding an old pooled destination. Keep the httpkit 5-second connect bound,
TLS verification, pool bounds, and user agent. Do not expose
`into_inner()` until after httpkit has installed those defaults.

Every standalone embedding request disables redirects even when `api_key` is
absent. Static headers may carry credentials, so a 3xx response is an opaque
request failure and no `Location` is followed. Mark generated auth and every
static header value sensitive. Header parser failures name only
`auth_header`, `headers.name`, or `headers.value`; they never echo the header
name or value.

Use a private closed error enum with variants for invalid URL, disallowed
destination, DNS failure, invalid header, client construction, request,
status, oversized response, and invalid response. Its `Display` strings are
fixed labels. Do not wrap the reqwest, URL, resolver, header, tonic, or JSON
source error into the displayed chain.

Replace `Response::json()` in the embedding response parser with a checked
chunk loop. Reject an advertised content length above
`MAX_EMBEDDING_RESPONSE_BYTES`, stop before appending a chunk that would cross
the same cap, and deserialize only the bounded bytes. Use checked arithmetic.
Status, transport, resolver, body-limit, and JSON failures map to a closed
`EmbeddingEndpointError` whose display contains no URL, host, address, header,
credential, response body, or upstream error string. Preserve quota
settlement at the existing send seam after endpoint, header, and client
construction have succeeded.

`EmbeddingCacheConfig::validate()` performs structural validation and calls
the public-only SSRF validator for an OpenAI base URL unless the explicit
private opt-in is set. The request-time resolver always repeats the decision
and supplies the connection pins, which closes the validation-to-connect DNS
rebinding gap. Require an absolute HTTP or HTTPS base URL with a host, no
userinfo, query, or fragment, and a timeout in
`1..=MAX_EMBEDDING_TIMEOUT_MS`.

Define sidecar TCP as a local-only transport. Parse the endpoint during
`EmbeddingCacheConfig::validate()`, then call
`ClassifierClient::validate_endpoint`. Require `http` or `https`, an explicit
port, a literal IPv4 loopback or IPv6 loopback host, no userinfo, query, or
fragment, and an empty or `/` path. Reject `localhost`, public addresses,
RFC1918 addresses, link-local addresses, and arbitrary internal hostnames.
Require `timeout_ms` in `1..=MAX_EMBEDDING_TIMEOUT_MS`. The current tonic
client keeps its call timeout and decode-message bound.
Validate the returned vector dimension through the common 8,192-dimension
limit before cache lookup. Map sidecar validation, connect, timeout, RPC, and
response errors to the same closed embedding failure classes without
displaying the tonic error or configured endpoint.

Add focused tests in `semantic_cache.rs`:

```text
openai_embedding_uses_the_httpkit_request_timeout
openai_embedding_never_follows_a_redirect_or_forwards_auth_or_static_headers
openai_embedding_public_policy_rejects_a_private_dns_answer
openai_embedding_public_policy_accepts_only_an_all_public_address_set
openai_embedding_private_opt_in_still_uses_the_resolved_address_pin
openai_embedding_pin_prevents_a_second_rebinding_resolution
openai_embedding_rejects_advertised_body_above_one_mib
openai_embedding_rejects_chunked_body_crossing_one_mib
openai_embedding_accepts_a_bounded_response
openai_embedding_error_never_contains_url_host_header_key_or_body
sidecar_embedding_rejects_a_non_loopback_endpoint_before_connect
```

Use loopback servers only behind `allow_private_base_url: true`. A fake host
resolver maps a non-resolving test hostname to that listener; a successful
request proves reqwest used the pin. A second resolver answer changes to a
private address and the test asserts that no second resolution or connection
occurs. The redirect fixture records both listeners and proves the target
listener receives no request, generated authorization, or sentinel static
header. Test both declared and chunked oversized responses.

- [ ] **Step 5: Make the AI handler field typed**

Replace the opaque field with:

```rust
/// Optional embedding semantic cache for this AI action.
#[serde(default)]
pub semantic_cache: Option<crate::semantic_cache::EmbeddingCacheConfig>,
```

At the start of `AiHandlerConfig::from_config`, after deserialization:

```rust
if let Some(semantic_cache) = config.semantic_cache.as_ref() {
    semantic_cache
        .validate()
        .map_err(|error| anyhow::anyhow!("ai semantic_cache: {error}"))?;
}
```

Update `embedding_cache()` to read `self.semantic_cache.as_ref()` directly
instead of cloning and reparsing `serde_json::Value`. Preserve the current
`EmbeddingCache::from_config` memory construction until Task 8, but return
`None` when the explicit backend is Redis or mesh. Those selections must
never silently run against memory while the compiled registry is not yet
installed.

The current dead stream-recorder branch calls `.get("streaming")` on the
opaque value. Set its temporary `stream_policy` to
`serde_json::Value::Null` so this typed-config commit compiles. The recorder
has no OSS implementation and the typed contract intentionally rejects
`streaming`; Task 8 removes the complete dead branch and its hook types.

Keep the reversible PII block in `from_config`. It still sets
`config.semantic_cache = None` and emits no user data.

- [ ] **Step 6: Keep LiteLLM migration output compatible**

The existing LiteLLM converter writes only:

```yaml
semantic_cache:
  enabled: true
```

Keep that conversion stable and add a test that the generated action parses
through `AiHandlerConfig::from_config`. It remains inert until an operator
adds one current embedding source block. Do not invent an embedding provider
or copy a LiteLLM credential into a new field.

- [ ] **Step 7: Generate and gate the dedicated schema**

The generator prints `schemars::schema_for!(EmbeddingCacheConfig)` as stable
pretty JSON with a trailing newline. Add:

```bash
"schemas/ai-semantic-cache.schema.json|-p sbproxy-ai --bin generate-ai-semantic-cache-schema"
```

to `scripts/check-config-schema.sh`.

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo run --quiet --locked -p sbproxy-ai --bin generate-ai-semantic-cache-schema \
  > schemas/ai-semantic-cache.schema.json
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-config-schema.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache::config) | test(openai_embedding) | test(sidecar_embedding)'
```

Expected: the schema gate, typed defaults, compatibility fixtures, bounds,
unknown-field checks, endpoint policy, DNS pin, redirect, body limit,
redaction, and reversible-PII tests pass.

- [ ] **Step 8: Commit the typed contract**

```bash
git add crates/sbproxy-ai/src/semantic_cache/config.rs \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/handler.rs crates/sbproxy-ai/src/lib.rs \
  crates/sbproxy-ai/src/bin/generate-ai-semantic-cache-schema.rs \
  crates/sbproxy-config/src/litellm.rs \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  schemas/ai-semantic-cache.schema.json schemas/README.md \
  scripts/check-config-schema.sh
git commit -m "feat(ai): type semantic cache backends"
```

### Task 2: Add Safe Namespace Digests and Multi-Table LSH

**Files:**
- Create: `crates/sbproxy-ai/src/semantic_cache/identity.rs`
- Create: `crates/sbproxy-ai/src/semantic_cache/lsh.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache.rs`
- Modify: `crates/sbproxy-ai/src/lib.rs`
- Modify: `Cargo.lock`
- Modify: `crates/sbproxy-core/Cargo.toml`
- Modify: `crates/sbproxy-core/src/server/ai_support.rs`
- Modify: `crates/sbproxy-core/src/server/tests.rs`

**Interfaces:**
- Consumes: current canonical AI request bodies, `RequestContext` identity,
  the request-pinned governed-policy revision, one compiled action-policy
  digest, the embedding source identity, and `SemanticLshConfig`.
- Produces:

```rust
#[derive(Clone)]
pub struct SemanticNamespaceInput<'a> {
    pub origin_route: &'a str,
    pub request_host: &'a str,
    pub tenant_id: &'a str,
    pub credential_identity: &'a str,
    pub requested_model: &'a str,
    pub api_surface: &'a str,
    pub request_context_digest: &'a [u8; 32],
    pub embedding_identity: &'a str,
    pub embedding_dimensions: usize,
    pub semantic_config_digest: &'a [u8; 32],
    pub response_policy_digest: &'a [u8; 32],
    pub schema_version: u16,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticNamespace {
    origin_digest: [u8; 32],
    scope_digest: [u8; 32],
    compatibility_digest: [u8; 32],
}

impl SemanticNamespace {
    pub fn derive(input: SemanticNamespaceInput<'_>) -> Self;
    pub fn origin_digest(&self) -> [u8; 32];
    pub fn origin_prefix(&self) -> String;
    pub fn namespace_prefix(&self) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticBucket {
    pub table: u8,
    pub value: u64,
}

pub struct RandomProjectionLsh;

impl RandomProjectionLsh {
    pub fn from_config(config: &SemanticLshConfig) -> Result<Self, LshError>;
    pub fn buckets(
        &self,
        embedding: &[f32],
    ) -> Result<smallvec::SmallVec<[SemanticBucket; 8]>, LshError>;
}
```

- Produces an internal key builder:

```rust
pub struct SemanticEntryKeys {
    pub entry_key: String,
    pub bucket_indexes: smallvec::SmallVec<[SemanticBucketIndex; 8]>,
}

pub struct SemanticBucketIndex {
    pub manifest_key: String,
    pub member_prefix: String,
    pub routing_key: String,
}

pub fn semantic_entry_keys(
    namespace: &SemanticNamespace,
    prompt_digest: &[u8; 32],
    buckets: &[SemanticBucket],
) -> SemanticEntryKeys;

pub fn semantic_entry_key(
    namespace: &SemanticNamespace,
    prompt_digest: &[u8; 32],
) -> String;

pub fn semantic_origin_route_digest(compiled_origin_route: &str) -> [u8; 32];

pub fn semantic_configuration_digest(
    config: &EmbeddingCacheConfig,
) -> [u8; 32];
```

- Produces from core:

```rust
pub(super) struct SemanticPromptInput {
    pub text: String,
    pub request_context_digest: [u8; 32],
}

pub(super) fn extract_semantic_prompt(
    body: &serde_json::Value,
) -> SemanticPromptInput;

pub(super) fn semantic_response_policy_digest(
    static_action_policy_digest: &[u8; 32],
    governed_policy_revision: &str,
    api_surface: &str,
) -> [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SemanticIdentityError {
    #[error("semantic action policy cannot be canonicalized")]
    InvalidActionPolicy,
}

pub(crate) fn semantic_static_action_policy_digest(
    origin: &sbproxy_config::CompiledOrigin,
    forward_rule_idx: Option<usize>,
) -> Result<[u8; 32], SemanticIdentityError>;
```

The static helper and its closed error are `pub(crate)` because Task 7 calls
it from `server::ai_dispatch` and Task 8 calls it from the sibling
`semantic_cache_runtime` module. Keep prompt extraction and the request-time
response digest at `pub(super)` inside `server`.

- [ ] **Step 1: Write failing namespace-isolation tests**

Add tests named:

```text
namespace_changes_with_origin
namespace_changes_with_request_host_under_the_same_wildcard_origin
namespace_changes_with_tenant
namespace_changes_with_api_key_id
namespace_changes_with_principal_subject_fallback
namespace_changes_with_unnamed_authorization_digest
namespace_changes_with_requested_model
namespace_changes_with_api_surface
namespace_changes_with_request_context
namespace_changes_with_embedding_model
namespace_changes_with_embedding_dimensions
namespace_changes_with_semantic_configuration
namespace_changes_with_static_action_policy
namespace_changes_with_governed_policy_revision
namespace_changes_with_schema_version
namespace_is_stable_across_openai_api_key_rotation
namespace_changes_with_static_embedding_header_behavior
semantic_configuration_changes_with_backend_threshold_lsh_model_endpoint_or_local_path
semantic_configuration_ignores_openai_api_key_rotation
semantic_configuration_changes_when_openai_api_key_presence_changes
semantic_configuration_changes_with_auth_header_or_prefix
semantic_configuration_changes_with_static_header_name_or_value
semantic_configuration_canonicalizes_distinct_static_header_order_and_name_case
semantic_configuration_changes_when_duplicate_header_order_changes_the_final_value
semantic_configuration_never_renders_static_header_names_or_values
static_action_policy_projection_excludes_the_semantic_cache_block
fixed_namespace_prompt_and_key_fixture_matches_the_v2_byte_encoding
keys_contain_only_fixed_labels_and_lowercase_hex
keys_do_not_contain_any_raw_identity_or_prompt_value
origin_and_namespace_prefixes_select_only_their_intended_scope
entry_key_rebuilds_from_a_valid_prompt_digest
origin_and_request_host_case_and_one_trailing_dot_normalize_identically
```

Use sentinels such as `tenant-secret-a`, `sk-secret-value`,
`subject-secret-a`, `X-Secret-Embedding-Route`,
`header-secret-value`, `refund policy`, and
`https://private.example/v1`. Assert none appear in any rendered key or
`Debug` representation.

Credential selection in core follows this exact order:

```text
1. Principal::api_key_id() when nonempty
2. PrincipalSource plus Principal.sub when sub is nonempty
3. SHA-256 of the Authorization value when a header exists
4. the fixed anonymous marker
```

The credential identity helper returns a digest-ready safe string and never
returns the raw authorization value.

- [ ] **Step 2: Write failing request-context tests**

Add `extract_semantic_prompt` beside the existing prompt helpers. Share
low-level content-part traversal where useful, but keep
`extract_prompt_text` behavior unchanged: its full system, history, tool, and
asset representation is still consumed by guardrails, classifiers, tracing,
and policy code. Add tests proving:

```text
paraphrasing the final text changes semantic text but preserves context digest
changing a system message preserves semantic text and changes context digest
changing a tool definition changes the context digest
changing tool_choice changes the context digest
changing response_format changes the context digest
changing temperature, top_p, seed, or stop changes the context digest
changing role order or content block types changes the context digest
changing an image, audio, or file reference changes the context digest
changing injected RAG context changes the context digest
OpenAI chat, OpenAI Responses, and Anthropic Messages produce stable digests
object key order does not change the canonical digest
raw prompt, system, tool, and asset values never appear in the digest output
```

The normalized context replaces only the semantic query slot with a typed
sentinel. For chat and Messages requests, that slot is the final user text
turn. Preserve the content-block shape and replace only its text-bearing
parts, so a final-turn image, audio, or file remains in context. For a
Responses input array, use only the final user input-text slot and preserve
all earlier input items. For a string Responses input or string legacy
completion prompt, the complete string is the semantic text. Skip a batch or
ambiguous prompt shape instead of dropping context. Keep system and developer
instructions, earlier conversation turns, tool calls and results, tool
schemas, sampling controls, response format, and non-text asset identity in
the canonical hash. This lets a paraphrase of the current query find
candidates while preventing reuse across different instructions, history,
tools, or assets. Add a test that changing an earlier user or assistant turn
changes the context digest. When the RAG runtime is present, run this helper
on the final canonical body after context injection and the augmented input
guardrails. The injected system context therefore fences cache reuse when
retrieved content changes while the final user query remains the semantic
text.

Use `serde_json_canonicalizer` before SHA-256 so map insertion order cannot
split the namespace. The canonicalized bytes are temporary and never logged.
The public result is only the fixed 32-byte digest.
Add `serde_json_canonicalizer.workspace = true` to `sbproxy-core` for the
request-context and static-policy projections.

After that manifest edit, refresh only the lockfile's direct dependency edge,
review it, and return to locked commands:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo metadata --offline --format-version 1 >/dev/null
git diff -- Cargo.lock crates/sbproxy-core/Cargo.toml
```

Expected: the existing locked `serde_json_canonicalizer` version is added to
the `sbproxy-core` package dependency list with no unrelated version update.

- [ ] **Step 3: Write failing LSH and collision tests**

Add deterministic tests:

```rust
#[test]
fn deterministic_tables_match_a_fixed_fixture() {
    let lsh = RandomProjectionLsh::from_config(&fixture_config()).unwrap();
    let buckets = lsh.buckets(&[0.8, 0.6, 0.0]).unwrap();
    assert_eq!(buckets.len(), 8);
    assert_eq!(buckets, expected_fixture_buckets());
}

#[test]
fn exact_reranking_is_required_after_a_bucket_collision() {
    let lsh = RandomProjectionLsh::from_config(&collision_config()).unwrap();
    let left = normalized([1.0, 0.0, 0.0]);
    let right = normalized([0.0, 1.0, 0.0]);
    assert!(shares_at_least_one_bucket(&lsh, &left, &right));
    assert_eq!(cosine(&left, &right), 0.0);
}
```

Also assert:

```text
the same vector produces one bucket per table
table IDs are unique and ordered
the same seed is deterministic across instances
changing the seed changes at least one bucket
projection seed storage scales with tables times planes, not dimensions
zero-length vectors fail
all-zero vectors fail
NaN and infinity fail
dimensions above 8,192 fail
planes above 63 fail before shifting a u64
```

Use random projection only to select candidates. Do not expose a
`bucket_is_hit` API.

- [ ] **Step 4: Run the identity and LSH tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache::identity) | test(semantic_cache::lsh)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(extract_semantic_prompt) | test(semantic_request_context)'
```

Expected: compile failures for the new namespace, LSH, and prompt-input
interfaces.

- [ ] **Step 5: Implement domain-separated digests**

Hash each boundary separately with a fixed domain label and zero-byte field
separators:

```text
sbproxy-semcache-origin-v2
sbproxy-semcache-scope-v2
sbproxy-semcache-compat-v2
sbproxy-semcache-prompt-v2
```

Normalize the compiled origin route and concrete request hostname to
lowercase and remove one trailing DNS dot before hashing. The origin route
may be a compiler-validated leading wildcard such as `*.example.com`; the
request hostname must be the concrete `RequestContext.hostname`. Accept
neither value from an operator-supplied Redis prefix, URL, or path.
Encode every digest deterministically. Start with the literal domain bytes
and one zero byte. For each ordered field, append its length as one unsigned
64-bit big-endian integer, the field bytes, and one zero byte. Encode
integers at their fixed field width in big-endian form and feed 32-byte child
digests as raw bytes, never as hex. Reject a value that cannot be represented
before hashing. This fixed encoding prevents concatenation aliases and
architecture-dependent digests.

The origin digest covers the configured origin route so an admin origin purge
can remove every concrete host matched by one wildcard route. The scope
digest covers tenant and credential identity. The compatibility digest covers
the concrete request host, requested model, API surface, normalized request
context, embedding source and model identity, embedding dimensions, the
semantic-configuration digest, response-policy digest, and schema version.

Use the exact field order shown by `SemanticNamespaceInput`: origin route for
the origin digest; tenant then credential for the scope digest; concrete
request host, requested model, API surface, request-context digest, embedding
identity, embedding dimensions, semantic-configuration digest,
response-policy digest, then schema version for the compatibility digest.
The prompt digest contains only the prompt domain and the exact semantic
prompt UTF-8 bytes returned by `extract_semantic_prompt`; do not add a second,
backend-specific text normalization step.

Do not use `CompiledPipeline.config_revision` as the semantic compatibility
fence. The current field is intentionally only an origin-set identity and
does not change for many guardrail, AI action, or response-policy edits.

`semantic_configuration_digest` hashes a secret-safe compatibility projection
of the typed semantic block: backend, threshold bits, TTL, memory capacity
when the backend is memory, explicit response cap, LSH settings, embedding
source, and embedding identity. Embedding identity includes the configured
provider, model, private-destination opt-in, hashed endpoint or base URL
identity, hashed local model and tokenizer path identities, and a canonical
digest of the effective standalone embedding headers.

Build the header projection with the same validated `HeaderMap::insert`
semantics used by the request. Normalize names case-insensitively, retain only
the final value for a duplicate name, sort the effective map by normalized
name, then hash each name and value separately with these domains:

```text
sbproxy-semcache-header-name-v2
sbproxy-semcache-header-value-v2
```

Feed only the two raw 32-byte child digests into the ordered semantic
configuration encoding. Never format or retain a raw header name or value.
Changing a static header name, value, or duplicate order that changes the
effective map creates a new namespace. Reordering distinct headers or
changing header-name case does not.

The generated credential value from `OpenAiEmbeddingConfig.api_key` is the
only credential-only header input. Exclude that key value so ordinary API-key
rotation does not fragment the namespace. Include a credential-present
boolean based on the same nonempty-key check as request construction, the
hashed `auth_header` name, and the hashed `auth_prefix`, because adding
credential injection or changing how it is applied changes request behavior.
Hash the normalized auth name with the header-name domain and the prefix with
the header-value domain, then feed them under a distinct generated-auth tag
so they cannot alias a static header pair. Treat every
entry in `headers` as behavior-bearing, even when an operator uses one as a
custom credential. Its name and value digests therefore remain in
compatibility identity. Document that operators who need rotation-stable
credentials should use `api_key` plus `auth_header` and `auth_prefix`, rather
than placing the credential in `headers`.

Raw endpoint, path, header, and credential text never appears in a key,
formatted digest input, log, or admin response. A change to any
behavior-bearing field creates a new namespace.

Task 8 computes `static_action_policy_digest` from the canonical raw action
for the selected main or forward-rule slot plus its slot identity. It covers
provider and routing configuration, guardrails, PII behavior, compression,
and response shaping. At request time,
`semantic_response_policy_digest` combines that static digest with the
already request-pinned `peer_policy_revision` returned by
`prepare_ai_request_identity` and the API surface. This fences governed-key
policy changes without reparsing or rehashing the full policy on each lookup.
Only the resulting digest reaches the namespace.

Implement the shared static helper in Task 2. Its canonical object contains
`action_config`, `policy_configs`, `transform_configs`, serialized
`response_modifiers`, `compression`, `auto_content_negotiate`, and
`content_signal`. Including the origin compression block is mandatory even
though compressed sessions bypass lookup, because changes to response
representation policy must not share a static response fence. For a forward
slot, replace `action_config` with the complete corresponding raw
`CompiledOrigin.forward_rules[index]`. Include an explicit `main` or
`forward_rule:<index>` tag. Hash the canonical bytes immediately, drop them,
and never format them. Task 7 uses this helper temporarily on the memory path.
Task 8 moves the result into the immutable registry so the request path stops
rehashing it.

Before canonicalizing, remove only the selected action's
`semantic_cache` field from that static policy projection. The dedicated
secret-free `semantic_configuration_digest` already owns its behavior.
Leaving it in the broader raw action would reintroduce credential values and
memory-only tuning into distributed compatibility identity. For a forward
rule, remove only the nested inline action field and retain its matchers,
modifiers, and every other behavior-bearing field.

Use this fixed key grammar:

```text
sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:entry:<64hex>
sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:index:t:<2hex>:b:<16hex>
sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:index:t:<2hex>:b:<16hex>:member:<64hex>
```

Start the independent OSS wire and keyspace at version 2 so it cannot read or
overwrite an older experimental or historical `v1` semantic namespace.

All purge prefixes come from the same builder. Never concatenate an
operator-supplied prefix or Redis glob.

- [ ] **Step 6: Implement deterministic multi-table projection**

At construction, derive one `u64` projection seed from SHA-256 over the fixed
`sbproxy-semcache-lsh-v2` domain, length-prefixed operator seed bytes, table
byte, and plane byte. Use the first eight digest bytes in big-endian order.

For each zero-based input coordinate index `d`, add
`d * 0x9E3779B97F4A7C15` with wrapping arithmetic to that projection seed and
run the fixed SplitMix64 finalizer:

```text
z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
z = (z ^ (z >> 27)) * 0x94D049BB133111EB
z = z ^ (z >> 31)
```

Use the low output bit as a Rademacher coefficient: zero is `-1.0`, one is
`1.0`. Accumulate each dot product in `f64`; a value greater than or equal to
zero sets the plane bit. This exact mapping makes the fixture portable across
architectures and avoids one SHA-256 call per embedding element. Do not use
process RNG and do not persist a dimension-sized projection matrix.

Normalize vectors once, reject non-finite or zero-norm inputs, and keep at
most 63 planes in one `u64`. The exact cosine reranker lands in Task 3 and
must compare normalized vectors again after candidate loading.

- [ ] **Step 7: Run and commit identity plus LSH**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache::identity) | test(semantic_cache::lsh)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(extract_semantic_prompt) | test(semantic_request_context)'
git add crates/sbproxy-ai/src/semantic_cache/identity.rs \
  crates/sbproxy-ai/src/semantic_cache/lsh.rs \
  crates/sbproxy-ai/src/semantic_cache.rs crates/sbproxy-ai/src/lib.rs \
  Cargo.lock crates/sbproxy-core/Cargo.toml \
  crates/sbproxy-core/src/server/ai_support.rs \
  crates/sbproxy-core/src/server/tests.rs
git commit -m "feat(ai): isolate semantic cache namespaces"
```

Expected: identity dimensions, API-key rotation stability, static-header
behavior isolation, canonical request context, secret absence, deterministic
LSH, invalid-vector, and collision fixtures pass.

### Task 3: Define the Async Store Contract and Preserve the Memory Backend

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/sbproxy-ai/Cargo.toml`
- Modify: `crates/sbproxy-mesh/Cargo.toml`
- Create: `crates/sbproxy-ai/src/semantic_cache/store.rs`
- Create: `crates/sbproxy-ai/src/semantic_cache/memory.rs`
- Create: `crates/sbproxy-ai/src/semantic_cache/wire.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache.rs`
- Modify: `crates/sbproxy-ai/src/lib.rs`

**Interfaces:**
- Consumes: `SemanticNamespace`, `SemanticEntryKeys`, current
  `CachedHttpResponse`, current LRU and TTL semantics, and `postcard`.
- Produces:

```rust
#[derive(Clone)]
pub struct StoredSemanticEntry {
    pub schema_version: u16,
    pub namespace: SemanticNamespace,
    pub prompt_digest: [u8; 32],
    pub embedding: Vec<f32>,
    pub response: Arc<CachedHttpResponse>,
    pub stored_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone)]
pub struct SemanticStoreLookupQuery {
    pub namespace: SemanticNamespace,
    pub keys: SemanticEntryKeys,
    pub embedding: Arc<[f32]>,
    pub threshold: f32,
    pub maximum_per_bucket: usize,
}

#[derive(Clone)]
pub struct SemanticExactMatch {
    pub entry: Arc<StoredSemanticEntry>,
    pub score: f32,
}

#[derive(Clone)]
pub struct SemanticStoreLookup {
    pub exact_hit: Option<SemanticExactMatch>,
    pub best_score: Option<f32>,
    pub rejected: u64,
    pub expired: u64,
    pub incompatible: u64,
    pub truncated: bool,
}

#[derive(Clone)]
pub struct SemanticStoreWrite {
    pub entry: Arc<StoredSemanticEntry>,
    pub keys: SemanticEntryKeys,
    pub ttl_secs: u64,
    pub maximum_per_bucket: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SemanticPurgeScope {
    All,
    Origin { origin_digest: [u8; 32] },
    Namespace { namespace: SemanticNamespace },
    Entry {
        namespace: SemanticNamespace,
        prompt_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticPurgeReport {
    pub removed: u64,
    pub nodes_attempted: u64,
    pub nodes_failed: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticHealthState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticStoreHealth {
    pub backend: SemanticCacheBackend,
    pub state: SemanticHealthState,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SemanticStoreStats {
    pub candidate_reads: u64,
    pub candidate_read_errors: u64,
    pub writes: u64,
    pub write_errors: u64,
    pub rejected_records: u64,
    pub purges: u64,
    pub purge_errors: u64,
    pub purged_entries: u64,
    pub local_entries: Option<usize>,
}

#[derive(Default)]
pub struct SemanticStoreCounters {
    candidate_reads: AtomicU64,
    candidate_read_errors: AtomicU64,
    writes: AtomicU64,
    write_errors: AtomicU64,
    rejected_records: AtomicU64,
    purges: AtomicU64,
    purge_errors: AtomicU64,
    purged_entries: AtomicU64,
}

impl SemanticStoreCounters {
    pub fn record_candidate_read(&self, success: bool);
    pub fn record_write(&self, success: bool);
    pub fn record_rejected(&self, count: u64);
    pub fn record_purge(&self, report: &SemanticPurgeReport);
    pub fn snapshot(&self, local_entries: Option<usize>) -> SemanticStoreStats;
}

pub trait SemanticClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticStoreError {
    #[error("semantic cache backend unavailable")]
    Unavailable,
    #[error("semantic cache write rejected")]
    InvalidWrite,
    #[error("semantic cache backend returned invalid state")]
    InvalidState,
    #[error("semantic cache operation failed")]
    OperationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticLookupError {
    #[error("semantic cache embedding is invalid")]
    InvalidEmbedding,
    #[error("{0}")]
    Store(#[from] SemanticStoreError),
}

#[async_trait::async_trait]
pub trait SemanticCacheStore: Send + Sync {
    fn backend(&self) -> SemanticCacheBackend;

    async fn lookup(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError>;

    async fn put(
        &self,
        write: &SemanticStoreWrite,
    ) -> Result<(), SemanticStoreError>;

    async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError>;

    async fn health(&self) -> SemanticStoreHealth;

    fn stats(&self) -> SemanticStoreStats;
}

pub fn semantic_purge_prefix(scope: &SemanticPurgeScope) -> String;
```

`semantic_purge_prefix` returns a literal generated key prefix with no Redis
glob characters. `All` returns `sbproxy:semcache:v2:`, origin and namespace
return their trailing-colon prefixes, and entry returns the exact entry key.
The Redis adapter alone appends `*` to the first three scopes for `SCAN
MATCH`; mesh passes the literal prefix directly to `purge_prefix_local`.

- Produces:

```rust
pub const SEMANTIC_CACHE_SCHEMA_VERSION: u16 = 2;

pub const MAX_SEMANTIC_RESPONSE_HEADERS: usize = 128;
pub const MAX_SEMANTIC_HEADER_NAME_BYTES: usize = 256;
pub const MAX_SEMANTIC_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub const MAX_SEMANTIC_TOTAL_HEADER_BYTES: usize = 64 * 1024;

pub fn encode_entry(entry: &StoredSemanticEntry) -> Result<Bytes, WireError>;

pub fn decode_entry(
    bytes: &[u8],
    expected_namespace: &SemanticNamespace,
    now_unix_ms: u64,
) -> Result<StoredSemanticEntry, WireError>;
```

- [ ] **Step 1: Write a failing common store contract**

Add a local generic test helper in `store.rs` that accepts an
`Arc<dyn SemanticCacheStore>` and proves:

```text
empty store misses
put then load returns the stored entry
TTL expiry removes the entry
namespace lookup cannot see another tenant scope
origin purge removes only one origin
namespace purge removes only one namespace
entry purge removes only one prompt
all purge removes every semantic key
health is healthy after successful operations
stats count reads, writes, and purges without raw labels
store errors have fixed Display text and no source error containing a DSN,
peer address, key, prompt, response, or embedding
```

Run this contract against `MemorySemanticCacheStore`.

Because dependency crates do not expose their `#[cfg(test)]` helpers, do not
make this harness part of the public production API. Task 4 mirrors the same
assertion table in a private `semantic_cache_runtime::tests` helper inside
core; Redis and mesh both use that core-local harness.

- [ ] **Step 2: Write failing wire rejection tests**

Add tests for:

```text
version 2 round-trip preserves status, safe headers, body, vector, and times
maximum legal body, vector, and headers fit beneath the 8 MiB entry cap
wire input above 8 MiB is rejected before deserialization
unknown schema version is rejected
wrong namespace is rejected
expired entry is rejected
expiry at or before storage time is rejected
write-time seconds-to-milliseconds overflow is rejected
zero, NaN, or infinite embedding elements are rejected
embedding dimensions above 8,192 are rejected
status other than the canonical cacheable status 200 is rejected
response body above the 7 MiB body cap is rejected
more than 128 headers is rejected
header names above 256 bytes are rejected
individual header values above 8 KiB are rejected
aggregate header bytes above 64 KiB are rejected
```

Do not include raw bytes, headers, namespace inputs, or decode internals in
`WireError::Display`.

- [ ] **Step 3: Write memory compatibility and exact-rerank tests**

The memory store deliberately ignores LSH buckets and scans all live entries
in the requested namespace. Add tests:

```text
near vector in a different LSH bucket is still returned as a memory hit
LRU access refreshes recency
insert at capacity evicts the least recently used logical entry
eviction removes every index reference
expired entries are removed lazily
same-scope full scan preserves the existing nearest-vector fixture
cross-scope entries never enter exact selection
```

Add a common exact-rerank helper:

```rust
pub fn select_exact_hit<'a, I>(
    query: &[f32],
    candidates: I,
    threshold: f32,
    expected_namespace: &SemanticNamespace,
    now_unix_ms: u64,
) -> Result<SemanticStoreLookup, SemanticLookupError>
where
    I: IntoIterator<Item = &'a Arc<StoredSemanticEntry>>;

pub struct SemanticExactSelector {
    // Private normalized query, threshold, current winner, best score,
    // deterministic tie digest, and closed rejection counts.
}

impl SemanticExactSelector {
    pub fn new(
        query: Arc<[f32]>,
        threshold: f32,
        expected_namespace: SemanticNamespace,
        now_unix_ms: u64,
    ) -> Result<Self, SemanticLookupError>;

    pub fn consider(&mut self, candidate: Arc<StoredSemanticEntry>);

    pub fn finish(self) -> SemanticStoreLookup;
}
```

It revalidates schema version, namespace, expiry, dimension, vector
finiteness, and norm for every candidate, computes exact normalized cosine,
chooses the highest score, retains the best below-threshold score for
diagnostics, and breaks an equal-score tie by lexicographic prompt digest. A
bucket collision below threshold must miss. An invalid query returns
`SemanticLookupError`; an invalid candidate increments `rejected` and is
skipped so one malformed distributed record cannot fail the lookup.

`rejected` is the sum of the `expired` and `incompatible` candidate counts.
Memory records lazy TTL removals as expired. Redis and mesh classify a
well-formed expired wire value as expired and every corrupt, wrong-version,
wrong-namespace, wrong-dimension, or non-finite value as incompatible. These
closed counts let `EmbeddingCache` maintain its existing diagnostics without
exposing a rejected value or backend error.

Implement `select_exact_hit` as the synchronous iterator convenience wrapper
over `SemanticExactSelector`. Redis and mesh feed decoded fetch results into
the selector as their bounded async stream yields them. The selector retains
only the current winning entry, score metadata, and counters. It never
materializes every decoded response body at once.
Each lookup snapshots `now_unix_ms` once and passes the same value to wire
decode and exact selection, so candidates do not change classification
halfway through one operation.

- [ ] **Step 4: Run the store tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache::store) | test(semantic_cache::memory) | test(semantic_cache::wire)'
```

Expected: compile failures for the store, memory, and wire modules.

- [ ] **Step 5: Add postcard as one shared workspace dependency**

Move the existing mesh declaration into the workspace dependency table:

```toml
postcard = { version = "1", features = ["use-std"] }
```

Use `postcard.workspace = true` from `sbproxy-ai` and `sbproxy-mesh`. Do not
introduce bincode. Prefix the encoded payload with a fixed four-byte magic
`SBSC` and a two-byte big-endian schema version before postcard data so
random Redis or mesh bytes fail cheaply. Keep the magic private to the wire
module and export `SEMANTIC_CACHE_SCHEMA_VERSION` through the facade with the
other backend-neutral constants.

Refresh and review the lockfile immediately after the manifest edits:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo metadata --offline --format-version 1 >/dev/null
git diff -- Cargo.lock Cargo.toml crates/sbproxy-ai/Cargo.toml \
  crates/sbproxy-mesh/Cargo.toml
```

Expected: the already locked postcard package becomes a direct
`sbproxy-ai` dependency and the mesh declaration moves to the workspace,
with no unrelated version update. Every later Cargo command remains
`--locked`.

Declare the new child modules from `semantic_cache.rs`. Re-export every
backend-neutral interface named in Tasks 1 through 3 from
`sbproxy_ai::semantic_cache` and from the existing `sbproxy_ai` facade,
including the config, identity, LSH, store, memory, selector, wire error,
wire limit, encode, and decode types and functions. Core adapters must not
reach into a private child module. Keep implementation-only DTOs, bounded
serde visitors, memory state, counters' atomics, and selector fields private.

Keep both `CachedHttpResponse` and `StoredSemanticEntry` out of serde.
Serialize them only through a borrowed wire DTO that exposes the response
body as a byte slice. Decode through an owned bounded wire DTO and wrap the
validated response in `Arc`. Task 7 changes the response body backing from
`Vec<u8>` to `Bytes` at the same time it updates every dispatcher call site,
so this store-foundation commit remains buildable. Replace its
value-revealing derived `Debug`, and the derived `Debug` on `EmbeddingHit`,
with redacted implementations that show only status, body length, header
count, embedding dimension, and score as applicable. Give
`StoredSemanticEntry`, store lookup queries and results, and writes the same
treatment. Do not implement `Debug` for `SemanticExactSelector`, which
retains the normalized query and current candidate.
Do not derive `Debug` for `SemanticNamespace`. Give `SemanticPurgeScope` a
redacted implementation that prints only `All`, `Origin`, `Namespace`, or
`Entry`, never a digest.
Sentinel prompt, response, header, and embedding values must not appear in
formatted output.

The wire layer is the only distributed serialization path and applies
response and header bounds before encoding or after decoding.

`encode_entry` applies all structural limits before allocation.
`decode_entry` first checks total bytes, magic, and version, then
deserializes and rechecks namespace, expiry, vector, response, and header
bounds. Compute `expires_at_unix_ms` with checked multiplication and addition;
never saturate an operator TTL into a practically immortal entry.

Do not rely on post-deserialization length checks for attacker-controlled
postcard vectors. Use wire-only DTO fields with custom bounded serde visitors
that reject the declared embedding count above 8,192, header count above 128,
individual string lengths above their constants, and body length above the
wire cap before reserving those collections. Add malformed length-prefix
fixtures that declare `usize::MAX`-scale vectors in a tiny input and prove
decoding returns `WireError` without a large allocation.

- [ ] **Step 6: Implement the memory store without changing dispatch yet**

Use one `parking_lot::Mutex` around:

```rust
struct MemoryState {
    entries: LruCache<String, Arc<StoredSemanticEntry>>,
}
```

Define the shared clock seam in `store.rs`. Production constructors use
`SystemTime`. A test-only
`MemorySemanticCacheStore` constructor accepts an
`Arc<dyn SemanticClock>` controlled by the test.

The entry key comes only from `SemanticEntryKeys.entry_key`. Lookup removes
expired entries, filters by exact `SemanticNamespace`, and feeds an iterator
over every live same-namespace entry directly into `select_exact_hit`. It does
not use `bucket_indexes` and does not allocate an O(n) candidate vector. If a
hit wins, rebuild its generated entry key and call `LruCache::get` to refresh
recency before returning it.

Store statistics use relaxed atomics. `stats()` returns a snapshot, not
references to atomics. Memory removes expired entries before reporting its
live `local_entries`; Redis and mesh report `None` because a process cannot
claim a cheap global count. `Debug` implementations show backend, counts,
and bounds only.
`record_purge` increments `purge_errors` when a report is incomplete and
always adds the successfully removed backend-record count.

A memory purge always reports one attempted local store, zero failed nodes,
and `complete: true`.

Keep the current `EmbeddingCache` fields and dispatcher-facing sync methods
unchanged in this task. Task 7 switches orchestration to the new store after
all backends can satisfy the contract, which keeps every intermediate commit
buildable.

- [ ] **Step 7: Run and commit the store foundation**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache::store) | test(semantic_cache::memory) | test(semantic_cache::wire)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo check --locked -p sbproxy-ai -p sbproxy-mesh
git add Cargo.toml Cargo.lock crates/sbproxy-ai/Cargo.toml \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/semantic_cache/store.rs \
  crates/sbproxy-ai/src/semantic_cache/memory.rs \
  crates/sbproxy-ai/src/semantic_cache/wire.rs \
  crates/sbproxy-ai/src/lib.rs crates/sbproxy-mesh/Cargo.toml
git commit -m "feat(ai): define semantic cache stores"
```

Expected: the common memory contract, compatibility scan, LRU, wire bounds,
namespace isolation, and exact collision reranking pass.

### Task 4: Implement Redis Payloads and Bounded Atomic LSH Indexes

**Files:**
- Create: `crates/sbproxy-core/src/semantic_cache_runtime.rs`
- Create: `crates/sbproxy-core/src/semantic_cache_runtime/redis.rs`
- Modify: `crates/sbproxy-core/src/lib.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes:
  `sbproxy_platform::storage::{AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore}`,
  `KVStore::validated_redis_connection`,
  `AsyncRedisKVStore::evalsha_with_reload`,
  `AsyncRedisKVStore::scan_page`, and `SemanticCacheStore`.
- Produces:

```rust
pub(crate) struct RedisSemanticCacheStore {
    redis: Arc<AsyncRedisKVStore>,
    stats: SemanticStoreCounters,
}

impl RedisSemanticCacheStore {
    pub(crate) fn from_l2_store(
        l2_store: Option<&dyn sbproxy_platform::storage::KVStore>,
    ) -> anyhow::Result<Arc<Self>>;

    #[cfg(test)]
    fn from_async_store(redis: Arc<AsyncRedisKVStore>) -> Arc<Self>;
}
```

- Produces two fixed Lua scripts:

```text
SEMANTIC_INDEX_PUT
  KEYS[1] = one bucket manifest key
  ARGV[1] = safe 64-hex entry digest
  ARGV[2] = maximum members
  ARGV[3] = TTL seconds
  LREM duplicate, LPUSH member, LTRIM bound, EXPIRE manifest
  return a flat string-compatible array

SEMANTIC_INDEX_READ
  KEYS[1] = one bucket manifest key
  ARGV[1] = maximum members
  LRANGE 0 through maximum minus one
  return only safe entry digests
```

- [ ] **Step 1: Write failing constructor and validation tests**

Create `crates/sbproxy-core/src/semantic_cache_runtime/` before adding the
module and its tests.

Add tests in `semantic_cache_runtime/redis.rs`:

```text
redis_backend_requires_proxy_l2_cache_settings
redis_backend_rejects_a_non_redis_l2_driver
redis_backend_reuses_the_validated_connection_snapshot
constructor_does_not_open_a_socket
redis_errors_never_render_the_dsn_username_password_host_or_key
```

Use the same validated-connection pattern as
`compression_runtime::redis_dependency`:

```rust
let connection = l2_store
    .and_then(KVStore::validated_redis_connection)
    .ok_or_else(|| anyhow::anyhow!(
        "semantic_cache.backend redis requires proxy.l2_cache_settings.driver redis"
    ))?;
let redis = AsyncRedisKVStore::new(AsyncRedisConfig::from_connection(connection));
```

Do not accept a semantic-cache DSN or silently fall back to memory when the
operator explicitly selected Redis.

- [ ] **Step 2: Write failing deterministic RESP contracts**

Use a local Tokio RESP fixture that handles Redis client setup, `SCRIPT LOAD`,
`EVALSHA`, `SET EX`, `GET`, `DEL`, and bounded `SCAN`. Capture commands
without including values in panic output.

Add tests:

```text
redis_put_writes_payload_before_any_bucket_index
redis_index_put_uses_lrem_lpush_ltrim_and_expire
redis_candidate_read_never_requests_more_than_the_configured_bound
redis_candidate_read_deduplicates_ids_across_tables
redis_candidate_read_fetches_each_payload_at_most_once
redis_payload_fetch_concurrency_never_exceeds_eight
redis_payload_error_discards_a_partial_exact_hit
dangling_index_member_is_a_safe_miss
payload_without_index_is_unreachable_and_safe
partial_index_write_returns_an_error_but_cannot_create_a_false_hit
redis_connection_failure_is_returned_without_sensitive_context
redis_health_reports_unavailable_after_a_sanitized_get_failure
redis_purge_reports_successful_deletes_before_a_later_failure
```

The fixture may emulate script results for ordinary unit tests. Task 4 Step 3
adds real Redis proof of Lua behavior.

- [ ] **Step 3: Write failing disposable-Redis Lua tests**

Copy only the disposable-process test pattern from the current OSS
`AsyncRedisKVStore` tests, not historical semantic-cache code. Start
`redis-server` on an ephemeral loopback port with persistence disabled.

Add a private core-local store-contract harness under
`semantic_cache_runtime::tests` with the same assertions listed in Task 3.
It accepts a store plus a backend-specific async expiry callback. This keeps
test support out of the public `sbproxy-ai` API. The Redis case uses a
one-second TTL and a bounded poll loop; it never sleeps without an outer
timeout.

Add ignored tests named:

```text
live_redis_semantic_store_contract
live_redis_semantic_index_is_bounded_and_deduplicated
live_redis_semantic_payload_and_index_expire
live_redis_semantic_script_recovers_after_script_flush
live_redis_semantic_origin_purge_removes_payloads_and_indexes
live_redis_semantic_tenant_namespaces_do_not_cross
```

The first test performs more than `candidates_per_bucket` inserts into one
forced-collision bucket and proves `LRANGE` never returns more than the bound.
The NOSCRIPT case invokes `SCRIPT FLUSH` between writes and proves
`evalsha_with_reload` reloads the script.

- [ ] **Step 4: Run the Redis tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_cache_runtime::redis) and not test(live_redis_)'
redis-server --version
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo test --locked -p sbproxy-core --lib \
  'semantic_cache_runtime::redis::tests::live_redis_semantic_' -- \
  --ignored --test-threads=1
```

Expected: compile failures for `RedisSemanticCacheStore`.

- [ ] **Step 5: Implement payload-first Redis writes**

For one logical write:

1. Encode and `SET EX` the payload under `keys.entry_key`.
2. For each table, invoke `SEMANTIC_INDEX_PUT` with the fixed manifest key,
   safe entry digest, candidate bound, and TTL.
3. Stop and return a sanitized error if an index operation fails.

The payload-first order means a crash can leave an unreachable payload but
cannot leave an index pointing at a response that was never validated and
stored.

Use
`futures::stream::iter(index_operations.into_iter()).buffer_unordered(configured_tables)`
for independent index operations. The table count is bounded to 16. Never
spawn detached tasks and never report a write as successful before all
selected indexes acknowledge.

- [ ] **Step 6: Implement bounded candidate reads**

Read each table manifest through `SEMANTIC_INDEX_READ`, validate every result
as exactly 64 lowercase hex characters, deduplicate IDs in deterministic
lexicographic order, and cap the total at:

```rust
usize::from(lsh.tables)
    .saturating_mul(lsh.candidates_per_bucket)
```

Issue manifest reads with at most `lsh.tables` operations in flight, which is
already capped at 16. Issue payload GETs with a separate fixed concurrency cap
of 8 so a worst-case 4,096-candidate configuration cannot enqueue unbounded
Redis work or retain every maximum-size response at once.

Parse each retained ID into a 32-byte prompt digest and rebuild its payload
key only through `semantic_entry_key`. Fetch payload keys through
`AsyncKVStore::get` with bounded concurrency. Decode each payload through
`wire::decode_entry`. Missing, expired, corrupt, wrong-version, and
wrong-namespace payloads are rejected independently so one bad value cannot
fail the complete lookup.

A Redis command or transport error while reading any manifest or payload
fails that store lookup with the closed error. Drain or cancel the bounded
stream, discard any partial exact winner, and let `EmbeddingCache` turn the
operation into one observable miss.

Feed each decoded result into one `SemanticExactSelector` as the bounded
stream yields it, then finish the selector after all retained IDs resolve.
Do not collect decoded entries. Set `SemanticStoreLookup.truncated` when a
manifest returned the requested limit, because more candidates may exist
behind the bound.
The orchestrator already validates the query before calling a store. If the
shared selector nevertheless returns `SemanticLookupError::InvalidEmbedding`,
map that impossible store-side invariant to the closed
`SemanticStoreError::InvalidState`; never attach the vector or backend error.

- [ ] **Step 7: Implement Redis health and generated-prefix purge**

Health performs a `GET` on a fixed semantic-health probe key. Any successful
Redis reply is healthy, whether the key is absent or an operator happened to
create it. A sanitized connection or command error is unavailable. Do not
write a health key and do not expose the Redis address.

Start from the shared literal prefix helper. Redis builds only these patterns:

```text
sbproxy:semcache:v2:*
sbproxy:semcache:v2:o:<origin hex>:*
sbproxy:semcache:v2:o:<origin hex>:s:<scope hex>:c:<compat hex>:*
one exact generated entry key
```

Use `scan_page(cursor, pattern, 250)` until the cursor returns zero. Delete
each returned key through `AsyncKVStore::delete` with concurrency capped at
32, finish that page, then request the next. Never use `KEYS`, never accept a
caller pattern, and never accumulate the whole keyspace.

Redis `SCAN` is not an atomic barrier against concurrent writes.
`SemanticPurgeReport.complete` means every observed scan page and delete
succeeded. It does not claim durable invalidation of a write racing the
purge. State this in the narrow admin reference in Task 10.

A successful Redis purge reports `nodes_attempted: 1` and `nodes_failed: 0`.
If a SCAN or delete fails after earlier deletes succeeded, return
`Ok(SemanticPurgeReport)` with the successful `removed` count,
`nodes_attempted: 1`, `nodes_failed: 1`, and `complete: false`. Finish the
already-started bounded delete futures but do not claim unvisited pages.
Reserve `Err(SemanticStoreError)` for an invalid typed scope or internal
invariant before a meaningful report can be formed. Task 8 still catches
that exceptional case, records one failed attempt, and continues purging
other unique stores.

- [ ] **Step 8: Add the live Redis test to the existing CI lane**

Append to the current `Redis live state` command block:

```bash
cargo test -p sbproxy-core --locked --lib \
  'semantic_cache_runtime::redis::tests::live_redis_semantic_' -- \
  --ignored --test-threads=1
```

Do not create another shared Redis service. Every semantic test owns its
ephemeral process and terminates it in `Drop`.

- [ ] **Step 9: Run and commit Redis**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_cache_runtime::redis) and not test(live_redis_)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo test --locked -p sbproxy-core --lib \
  'semantic_cache_runtime::redis::tests::live_redis_semantic_' -- \
  --ignored --test-threads=1
git add crates/sbproxy-core/src/lib.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/redis.rs \
  .github/workflows/ci.yml
git commit -m "feat(core): add Redis semantic cache store"
```

Expected: constructor, command shape, atomic bound, TTL, NOSCRIPT recovery,
partial-write safety, namespace isolation, health, and generated-prefix purge
tests pass.

### Task 5: Add a Bounded Routed-Prefix Snapshot to the OSS Mesh

**Files:**
- Modify: `crates/sbproxy-mesh/src/state/distributed_cache.rs`
- Modify: `crates/sbproxy-mesh/src/transport/frame.rs`
- Modify: `crates/sbproxy-mesh/src/transport/client.rs`
- Modify: `crates/sbproxy-mesh/src/transport/server.rs`

**Interfaces:**
- Consumes:
  `DistributedCache::snapshot_prefix_local`,
  `DistributedCache::responsible_node`,
  `TransportClientPool`, `PeerClient`, and existing postcard framing.
- Produces new variants appended at the end:

```rust
pub enum CacheOp {
    // Keep every current variant in its current order.
    SnapshotPrefix {
        prefix: String,
        maximum: u32,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CacheSnapshot {
    pub entries: Vec<(String, Bytes)>,
    pub truncated: bool,
}

pub enum CacheResult {
    // Keep every current variant in its current order.
    Snapshot(CacheSnapshot),
}

pub const MAX_ROUTED_SNAPSHOT_PREFIX_BYTES: usize = 1_024;
pub const MAX_ROUTED_SNAPSHOT_BYTES: usize = 1024 * 1024;
```

- Produces:

```rust
impl PeerClient {
    pub async fn snapshot_prefix(
        &self,
        prefix: String,
        maximum: u32,
    ) -> anyhow::Result<CacheSnapshot>;
}

impl DistributedCache<Bytes> {
    pub async fn put_routed_by(
        &self,
        routing_key: &str,
        key: &str,
        value: Bytes,
        ttl_secs: u64,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()>;

    pub async fn snapshot_prefix_routed(
        &self,
        routing_key: &str,
        prefix: &str,
        maximum: usize,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<LocalCacheSnapshot<Bytes>>;
}
```

- [ ] **Step 1: Write failing frame round-trip and bounds tests**

Append the new variants rather than inserting them. Add tests:

```text
request_wire_roundtrip_snapshot_prefix
response_wire_roundtrip_snapshot
snapshot_prefix_zero_limit_is_rejected
snapshot_prefix_above_4096_is_rejected
snapshot_prefix_empty_prefix_is_rejected
snapshot_prefix_above_1024_bytes_is_rejected
snapshot_local_stops_before_cloning_more_than_one_mib
snapshot_response_above_the_frame_cap_is_rejected
snapshot_debug_reports_only_count_bytes_and_truncated
```

The request carries only prefix and maximum. It never carries a routing key
because the client selects the owner before sending.

- [ ] **Step 2: Write failing server and client tests**

Add:

```text
server_handles_snapshot_prefix_in_lexicographic_order
server_snapshot_prefix_omits_expired_entries
server_snapshot_prefix_sets_truncated
server_snapshot_prefix_rejects_invalid_limit_without_echoing_prefix
client_snapshot_prefix_maps_only_snapshot_result
client_snapshot_prefix_rejects_an_unexpected_result
snapshot_prefix_uses_the_closed_transport_operation_label
```

The server calls only a new bounded local helper:

```rust
cache.snapshot_prefix_local_bounded(
    &prefix,
    maximum as usize,
    MAX_ROUTED_SNAPSHOT_BYTES,
)
```

Implement the helper only for `DistributedCache<Bytes>`. Retain at most
`maximum + 1` borrowed candidates in a lexicographic `BTreeMap`, then check
`key.len() + value.len()` with checked arithmetic before cloning each output.
Mark the page truncated when the next entry would cross either bound. A first
oversized entry produces an empty truncated page. Never call the existing
entry-count-only helper after values have been cloned. The server must not
recurse into routed methods. Preserve the current behavior that removes
expired local entries before selecting candidates.

- [ ] **Step 3: Write failing routed ownership tests**

Use two `DistributedCache<Bytes>` instances with the same two-node ring and
two `TransportServer` fixtures. Find a deterministic routing key owned by the
remote node and assert:

```text
put_routed_by stores the actual key on the routing key owner
snapshot_prefix_routed reads the remote owner
snapshot_prefix_routed reads locally when this node owns the routing key
snapshot_prefix_routed returns an error for a missing owner address
snapshot_prefix_routed returns an error for a transport failure
put_routed_by preserves TTL
```

Unlike `get_routed`, the snapshot method returns transport errors. The
semantic adapter decides that those errors become misses and records them.

- [ ] **Step 4: Run the focused mesh tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-mesh \
  -E 'test(snapshot_prefix) | test(put_routed_by)'
```

Expected: compile failure because the frame variants and routed methods do
not exist.

- [ ] **Step 5: Implement the generic OSS mesh operation**

`put_routed_by` resolves the owner from `routing_key` but stores `key`.
This lets every membership record beneath one LSH bucket live on the same
owner without changing the key used for purge.

`snapshot_prefix_routed`:

1. Validates `maximum` through the same `1..=4_096` bound as the local method
   and rejects an empty prefix or a prefix above 1,024 bytes.
2. Resolves the owner from `routing_key`.
3. Calls `snapshot_prefix_local_bounded` with the fixed 1 MiB aggregate cap
   if local.
4. Resolves the peer address and uses `pool.try_client_for_node`.
5. Calls `PeerClient::snapshot_prefix`.
6. Revalidates entry count and aggregate key-plus-value bytes before mapping
   the wire snapshot back to `LocalCacheSnapshot<Bytes>`.

The transport server returns a fixed non-secret error string for invalid
limits. It does not include the prefix or any entry value in logs or errors.
Add `snapshot_prefix` to the exhaustive `cache_op_label` match used by
transport metrics. Give `CacheSnapshot` a redacted `Debug` implementation
that reports entry count, aggregate key-plus-value bytes, and `truncated`
only.

- [ ] **Step 6: Record the wire requirement enforced by Task 6**

Update the existing wire-format rustdoc in `frame.rs`:

```text
SnapshotPrefix is appended after SyncDigest. Postcard enum variants are not
self-describing. A caller must verify the authenticated
semantic_cache_snapshot_v1 fleet capability before sending this operation.
```

Existing mesh operations keep their discriminants, so operators may roll the
binary while semantic caching remains disabled. Task 6 adds the enforceable
capability declaration and live-member proof by reusing authenticated typed
cluster state. Do not rely on documentation or a binary-version string as the
gate.

- [ ] **Step 7: Run and commit the OSS mesh capability**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-mesh \
  -E 'test(snapshot_prefix) | test(put_routed_by)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo check --locked -p sbproxy-mesh
git add crates/sbproxy-mesh/src/state/distributed_cache.rs \
  crates/sbproxy-mesh/src/transport/frame.rs \
  crates/sbproxy-mesh/src/transport/client.rs \
  crates/sbproxy-mesh/src/transport/server.rs
git commit -m "feat(mesh): add bounded routed cache snapshots"
```

Expected: frame, cap, server, client, local owner, remote owner, TTL, and
transport failure tests pass.

### Task 6: Implement the Thin Mesh Semantic Store and Two-Node Contract

**Files:**
- Create: `crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime.rs`
- Modify: `crates/sbproxy-core/src/key_capability.rs`
- Modify: `crates/sbproxy-core/src/cluster.rs`
- Modify: `crates/sbproxy-core/src/lib.rs`

**Interfaces:**
- Consumes:
  `ClusterHandle::{membership,read_state}`,
  the current `key_capability` typed-state namespace, announcement schema,
  TTL, and process announcer,
  `MeshNode::distributed_cache`,
  `MeshNode::transport_pool`,
  `MeshNode::peer_addr_lookup`,
  `MeshNode::isolation_observer`,
  `MeshNode::has_transport`,
  `DistributedCache::{responsible_node,get_local,put_routed_with_ttl,put_routed_by,snapshot_prefix_routed}`,
  `DistributedCache::{member_nodes,local_node_id,purge_prefix_local}`, and
  `PeerClient::{get,purge_prefix}`.
- Produces:

```rust
pub const CAP_SEMANTIC_CACHE_SNAPSHOT_V1: &str =
    "semantic_cache_snapshot_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SemanticMeshCapabilityError {
    #[error("mesh semantic cache capability is missing")]
    Missing,
    #[error("mesh semantic cache capability is unknown")]
    Unknown,
    #[error("mesh semantic cache membership changed after verification")]
    MembershipChanged,
}

pub(crate) struct SemanticMeshCapabilityEvidence {
    live_members: BTreeMap<String, u64>,
}

pub(crate) async fn require_semantic_mesh_capability(
    cluster: &ClusterHandle,
) -> Result<SemanticMeshCapabilityEvidence, SemanticMeshCapabilityError>;

type PeerAddr =
    Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub(crate) struct MeshSemanticCacheStore {
    cluster: ClusterHandle,
    capability: SemanticMeshCapabilityEvidence,
    cache: Arc<DistributedCache<Bytes>>,
    pool: Arc<TransportClientPool>,
    peer_addr: PeerAddr,
    isolation: Option<Arc<IsolationObserver>>,
    stats: SemanticStoreCounters,
}

impl MeshSemanticCacheStore {
    pub(crate) fn from_cluster(
        cluster: &ClusterHandle,
        capability: SemanticMeshCapabilityEvidence,
    ) -> anyhow::Result<Arc<Self>>;

    #[cfg(test)]
    fn from_parts(
        cluster: ClusterHandle,
        capability: SemanticMeshCapabilityEvidence,
        cache: Arc<DistributedCache<Bytes>>,
        pool: Arc<TransportClientPool>,
        peer_addr: PeerAddr,
        isolation: Option<Arc<IsolationObserver>>,
    ) -> Arc<Self>;
}
```

- [ ] **Step 1: Write failing one-node contract tests**

Run the private core-local store contract introduced in Task 4 against a
one-node mesh adapter and add:

```text
mesh_constructor_requires_a_bound_transport_for_distributed_mode
one_node_mesh_put_and_candidate_read_round_trip
one_node_mesh_ttl_expires_payload_and_membership
mesh_candidate_read_deduplicates_entry_ids_across_tables
mesh_payload_fetch_concurrency_never_exceeds_eight
mesh_corrupt_payload_is_rejected_without_failing_other_candidates
mesh_payload_transport_error_discards_a_partial_exact_hit
mesh_health_reports_degraded_while_isolated
mesh_lookup_while_isolated_returns_a_miss
mesh_write_while_isolated_returns_a_sanitized_error
mesh_purge_while_isolated_never_reports_complete
current_binary_advertises_semantic_cache_snapshot_v1
metadata_and_typed_announcement_use_the_same_capability_set
capability_error_display_never_contains_node_id_address_or_state_payload
```

Do not fall back to a local write while isolated. Such a write could land on
the wrong owner and later appear as an ambiguous duplicate.

- [ ] **Step 2: Write the required two-node tests**

Create two real `TransportServer` fixtures, two caches with identical
two-node rings, and node-aware address maps. Use deterministic key search to
place payload and index ownership on both nodes as needed.

Drive every behavioral assertion through the public
`SemanticCacheStore::{put,lookup,purge}` contract used by the proxy. Inspect
local shards only to prove fixture placement or final cleanup, never as the
operation under test. Task 8 then adds the narrow two-process HTTP proof that
compiled dispatch reaches this same contract.

Add tests with these exact outcomes:

```text
two_node_old_binary_without_snapshot_capability_is_rejected_before_store_construction
two_node_missing_or_expired_capability_is_unknown_and_rejected
two_node_capability_publisher_mismatch_is_unknown_and_rejected
two_node_homogeneous_capability_is_accepted_before_store_construction
two_node_membership_or_incarnation_change_blocks_snapshot_before_transport
two_node_remote_semantic_hit_uses_the_common_cache_contract
two_node_remote_entry_expires_on_the_owner
two_node_owner_failure_returns_a_miss
two_node_membership_handoff_rewarms_the_new_owner
two_node_tenant_isolation_never_returns_a_foreign_candidate
two_node_cluster_purge_clears_every_shard
two_node_partial_purge_reports_the_failed_peer
```

The handoff test performs:

1. Store an entry whose payload owner is node B.
2. Prove node A reads it remotely.
3. Stop node B and prove node A observes a miss.
4. Remove node B from node A's ring.
5. Prove the old store rejects the changed membership before transport.
6. Publish and verify the new one-node capability view and construct the
   replacement store, matching a successful pipeline reload.
7. Write the same logical entry through node A.
8. Prove the next lookup hits node A.

Do not assert that an ephemeral cached value survives owner loss. That would
require replicated cache payloads, which the approved design does not
promise.

- [ ] **Step 3: Run the mesh semantic tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(key_capability) | test(semantic_cache_runtime::mesh)'
```

Expected: compile failure because the semantic mesh capability and
`MeshSemanticCacheStore` are missing.

- [ ] **Step 4: Advertise and verify the snapshot capability**

Add `CAP_SEMANTIC_CACHE_SNAPSHOT_V1` to the deterministic capability list in
`key_capability::local_capabilities()` and to the existing
`CapabilityAnnouncement` published by `run_capability_announcer`. Keep
`credential_binding` unchanged. Do not add capability data to the postcard
gossip or cache-operation enums; an old binary must remain able to participate
by publishing no declaration, which is the fail-closed signal.

Use one sorted private `local_capability_names()` source for both the
comma-separated metadata returned by `local_capabilities()` and
`CapabilityAnnouncement.caps`. Add a test that the two projections contain
the same exact set, so later capabilities cannot be advertised on only one
path.

Move the publication generation counter behind
`key_capability::announce_local_capabilities()` as one process-wide
`AtomicU64`; callers no longer supply a generation. The periodic announcer
and the semantic preflight both use that function, so an immediate preflight
publication cannot race the background loop with two different payloads at
one generation. Preserve the current stale-generation and TTL behavior.

`require_semantic_mesh_capability` reuses the current
`key_capability::{CAPABILITY_NAMESPACE,CAPABILITY_SCHEMA_VERSION,
CapabilityAnnouncement}` records. Take one `ClusterHandle::membership()`
snapshot. Ignore `Dead` entries. Reject the snapshot as `Unknown` if it is
empty or contains `Suspect` or `Unreachable` entries. For every `Alive`
member, read the typed capability record keyed by that exact node ID. Accept
only a current `Present` record whose `publisher_node_id` matches the member.
When `authenticated_identity` is present, require its node ID to match too.
`ClusterHandle::read_state` already rejects a missing or invalid identity
proof when an enrolled identity authenticator is configured; preserve that
check rather than adding a parallel verifier. Require the exact capability
list to contain
`semantic_cache_snapshot_v1`. A present declaration for a different
capability, an incompatible schema, missing or expired state, malformed state,
transport failure, or publisher mismatch rejects the proof. Use `Missing`
only when a valid declaration omits this capability; use `Unknown` for every
case where the member's support cannot be proven.

On success, return private evidence containing the exact sorted live
`node_id -> incarnation` map. It has no `Debug`, serialization, admin, or
logging surface. Error display uses only the three closed strings above and
never includes node IDs, addresses, capability payloads, or transport errors.

`MeshSemanticCacheStore::from_cluster` requires that evidence and rechecks the
current membership before extracting the existing mesh node and transport.
Before every lookup, write, and purge, compare the current non-dead
membership and incarnation map with the verified evidence. Any added,
restarted, suspect, unreachable, or removed member returns
`MembershipChanged` before a `SnapshotPrefix` operation or semantic write is
sent. This intentionally requires a successful pipeline reload to bind a new
homogeneous membership view. It prevents a newly joined old binary, including
one that reused an earlier node ID with a new incarnation, from receiving the
appended postcard variant through an already-running pipeline.

Task 8 performs the initial async proof through one
`crate::cluster::block_on_cluster` call that first publishes this node's
complete capability list, then awaits
`require_semantic_mesh_capability(&handle)`. It does this before constructing
the shared mesh store or installing any active mesh binding.
`block_on_cluster` already runs the future on the dedicated cluster runtime
and is safe from synchronous startup and reload call sites. A mixed or unknown
fleet rejects the candidate pipeline and leaves the prior pipeline live.

- [ ] **Step 5: Implement payload and membership storage**

Store one encoded payload through:

```rust
cache
    .put_routed_with_ttl(
        &write.keys.entry_key,
        payload,
        write.ttl_secs,
        pool.as_ref(),
        peer_addr.as_ref(),
    )
    .await?;
```

For each bucket, store one small membership key through `put_routed_by`.
The key is `member_prefix` plus the safe 64-hex prompt digest and its value is
the fixed one-byte marker `1`. Route by `SemanticBucketIndex.routing_key`.
Candidate lookup parses the digest only from the generated key suffix and
rebuilds the payload key through `semantic_entry_key`; it never trusts a
value-supplied key. Because the suffix is a SHA-256 prompt digest, a
lexicographically bounded full bucket produces a deterministic sample rather
than favoring caller-controlled prompt text.

Candidate lookup snapshots each bucket prefix at the bucket owner, validates
membership suffixes as prompt digests, deduplicates them, and performs bounded
concurrent strict payload reads. Add a private adapter helper that resolves
`cache.responsible_node(key)`, calls `cache.get_local(key)` for a local or
empty-ring owner, otherwise resolves the peer address, obtains an
authenticated client with `pool.try_client_for_node`, and awaits
`PeerClient::get`. It returns `Ok(None)` only for a clean absent payload and
returns a sanitized error for missing owner identity, missing address,
untrusted node ID, or peer transport failure. Do not call the current
`DistributedCache::get_routed` here because that compatibility API
intentionally collapses transport failures into `None`. Decode and reject
payload values independently.

Use at most 16 concurrent bucket snapshots and 8 concurrent payload reads,
matching the Redis fan-out bounds.

Feed decoded payloads into one `SemanticExactSelector` as the bounded stream
yields them and return its exact result. Do not collect decoded entries. LSH
membership alone never becomes a cache hit. Mark the lookup truncated when
any bucket snapshot reports truncation.
Map the selector's impossible invalid-query result to the same closed
`SemanticStoreError::InvalidState` used by Redis.

If any bucket snapshot transport fails, increment the store error counter and
return an error. `EmbeddingCache` converts it to a miss in Task 7. Do not use
candidates from only the reachable subset because that makes hit behavior
depend on which owner failed during the lookup.

Apply the same rule to routed payload reads. A missing payload is a safe
dangling-membership rejection, but a transport error discards any partial
winner and returns the closed store error.

- [ ] **Step 6: Implement cluster-wide purge**

Build the generated prefix from `SemanticPurgeScope`. Purge locally first,
then enumerate `cache.member_nodes()`, excluding `cache.local_node_id()`.
Resolve each node through `peer_addr`, obtain a node-aware client through
`pool.try_client_for_node`, and call `purge_prefix`.

Run peer purges concurrently with a maximum of 16 in flight. Sum successful
counts and retain failed-node count. Return:

```rust
SemanticPurgeReport {
    removed,
    nodes_attempted: 1 + peers_attempted,
    nodes_failed,
    complete: nodes_failed == 0,
}
```

Missing peer identity, address, transport, or reply is a failed node, not a
successful zero removal.

The report covers the local shard plus the membership snapshot visible when
purge starts. It cannot erase an offline node that has already been removed
from membership. Entries stranded there remain subject to TTL and must not be
described as durably revoked data.

If the isolation observer is isolated, purge may remove local and reachable
known-peer records but must force `complete: false` and at least one failed
attempt. It cannot claim the membership view was complete.

- [ ] **Step 7: Implement mesh health**

Return:

```text
healthy       transport exists and isolation observer is not isolated
degraded      isolation observer reports isolated
unavailable   transport is absent, capability is unverified, or membership changed
```

The reason is one fixed closed value such as `isolated` or
`transport_unavailable`, `capability_unverified`, or `membership_changed`.
Do not include node IDs, addresses, capability payloads, or transport errors.

- [ ] **Step 8: Run and commit mesh integration**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(key_capability) | test(semantic_cache_runtime::mesh)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo check --locked -p sbproxy-core -p sbproxy-mesh
git add crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs \
  crates/sbproxy-core/src/key_capability.rs \
  crates/sbproxy-core/src/cluster.rs \
  crates/sbproxy-core/src/lib.rs
git commit -m "feat(core): add mesh semantic cache store"
```

Expected: capability advertisement, mixed and unknown rejection, homogeneous
acceptance, membership-change fencing, one-node contract, real two-node
remote hit, TTL, owner failure, rewarm handoff, isolation, tenant boundary,
complete purge, and partial purge tests pass.

### Task 7: Move Canonical Cache Orchestration onto the Async Store

**Files:**
- Modify: `crates/sbproxy-ai/src/semantic_cache.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache/store.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache/memory.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache/wire.rs`
- Modify: `crates/sbproxy-ai/src/lib.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime/redis.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs`
- Modify: `crates/sbproxy-core/src/server.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/src/server/ai_support.rs`
- Modify: `e2e/tests/semantic_cache_e2e.rs`

**Interfaces:**
- Consumes: the current embedding-source calls, `SemanticCacheStore`,
  `RandomProjectionLsh`, safe namespaces, exact reranking, and the current
  buffered response relay.
- Produces:

```rust
pub struct SemanticLookupRequest<'a> {
    pub namespace: SemanticNamespace,
    pub prompt: &'a str,
    pub embedding: &'a [f32],
}

pub enum SemanticLookupOutcome {
    Hit(EmbeddingHit),
    Miss(SemanticWriteToken),
}

pub struct SemanticWriteToken {
    namespace: SemanticNamespace,
    prompt_digest: [u8; 32],
    embedding: Vec<f32>,
    keys: SemanticEntryKeys,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EmbeddingCacheStats {
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
    pub lookup_errors: u64,
    pub writes: u64,
    pub write_errors: u64,
    pub expired: u64,
    pub incompatible: u64,
    pub below_threshold: u64,
}

impl EmbeddingCache {
    pub fn from_config(cfg: &EmbeddingCacheConfig) -> Option<Self>;

    pub fn with_store(
        cfg: &EmbeddingCacheConfig,
        store: Arc<dyn SemanticCacheStore>,
    ) -> anyhow::Result<Option<Self>>;

    pub async fn lookup(
        &self,
        request: SemanticLookupRequest<'_>,
    ) -> Result<SemanticLookupOutcome, SemanticLookupError>;

    pub async fn store(
        &self,
        token: SemanticWriteToken,
        response: CachedHttpResponse,
    ) -> Result<(), SemanticStoreError>;

    pub async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError>;

    pub async fn health(&self) -> SemanticStoreHealth;

    pub fn backend(&self) -> SemanticCacheBackend;
    pub fn configuration_digest(&self) -> &[u8; 32];
    pub fn stats(&self) -> EmbeddingCacheStats;
    pub fn store_stats(&self) -> SemanticStoreStats;
}
```

- Changes:

```rust
type PendingEmbedMiss = (
    Arc<sbproxy_ai::EmbeddingCache>,
    sbproxy_ai::SemanticWriteToken,
);
```

- [ ] **Step 1: Write failing cache-orchestration tests**

Replace direct sync lookup tests with async tests over an injected memory
store:

```text
lookup_miss_returns_a_write_token
store_with_the_token_then_lookup_hits
embedding_hit_reuses_the_stored_response_arc_without_copying_the_body
exact_vector_hits
near_duplicate_hits
dissimilar_vector_misses_after_exact_rerank
same_bucket_collision_below_threshold_misses
best_exact_score_wins_across_multiple_tables
equal_score_tie_breaks_by_prompt_digest
expired_candidate_misses
wrong_namespace_candidate_is_rejected
wrong_dimension_candidate_is_rejected
explicit_max_response_bytes_rejects_an_oversized_memory_response
distributed_wire_rejects_a_response_above_7_mib
store_error_is_returned_without_losing_the_client_response
recent_decisions_never_retain_scope_namespace_prompt_or_backend_error
streaming_request_skips_embedding_lookup_and_store
slow_provider_time_does_not_reduce_ttl_before_store
with_store_rejects_a_backend_mismatch
```

Keep the existing memory LRU, threshold, source parsing, OpenAI headers,
quota, embedding-source, provider allowlist and blocklist, standalone OpenAI
policy, and compression-bypass tests. Update only their construction helper.

- [ ] **Step 2: Write failing safe-header tests**

Add in `ai_support.rs`:

```rust
pub(super) fn semantic_cache_response_headers(
    headers: &[(String, String)],
) -> Vec<(String, String)>;
```

Prove it retains only this closed set:

```text
content-type
content-language
```

Prove it drops:

```text
connection
transfer-encoding
content-length
set-cookie
set-cookie2
www-authenticate
proxy-authenticate
authentication-info
retry-after
date
age
server
vary
etag
all x-ratelimit and ratelimit fields
all x-request-id, traceparent, tracestate, baggage, and server-timing fields
all unrecognized response headers
```

Compare header names case-insensitively and write the retained canonical
lowercase name. A cached response must not replay a prior caller's cookie,
challenge, request ID, quota state, trace correlation, or content encoding
that may no longer match buffered response bytes.

Validate retained names and values through the HTTP header parsers, cap them
through the wire constants, deduplicate them, and sort them by canonical
name. Drop an invalid value containing control bytes. Apply this helper both
before storage and again to a decoded hit, so a tampered distributed value
cannot turn an allowlisted name into an invalid response header.

Replay through `send_response_with_extras` rather than hand-building a
different response path. Use the stored content type, stored content
language, the current request's `public_route_headers(ctx)`, and a fresh
`x-semcache: HIT`. Default a missing or rejected content type to
`application/json` and recompute content length. Never store or replay an
earlier request's public route headers. Add a test that a changed
logical-model route header comes from the current request while the response
body comes from the cache.

- [ ] **Step 3: Write failing real proxy memory regressions**

Extend `semantic_cache_e2e.rs`:

```text
existing_config_without_backend_still_hits_memory
same_tenant_and_governed_key_can_hit
different_tenant_misses
different_governed_key_misses
different_system_message_misses
different_tool_definition_misses
different_requested_model_misses
different_inbound_surface_misses
different_semantic_configuration_misses_after_reload
different_static_action_policy_misses_after_reload
different_governed_policy_revision_misses
backend_lookup_failure_forwards_to_the_provider
cached_response_does_not_replay_cookie_request_id_or_rate_limit_headers
cached_response_rebuilds_current_public_route_headers
explicit_compression_selection_still_bypasses_semantic_cache
session_compression_runtime_still_bypasses_semantic_cache
streaming_request_never_calls_the_semantic_backend
```

Keep the existing paraphrase, unrelated prompt, and input-guardrail tests.
Keep the sidecar test focused on one near-duplicate hit.

- [ ] **Step 4: Run focused tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache) and not test(live_)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_cache_response_headers) | test(semantic_credential_identity)'
```

Expected: compile failures because `EmbeddingCache` still owns its private LRU
and sync API.

- [ ] **Step 5: Refactor `EmbeddingCache` into orchestration**

Replace its `entries` field with:

```rust
store: Arc<dyn SemanticCacheStore>,
lsh: RandomProjectionLsh,
clock: Arc<dyn SemanticClock>,
stats: EmbeddingCacheCounters,
```

In the same commit, change `CachedHttpResponse.body` from `Vec<u8>` to
`bytes::Bytes`. Update the borrowed wire encoder to use `body.as_ref()` and
convert the owned decoded wire body from `Vec<u8>` into `Bytes` without
copying. Keep `StoredSemanticEntry.response` as
`Arc<CachedHttpResponse>`. Memory hits clone that `Arc`; Redis and mesh create
one `Arc` after bounded wire decoding. The dispatcher then clones only the
`Bytes` handle when it builds a client response. This keeps every response
body behind one reference-counted allocation after admission and makes the
ownership test in Step 1 meaningful.

Update the common core store-contract fixtures and Redis and mesh adapter
fixtures in the same step. Prefer `fixture_body.into()` at construction
boundaries so the tests express byte ownership without another full copy.

Keep the existing source, provider, model, sidecar, inprocess, openai,
threshold, TTL, and recent-decision fields. Implement `from_config` as the
memory compatibility constructor:

```rust
if cfg.backend != SemanticCacheBackend::Memory {
    return None;
}
let store = Arc::new(MemorySemanticCacheStore::new(cfg.max_entries));
Self::with_store(cfg, store).ok().flatten()
```

`with_store` validates that `store.backend() == cfg.backend` before building
the cache. An explicit Redis or mesh selection must never run on a memory
adapter because a caller used the wrong constructor.

Retain Task 1's validated sidecar policy and hardened standalone OpenAI call
path unchanged during this refactor. Do not reintroduce a raw reqwest client,
redirect following, unpinned DNS, an uncapped response reader, or
value-revealing request errors.

Give `EmbeddingCache` a redacted `Debug` implementation that reports backend,
source kind, safe model identifier, tuning bounds, and counter snapshots only.
It must not format the store trait object, endpoints, local paths, API keys,
auth prefixes, static headers, entries, or recent identity.

Lookup:

1. Validates and normalizes the query vector.
2. Hashes the prompt with the fixed prompt domain.
3. Computes all LSH buckets and generated keys.
4. Calls `store.lookup` with the normalized vector and threshold.
5. Accepts only the store's exact hit result.
6. Returns a hit or a private write token.
7. Records one bounded recent decision without prompt or identity values.

Remove the current serialized `CacheDecision.scope` field. Recent decisions
retain no scope, namespace, prompt, key, model, origin, credential, response,
embedding, or backend error. Rename reason values to the closed set:

```text
hit
no_entry
expired
below_threshold
incompatible
backend_error
```

- [ ] **Step 6: Build the namespace at the request boundary**

In `handle_ai_proxy`, create one `SemanticPromptInput` after canonical request
translation, any RAG context injection, and the final input guardrail pass.
Use its `.text` only for semantic embedding and prompt-key derivation. Keep
the current full `extracted_prompt` value at every guardrail, classifier,
intent, trace, and policy call site. This ordering means retrieved context is
part of `request_context_digest` but the final user query remains the text
sent to the semantic embedding source.

After embedding succeeds, derive the namespace from:

```rust
// Inside:
// if let (Some(cache), Some(origin_idx)) =
//     (config.embedding_cache(), origin_idx) {
let compiled_origin = pipeline
    .config
    .origins
    .get(origin_idx)
    .ok_or_else(|| anyhow::anyhow!("semantic cache origin is unavailable"))?;
let static_policy_digest = semantic_static_action_policy_digest(
    compiled_origin,
    ctx.forward_rule_idx,
)?;
let response_policy_digest = semantic_response_policy_digest(
    &static_policy_digest,
    peer_policy_revision.as_str(),
    surface_label,
);
let credential_identity =
    semantic_credential_identity(session, &ctx.principal);

SemanticNamespaceInput {
    origin_route: compiled_origin.hostname.as_str(),
    request_host: ctx.hostname.as_str(),
    tenant_id: ctx.tenant_id.as_str(),
    credential_identity: credential_identity.as_str(),
    requested_model: model.as_str(),
    api_surface: surface_label,
    request_context_digest: &semantic_prompt.request_context_digest,
    embedding_identity: cache.embedding_identity(),
    embedding_dimensions: query_vec.len(),
    semantic_config_digest: cache.configuration_digest(),
    response_policy_digest: &response_policy_digest,
    schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
}
```

`origin_idx` is required once an AI action has been selected. Match it with
the cache as shown and skip semantic caching if it is absent.
If the static policy projection cannot be canonicalized, record a safe
identity error and continue uncached.

Keep the existing `compression_cache_bypass` gate around both lookup and
write-on-miss. Explicit compression selection, a runtime that requires
semantic bypass, or captured session compression state must not consult or
populate any semantic backend.

Move the existing `stream` request check before semantic lookup. A streaming
request skips embedding, lookup, and write entirely. Do not rely only on the
later response-store gate.

Hold the owned credential string and response-policy digest in local
variables before borrowing them. Never add the credential, policy revision,
canonical projection, or namespace inputs to tracing.

This per-request static digest calculation is temporary and applies only to
the memory compatibility path. Task 8 stores the same digest in each compiled
registry binding and removes the request-time canonicalization.

Use `Principal::api_key_id()` rather than raw authorization whenever it is
available. The authorization fallback is hashed before it reaches namespace
construction.

- [ ] **Step 7: Await lookup and fail open**

Replace:

```rust
cache.lookup(&query_vec, &cache_scope)
```

with:

```rust
match cache
    .lookup(SemanticLookupRequest {
        namespace,
        prompt: &semantic_prompt.text,
        embedding: &query_vec,
    })
    .await
{
    Ok(SemanticLookupOutcome::Hit(hit)) => {
        // Existing replay, savings, hit metrics, and return.
    }
    Ok(SemanticLookupOutcome::Miss(token)) => {
        embed_miss = Some((Arc::clone(cache), token));
    }
    Err(error) => {
        // Record backend error, log only backend plus safe error class,
        // and continue to ordinary provider routing.
    }
}
```

Do not include keys, namespace digests, embeddings, prompts, response bodies,
or Redis and mesh errors in the warning.

Retain the current provider allowlist and blocklist checks, quota-pool
reservation behavior, and standalone OpenAI embedding restriction before
lookup. Log an embedding failure only as the closed source label and a fixed
failure class. A request-client error may contain an endpoint, so do not log
its display text from this path.

- [ ] **Step 8: Await write-on-miss after output protection**

Keep the current status 200 gate and streaming bypass. Build
`CachedHttpResponse` only after output guardrails and response rewrapping.
Pass headers through `semantic_cache_response_headers` and clone the existing
`Bytes` handle into the response. Do not convert the buffered body back to a
`Vec<u8>`.

Await `cache.store(token, response)`. On error, increment write error metrics
and continue serving the already approved response. Do not fire and forget,
because a detached write could outlive its request-pinned pipeline and hide a
failed distributed write.

Take `stored_at_unix_ms` from the cache clock inside `store`, after the
provider response and output guardrails complete. Compute expiry from that
timestamp with checked arithmetic. Do not capture insertion time in the miss
token, because provider latency must not consume the entry TTL. The injected
clock constructor used by tests passes the same clock to the memory store and
the orchestrator.

If `max_response_bytes` is present, reject a larger body before calling any
store. If it is absent, the memory store keeps the current uncapped behavior.
Redis and mesh always pass through `encode_entry`, so their fixed 8 MiB wire
ceiling still applies when the optional operator cap is absent.

- [ ] **Step 9: Run and commit canonical async orchestration**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache) and not test(live_)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_cache_response_headers) | test(semantic_credential_identity)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo build --locked -p sbproxy
SBPROXY_E2E_BIN=/Users/rick/projects/soapbucket/sbproxy/target/debug/sbproxy \
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-e2e --test semantic_cache_e2e
git add crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/semantic_cache/store.rs \
  crates/sbproxy-ai/src/semantic_cache/memory.rs \
  crates/sbproxy-ai/src/semantic_cache/wire.rs \
  crates/sbproxy-ai/src/lib.rs crates/sbproxy-core/src/server.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/redis.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  crates/sbproxy-core/src/server/ai_support.rs \
  e2e/tests/semantic_cache_e2e.rs
git commit -m "feat(ai): run semantic cache through async stores"
```

Expected: the common memory path, full-scan compatibility, exact reranking,
request identity, safe headers, fail-open behavior, and real proxy tests pass.

### Task 8: Compile Per-Action Backends and Remove Dead Parallel Seams

**Files:**
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime/redis.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs`
- Modify: `crates/sbproxy-core/src/lib.rs`
- Modify: `crates/sbproxy-core/src/pipeline.rs`
- Modify: `crates/sbproxy-core/src/server.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/src/admin_cache.rs`
- Modify: `crates/sbproxy-core/src/admin_compression.rs`
- Modify: `crates/sbproxy-core/src/hooks.rs`
- Modify: `crates/sbproxy-core/tests/hooks.rs`
- Modify: `crates/sbproxy-ai/src/handler.rs`
- Modify: `crates/sbproxy-config/src/compiler.rs`
- Modify: `crates/sbproxy-config/src/types.rs`
- Create: `crates/sbproxy-core/tests/semantic_cache_runtime_registry.rs`
- Create: `e2e/tests/semantic_cache_distributed_e2e.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: compiled main actions, compiled forward-rule actions,
  `CompiledConfig.origins`, `CompiledConfig.server`,
  `CompiledConfig.l2_store`, `PipelineConstructionMode`, and the process-owned
  `ClusterHandle`.
- Produces:

```rust
#[derive(Default)]
pub struct SemanticCacheRuntimeRegistry {
    by_origin: Vec<SemanticCacheRuntimeSlot>,
    unique_stores: Vec<SemanticStoreRegistration>,
}

struct SemanticStoreRegistration {
    store: Arc<dyn sbproxy_ai::SemanticCacheStore>,
    origin_digests: BTreeSet<[u8; 32]>,
}

#[derive(Default)]
struct SemanticCacheRuntimeSlot {
    default: SemanticCacheBinding,
    forward_rules: Vec<SemanticCacheBinding>,
}

enum SemanticCacheBinding {
    NotConfigured,
    Disabled {
        backend: SemanticCacheBackend,
    },
    Inert {
        backend: SemanticCacheBackend,
        reason: &'static str,
    },
    Active {
        cache: Arc<sbproxy_ai::EmbeddingCache>,
        static_action_policy_digest: [u8; 32],
        store_id: usize,
    },
}

impl Default for SemanticCacheBinding {
    fn default() -> Self {
        Self::NotConfigured
    }
}

pub struct SemanticCacheRegistration<'a> {
    pub origin_idx: usize,
    pub forward_rule_idx: Option<usize>,
    pub configured: bool,
    pub enabled: bool,
    pub backend: Option<SemanticCacheBackend>,
    pub inert_reason: Option<&'static str>,
    pub cache: Option<&'a Arc<sbproxy_ai::EmbeddingCache>>,
    pub store_id: Option<usize>,
}

pub struct SemanticCacheSelection<'a> {
    pub cache: &'a Arc<sbproxy_ai::EmbeddingCache>,
    pub static_action_policy_digest: &'a [u8; 32],
}

impl SemanticCacheRuntimeRegistry {
    pub(crate) fn from_process(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn sbproxy_platform::storage::KVStore>,
        origins: &[sbproxy_config::CompiledOrigin],
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
    ) -> anyhow::Result<Self>;

    pub(crate) fn for_validation(
        server: &sbproxy_config::ProxyServerConfig,
        l2_store: Option<&dyn sbproxy_platform::storage::KVStore>,
        origins: &[sbproxy_config::CompiledOrigin],
        actions: &[sbproxy_modules::Action],
        forward_rules: &[Vec<CompiledForwardRule>],
    ) -> anyhow::Result<Self>;

    pub fn get(
        &self,
        origin_idx: usize,
        forward_rule_idx: Option<usize>,
    ) -> Option<SemanticCacheSelection<'_>>;

    pub fn registrations(
        &self,
    ) -> impl Iterator<Item = SemanticCacheRegistration<'_>>;

    pub async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> anyhow::Result<SemanticPurgeReport>;
}
```

- Adds:

```rust
pub struct CompiledPipeline {
    pub semantic_caches: SemanticCacheRuntimeRegistry,
}
```

- [ ] **Step 1: Write failing registry selection tests**

Compile one origin AI action and two inline forward-rule AI actions:

```rust
assert_eq!(
    registry.get(0, None).unwrap().cache.backend(),
    SemanticCacheBackend::Memory,
);
assert_eq!(
    registry.get(0, Some(0)).unwrap().cache.backend(),
    SemanticCacheBackend::Redis,
);
assert!(registry.get(0, Some(1)).is_none());
```

The last assertion is mandatory. A forward rule without `semantic_cache`
must not fall back to its origin cache, because it may have a different model,
guardrail, response shape, or credential policy.

Also test:

```text
non-AI action creates an empty slot
disabled semantic cache retains disabled status but has no runtime
inert missing-source config retains a fixed validation reason but has no runtime
memory backend needs no external dependency
Redis backend requires validated Redis L2 settings
mesh backend requires proxy.cluster in validation mode
mesh backend requires the installed distributed ClusterHandle at runtime
mesh backend rejects a local-only ClusterHandle
mesh_registry_rejects_two_node_mixed_version_before_binding
mesh_registry_rejects_missing_expired_suspect_or_unknown_capability
mesh_registry_accepts_two_node_homogeneous_capability_before_binding
mesh backend creates no store or active binding when capability preflight fails
validation constructs no Redis or mesh socket
runtime registry length matches actions and forward rules
main and forward bindings carry different static action-policy digests
one shared store records every origin digest that uses it
origin purge selects only stores registered for that origin
one shared Redis or mesh store is invoked once per purge
CompiledPipeline::default initializes an empty semantic cache registry
```

- [ ] **Step 2: Run the registry test and verify it fails**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  --test semantic_cache_runtime_registry
```

Expected: `SemanticCacheRuntimeRegistry` and the pipeline field are missing.

- [ ] **Step 3: Build shared process dependencies once**

Scan every main and forward action before creating stores. Build:

```text
one shared Arc<AsyncRedisKVStore> when any active action selects Redis
one shared Arc<MeshSemanticCacheStore> from the installed ClusterHandle and
one verified SemanticMeshCapabilityEvidence when any active action selects mesh
one MemorySemanticCacheStore per active memory action
```

Resolve disabled and inert bindings before dependency collection. A disabled
or source-incomplete Redis or mesh block appears in status but does not
require Redis, cluster transport, or a validation stub.

Each action receives its own `EmbeddingCache` orchestration and cache-level
stats. Redis and mesh adapters may be shared because namespace keys isolate
actions and their underlying connection pools are designed for concurrency.
Build each active binding's static action-policy digest once with
`semantic_static_action_policy_digest(&origins[origin_idx], forward_rule_idx)`.
Reject pipeline construction with a safe origin/slot error if that canonical
projection cannot be built.

Retain one `unique_stores` entry for the shared Redis adapter, one for the
shared mesh adapter, and one for each memory adapter. Registry purge uses this
deduplicated list so `scope: all` does not scan the same shared Redis or mesh
store once per origin.

Assign each unique store its vector index as `store_id`. When a binding is
attached, add that binding's `semantic_origin_route_digest` to the store
registration. For `All`, target every unique store. For `Origin`, target only
registrations whose origin set contains the requested digest. For the
internal namespace and entry scopes, derive the origin digest from the scope
and apply the same filter.

Run selected purges with at most 16 stores in flight. Do not stop after one
store error. Convert a store error into a safe failed attempt with
`nodes_attempted: 1`, `nodes_failed: 1`, and `complete: false`, then combine it
with every successful report. The registry returns `Err` only for an internal
scope invariant, never as a way to discard a partial report.

Runtime mode:

```rust
let cluster = crate::cluster::current_cluster_handle();
let mesh_node = cluster.as_ref().and_then(|handle| handle.mesh_node());
```

Require `ClusterHandle::mode() == ClusterMode::Distributed`,
`has_peer_transport()`, and a mesh node. Before calling
`MeshSemanticCacheStore::from_cluster`, run:

```rust
let capability = crate::cluster::block_on_cluster(
    async {
        crate::key_capability::announce_local_capabilities().await;
        crate::semantic_cache_runtime::mesh::require_semantic_mesh_capability(
            cluster.as_ref().expect("checked above"),
        )
        .await
    },
)?;
```

Do this once, after all enabled and source-complete actions have been scanned
and only when at least one binding selects mesh. A `Missing`, `Unknown`, or
membership-change result rejects the candidate pipeline before the shared
store exists and before any mesh binding becomes `Active`. The safe
construction error names only `semantic_cache.backend` and the closed
capability class. Do not use `CompiledConfig.mesh` and do not compare binary
version strings.

Validation mode checks `server.cluster.is_some()`, Redis driver and validated
connection shape, typed config, LSH construction, and inert-source behavior.
It creates validation-only store stubs and opens no network connection.

- [ ] **Step 4: Install the registry in pipeline construction**

Build the registry after main actions and forward rules are compiled. Match:

```rust
let semantic_caches = match mode {
    PipelineConstructionMode::Runtime => {
        SemanticCacheRuntimeRegistry::from_process(
            &config.server,
            config.l2_store.as_deref(),
            &config.origins,
            &actions,
            &forward_rules,
        )?
    }
    PipelineConstructionMode::Validation => {
        SemanticCacheRuntimeRegistry::for_validation(
            &config.server,
            config.l2_store.as_deref(),
            &config.origins,
            &actions,
            &forward_rules,
        )?
    }
};
```

Store it on the request-pinned `CompiledPipeline`. An old pipeline and its
connections remain alive only while in-flight requests hold that snapshot.

Add `semantic_caches: SemanticCacheRuntimeRegistry::default()` to the literal
inside `impl Default for CompiledPipeline` and to the direct struct fixture in
`admin_compression.rs`. Add these tests in `pipeline.rs`:

```text
compiled_pipeline_default_has_an_empty_semantic_cache_registry
compiled_pipeline_default_semantic_registry_has_no_registrations
```

The default path must not inspect config, resolve DNS, open Redis, read
cluster state, or bind a mesh store.

- [ ] **Step 5: Switch dispatch and admin debug to the registry**

Replace `config.embedding_cache()` with:

```rust
let selection = origin_idx.and_then(|origin_idx| {
    pipeline
        .semantic_caches
        .get(origin_idx, ctx.forward_rule_idx)
});
```

Use `selection.cache` for embedding, lookup, and write. Combine
`selection.static_action_policy_digest`, the request-pinned
`peer_policy_revision`, and `surface_label` through
`semantic_response_policy_digest`. Remove the temporary Task 7 call to
`semantic_static_action_policy_digest` from the request path.

Update the current synchronous admin debug function to iterate
`pipeline.semantic_caches` rather than initializing caches through action
config. Task 9 replaces this narrow debug function with the async status
surface.

Remove `AiHandlerConfig.embedding_cache`, its `OnceLock` field, every
initializer field assignment, and `embedding_cache()`. Configuration owns
wire settings only. Runtime state belongs exclusively to `CompiledPipeline`.

- [ ] **Step 6: Remove the dead semantic lookup hook**

Delete from `hooks.rs`:

```text
LookupRequest
CachedResponse
StoreRequest
PurgeScope
ResponseMode
ReplayPacing
LookupOutcome
SemanticLookupHook
Hooks.semantic_lookup
```

Delete `PendingSemcacheMiss` and the hook lookup and store branches from
`ai_dispatch.rs`. The canonical `EmbeddingCache` now owns every OSS semantic
lookup and store.

Update `crates/sbproxy-core/tests/hooks.rs` and the `Hooks::default` unit
test. Keep prompt classifier, intent detection, quality scoring, stream
safety, and other currently used hook contracts.

- [ ] **Step 7: Remove the dead stream cache recorder hook**

The recorder has no OSS implementation, depends on the removed semantic miss
key, and cannot replay through the current canonical semantic cache. Delete:

```text
StreamCacheCtx
StreamCacheEvent
StreamCacheChannel
StreamCacheGuard
StreamCacheRecorderHook
Hooks.stream_cache_recorder
StreamCacheRecorderArgs
stream recorder start and chunk fan-out
stream recorder tests
```

Keep the current explicit rule that streaming responses are not stored in
the semantic cache. Do not add streaming replay in this pull request.

Remove stale edition-specific comments around these branches. Do not modify the
independent stream-safety hook in this task.

- [ ] **Step 8: Remove stale semantic extension examples**

In `crates/sbproxy-config/src/compiler.rs` and
`crates/sbproxy-config/src/types.rs`, keep testing that extension maps accept
arbitrary nested data, but rename the fixture to a generic extension such as
`custom_metadata`. Remove comments claiming semantic cache belongs to an
external extension.

Do not remove the generic `extensions` map. Do not remove
`CompiledConfig.mesh` in this pull request because doing so touches unrelated
configuration fixtures. The new runtime must have zero reads of that obsolete
field.

- [ ] **Step 9: Prove Redis and mesh hits through two real proxy processes**

Create `e2e/tests/semantic_cache_distributed_e2e.rs` with two ignored tests:

```text
two_proxy_redis_semantic_hit_uses_the_public_ai_path
two_proxy_mesh_semantic_hit_uses_the_public_ai_path
```

Reuse the current semantic-cache mock embedding and chat-provider fixtures.
Each test:

1. Builds two temporary configs with distinct listen and admin ports.
2. Starts two copies of the already-built `SBPROXY_E2E_BIN`.
3. Waits for both readiness endpoints with a fixed deadline.
4. Sends the first prompt to node A and observes one mock provider call.
5. Sends a near-duplicate prompt with the same tenant and governed identity
   to node B.
6. Requires `x-semcache: HIT`, the expected body, and a provider call count
   still equal to one.
7. Stops both children through an RAII guard even after assertion failure.

The Redis test starts one disposable loopback `redis-server` with persistence
disabled and points both processes at its generated DSN. The mesh test gives
both processes the same cluster ID, distinct node IDs, reciprocal seed and
typed-transport addresses, and a runtime-generated temporary development
shared key. Write that key to a mode-0600 temporary file and put only its
`file:` reference in the two generated configs. The RAII fixture removes the
file with the processes.

Exercise the enforced two-stage rollout in the mesh test:

1. Start both processes with the same mesh configuration but
   `semantic_cache.enabled: false`.
2. Wait until both membership views are healthy.
3. Rewrite both temporary configs with the same semantic cache enabled.
4. Retry each enabling reload within one fixed deadline. An early
   capability-unverified rejection is allowed while announcements converge;
   the prior disabled pipeline must remain live. Require node A and node B to
   accept the reload before the deadline.
5. Send traffic only after both active pipelines report a mesh semantic
   binding.

The Task 6 two-node transport fixture owns mixed and missing declaration
rejection; do not add a production switch that suppresses this binary's
capability merely to recreate an old node in the process-level test. Never
commit, print, or preserve the temporary key or capability payload.

Keep failure, TTL, handoff, isolation, tenant boundary, and purge assertions
in the lower-level Task 6 suite. These two process tests prove only that the
compiled registry and public AI request path actually reach the shared
backends, which keeps the expensive layer selective.

Append this explicit target to the existing Redis live-state CI command block
after building `sbproxy`:

```bash
cargo build --locked -p sbproxy
SBPROXY_E2E_BIN=target/debug/sbproxy \
  cargo test --locked -p sbproxy-e2e \
  --test semantic_cache_distributed_e2e -- \
  --ignored --test-threads=1
```

- [ ] **Step 10: Run and commit registry plus cleanup**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  --test semantic_cache_runtime_registry
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(hooks) | test(semantic_cache_runtime) | test(compiled_pipeline_default)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo check --locked -p sbproxy-core -p sbproxy-ai
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo build --locked -p sbproxy
SBPROXY_E2E_BIN=/Users/rick/projects/soapbucket/sbproxy/target/debug/sbproxy \
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo test --locked -p sbproxy-e2e \
  --test semantic_cache_distributed_e2e -- \
  --ignored --test-threads=1
git add crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/redis.rs \
  crates/sbproxy-core/src/semantic_cache_runtime/mesh.rs \
  crates/sbproxy-core/src/lib.rs crates/sbproxy-core/src/pipeline.rs \
  crates/sbproxy-core/src/server.rs \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  crates/sbproxy-core/src/admin_cache.rs \
  crates/sbproxy-core/src/admin_compression.rs \
  crates/sbproxy-core/src/hooks.rs \
  crates/sbproxy-core/tests/hooks.rs \
  crates/sbproxy-core/tests/semantic_cache_runtime_registry.rs \
  crates/sbproxy-ai/src/handler.rs \
  crates/sbproxy-config/src/compiler.rs crates/sbproxy-config/src/types.rs \
  e2e/tests/semantic_cache_distributed_e2e.rs .github/workflows/ci.yml
git commit -m "feat(core): compile semantic cache runtimes"
```

Expected: origin and forward selection, dependency validation, default-field
initialization, no-dial validation, capability-gated mesh binding, pipeline
ownership, native lookup, hook cleanup, shared Redis cross-process hit, and
OSS mesh cross-process hit tests pass.

### Task 9: Add Async Admin Status, Scoped Purge, and Backend Metrics

**Files:**
- Modify: `crates/sbproxy-core/src/admin_cache.rs`
- Modify: `crates/sbproxy-core/src/admin.rs`
- Modify: `crates/sbproxy-core/src/semantic_cache_runtime.rs`
- Modify: `crates/sbproxy-ai/src/semantic_cache.rs`
- Modify: `crates/sbproxy-ai/src/ai_metrics.rs`
- Modify: `crates/sbproxy-observe/src/metric_registry.rs`
- Modify: `docs/metrics-stability.md`

**Interfaces:**
- Consumes: `SemanticCacheRuntimeRegistry::registrations`, backend health and stats,
  current operator authentication, CSRF, RBAC, and mutation auditing.
- Produces:

```rust
pub(crate) type Resp = (u16, &'static str, String);

pub(crate) async fn dispatch_semantic(
    method: &str,
    path: &str,
    body: Option<&str>,
    pipeline: &CompiledPipeline,
) -> Option<Resp>;
```

- Owns:

```text
GET  /admin/cache/semantic?limit=N
POST /admin/cache/semantic/purge
```

- Accepts only:

```json
{"scope":"all"}
```

or:

```json
{"scope":"origin","origin":"ai.example.com"}
```

- [ ] **Step 1: Write failing status tests**

Build a pipeline fixture with memory, Redis, mesh, disabled, and inert cache
slots. Assert status JSON contains only:

```text
origin
forward_rule
enabled
inert_reason
backend
health.state
health.reason
cache_stats
store_stats
recent
```

Add tests:

```text
semantic_status_lists_main_and_forward_rule_slots
semantic_status_reports_memory_default
semantic_status_reports_inert_missing_embedding_config
semantic_status_limit_defaults_to_50_and_caps_at_100
semantic_status_never_contains_prompt_body_embedding_header_key_or_dsn
semantic_status_reports_degraded_mesh_isolation
semantic_status_reports_unavailable_redis_without_exposing_the_error
semantic_status_checks_each_shared_store_health_once
```

Do not include rendered internal keys or namespace digests in the response.
Recent decisions expose reason, score, threshold, and timestamp only.
Group active registrations by internal `store_id`, await each unique store's
health once, then join the safe result back to every slot that shares it.
`store_id` is an implementation detail and is not serialized.

For an unconfigured slot, emit `enabled: false`, `backend: null`,
`inert_reason: null`, `health: null`, empty stats, and an empty recent list.
For an explicitly disabled slot, retain its selected backend but keep health
null. For an enabled source-incomplete slot, emit the fixed inert reason and
health null. Only active stores have a health object.

- [ ] **Step 2: Write failing purge authorization and scope tests**

At the admin connection level, prove:

```text
unauthenticated semantic status returns 401
read-only operator can read semantic status
read-only operator cannot purge
cookie-authenticated purge requires the existing CSRF token
admin operator can purge
unknown scope returns 400
owned semantic path with the wrong method returns 405
origin scope requires a known AI origin
wildcard origin scope purges every concrete host under that compiled route
request body cannot provide a raw key or prefix
all purge invokes every unique active store exactly once
origin purge invokes only unique stores used by matching main and forward slots
partial mesh purge returns complete false and a non-2xx status
Redis purge failure returns a sanitized non-2xx response
```

Reuse the current admin role and mutation audit path. Do not add a second
authorization check inside the cache store.

- [ ] **Step 3: Run admin tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_status) | test(semantic_purge)'
```

Expected: the semantic route still runs through the synchronous debug
dispatcher and has no purge endpoint.

- [ ] **Step 4: Dispatch semantic admin work on the async connection path**

`handle_admin_request` currently runs inside `spawn_blocking` because reload
and drift perform blocking file work. Do not call a Redis or mesh client tied
to the Tokio reactor from that blocking dispatcher or a second runtime.

In `handle_admin_connection`, after existing authentication, session upgrade,
CSRF, RBAC, and mutation-audit decisions, but before
`spawn_blocking(handle_admin_request)`, call:

```rust
if admin_cache::is_semantic_path(path) {
    if principal.is_none() {
        let _ = write_admin_response_headed(
            sock,
            401,
            "application/json",
            br#"{"error":"authentication required"}"#,
            &cors,
        )
        .await;
        return;
    }
    let pipeline = reload::current_pipeline_full();
    if let Some((status, content_type, body)) =
        admin_cache::dispatch_semantic(
            method,
            path,
            body_owned.as_deref(),
            pipeline.as_ref(),
        )
        .await
    {
        let _ = write_admin_response_headed(
            sock,
            status,
            content_type,
            body.as_bytes(),
            &cors,
        )
        .await;
        return;
    }
}
```

Adapt borrowing to the current response writer signature. The important
boundary is that the special async route repeats the explicit authenticated
principal check used by the other async admin routes. The connection-level
method gate has already applied CSRF, read-only RBAC, and mutation audit to
POST requests. Network operations then run on the active Tokio runtime.

Remove `/admin/cache/semantic` from synchronous `admin_cache::dispatch`.
Promote its private response tuple alias to `pub(crate)` or return the concrete
tuple so `admin.rs` can call the async dispatcher.
`dispatch_semantic` returns a 405 response for a recognized semantic path with
the wrong method and returns `None` only for an unowned path.

- [ ] **Step 5: Implement truthful purge responses**

For `scope: all`, call
`pipeline.semantic_caches.purge(&SemanticPurgeScope::All)`. For origin,
resolve the operator hostname through `pipeline.config.origins`, derive the
exact origin digest through the same identity builder used for keys, and call
the registry purge once. The registry invokes each unique underlying store
exactly once and only when its registered origin set matches the selected
origin.

Combine reports:

```rust
SemanticPurgeReport {
    removed: reports.iter().map(|report| report.removed).sum(),
    nodes_attempted: reports.iter().map(|report| report.nodes_attempted).sum(),
    nodes_failed: reports.iter().map(|report| report.nodes_failed).sum(),
    complete: reports.iter().all(|report| report.complete),
}
```

Return 200 only when complete. Return 503 with the safe report when a Redis
operation or mesh peer failed. Return 409 when no semantic cache is active.
Do not include backend errors.

- [ ] **Step 6: Add closed-label backend operation metrics**

Register the following in `sbproxy-ai/src/ai_metrics.rs` on the default
Prometheus registry:

```text
sbproxy_semantic_cache_backend_operations_total{backend,operation,outcome}
  backend: memory | redis | mesh
  operation: candidates | write | purge | health
  outcome: ok | miss | error | partial | rejected

sbproxy_semantic_cache_backend_operation_seconds{backend,operation}
  backend and operation use the same closed values
```

Use explicit duration buckets:

```text
0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
0.1, 0.25, 0.5, 1.0, 2.5, 5.0
```

Keep existing:

```text
sbproxy_ai_cache_results_total
sbproxy_ai_semantic_cache_similarity
sbproxy_semantic_cache_results_total
sbproxy_ai_tokens_saved_total
sbproxy_ai_cost_saved_micros_total
```

Do not add tenant, credential, prompt, key, namespace, peer, Redis address,
error string, or dynamic model labels to the new backend metrics.

Register both metrics in `metric_registry.rs` and add tests that all label
values come from the closed sets. Do not also declare these families in
`sbproxy-observe/src/metrics.rs`; the admin metrics renderer already gathers
the default registry, and double registration would create duplicate metric
families.

Register each descriptor as `SupportLevel::Stable`, `CompatTier::Beta`, and
`Registry::Default`, with the production recorder symbol as its writer. The
counter is `MetricKind::Counter`; the duration family is
`MetricKind::Histogram`. This keeps the executable metric registry and
generated stability page truthful.

Expose typed `SemanticBackendOperation` and `SemanticBackendOutcome` enums
with private `as_str()` mappings. One recorder accepts the backend enum,
operation enum, outcome enum, and elapsed duration. The cache orchestrator
records candidate and write calls, while the registry and admin status path
record purge and health calls. Empty candidates use `miss`; rejected records
use `rejected`; a partial purge uses `partial`; transport or store failures
use `error`.

Record one primary outcome per operation. Precedence is `error`, `partial`,
successful hit or write as `ok`, `rejected`, then `miss`. A lookup that skips
one bad candidate but still finds a valid hit records `ok`; the rejected
record remains visible in `SemanticStoreStats`.
Map health states to `ok`, `partial`, and `error` for healthy, degraded, and
unavailable. A complete purge is `ok`; an incomplete report is `partial`.

- [ ] **Step 7: Run and commit admin plus metrics**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo run --quiet --locked -p sbproxy-observe --bin generate-metrics-stability \
  > docs/metrics-stability.md
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-metrics-stability.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_status) | test(semantic_purge)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai -p sbproxy-observe \
  -E 'test(semantic_cache) | test(metric_registry)'
git add crates/sbproxy-core/src/admin_cache.rs \
  crates/sbproxy-core/src/admin.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/ai_metrics.rs \
  crates/sbproxy-observe/src/metric_registry.rs \
  docs/metrics-stability.md
git commit -m "feat(admin): operate distributed semantic caches"
```

Expected: async admin routing, existing authorization controls, safe status,
all and origin purge, partial failure reporting, counters, histograms, and
metric registry checks pass.

### Task 10: Update Only the Minimal Schema, Reference, and Existing Examples

**Files:**
- Modify: `schemas/ai-semantic-cache.schema.json`
- Modify: `schemas/README.md`
- Modify: `docs/ai-gateway.md`
- Modify: `docs/admin.md`
- Modify: `docs/admin-api-reference.md`
- Modify: `docs/architecture.md`
- Modify: `docs/observability.md`
- Modify: `docs/llms-full.txt`
- Modify: `examples/semantic-cache-local/README.md`
- Modify: `examples/semantic-cache-openai/README.md`
- Modify: `crates/sbproxy-core/tests/construct_examples.rs`

**Interfaces:**
- Consumes: the implemented memory, Redis, mesh, admin, metrics, and failure
  behavior.
- Produces only the documentation needed to configure and operate this pull
  request accurately.

- [ ] **Step 1: Update the canonical semantic-cache section**

In `docs/ai-gateway.md`, replace the process-local-only description with:

```text
semantic_cache is action scoped and opt-in
backend defaults to memory
memory retains the full same-namespace LRU cosine scan
Redis reuses proxy.l2_cache_settings
mesh reuses proxy.cluster and its current ownership ring
Redis and mesh use multi-table LSH only for candidate discovery
every backend applies exact cosine threshold reranking
keys bind origin, tenant, credential, model, surface, request context,
embedding identity and dimensions, semantic configuration, and response policy
lookup infrastructure failures become misses
corrupt or incompatible entries are rejected
streaming responses remain uncached
reversible PII disables semantic caching
cache payloads and embeddings are sensitive operator data
Redis and authenticated mesh peers are trusted infrastructure
standalone OpenAI embedding endpoints are public-only unless explicitly opted
into private access, resolve and pin DNS, never follow redirects, and cap
responses at 1 MiB
sidecar embedding endpoints accept only literal loopback HTTP or HTTPS
addresses with an explicit port
mesh refuses to bind until every live member advertises the authenticated
semantic_cache_snapshot_v1 capability
```

Keep the current embedding source examples. Do not duplicate local-inference
instructions already owned by `docs/local-inference.md`.

- [ ] **Step 2: Add concise Redis and mesh configuration fragments**

Add this Redis shape:

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: ${REDIS_URL}

origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          models: [gpt-4o-mini]
      semantic_cache:
        enabled: true
        backend: redis
        threshold: 0.85
        ttl_secs: 3600
        embedding:
          provider: openai
          model: text-embedding-3-small
```

Explain that `REDIS_URL` may be `redis://` or `rediss://` and that TLS files
remain under `proxy.l2_cache_settings.params`. Never duplicate them under
`semantic_cache`.

Add a partial mesh action fragment:

```yaml
semantic_cache:
  enabled: true
  backend: mesh
  threshold: 0.85
  ttl_secs: 3600
  source: sidecar
  sidecar:
    endpoint: http://127.0.0.1:9440
    model: all-MiniLM-L6-v2
```

Label it as a child of `action`. Link to the canonical cluster configuration
instead of copying a security-sensitive cluster block. State that mesh
requires a configured distributed `proxy.cluster`, working peer transport,
and a current authenticated `semantic_cache_snapshot_v1` declaration from
every live member. Document the enforced rollout:

```text
1. Deploy the new binary everywhere with backend mesh disabled.
2. Wait for every live member's capability announcement.
3. Enable backend mesh and reload each node.
4. If membership changes or a node restarts, reload after the fleet is
   homogeneous so the new membership snapshot can be verified.
```

A mixed, missing, expired, suspect, or unreachable member rejects the
candidate mesh binding. The prior pipeline remains active on reload failure.
This gate is enforced by runtime construction and checked again against the
verified membership evidence before semantic mesh operations. It is not an
operator promise or a version-string comparison.

Explain every storage field next to these fragments. `max_entries` controls
only the memory LRU; Redis and mesh use `ttl_secs` plus bounded
`lsh.candidates_per_bucket`. `max_response_bytes` is an optional operator cap;
when present it may be at most 7 MiB. When omitted, memory retains its prior
behavior while Redis and mesh still enforce the 7 MiB body and 8 MiB complete
wire-entry limits. Explain that LSH tables create candidate sets and never
replace exact threshold reranking. Tell operators to configure Redis
`maxmemory` and eviction policy for their deployment. Mesh cache memory is
ephemeral and bounded operationally by TTL and traffic shape. Neither
distributed backend treats `max_entries` as a global capacity guarantee.
Behavior-bearing configuration or policy changes create a new namespace;
older distributed records remain unreachable and expire by TTL unless an
operator purges them.

For `source: openai`, explain `allow_private_base_url` next to the existing
example. It defaults to false. The base URL must be absolute HTTP or HTTPS
with no userinfo, query, or fragment. DNS is resolved and pinned for each
call, every address must be public unless the opt-in is true, redirects are
never followed, timeout is at most 60 seconds, and the embedding response is
capped at 1 MiB. Rotating `api_key` preserves the compatibility namespace.
Changing `auth_header`, `auth_prefix`, or any static header name or value
creates a new namespace. Static `headers` are behavior-bearing, so place
rotation-only credentials in `api_key`.

For `source: sidecar`, state the local-only policy: use a literal
`127.0.0.0/8` or `::1` endpoint with an explicit port. Hostnames such as
`localhost`, public addresses, RFC1918 and link-local addresses, URL
credentials, queries, fragments, and non-root paths are invalid.

Include the validated defaults and limits in one compact table:

```text
backend                    memory
threshold                  0.85, inclusive 0.0 through 1.0
ttl_secs                   3600, positive
max_entries                1024, memory only, 1 through 1,000,000
max_response_bytes         unset, when set 1 through 7 MiB
lsh.tables                 8, 1 through 16
lsh.planes                 6, 1 through 63
lsh.candidates_per_bucket  32, 1 through 256
lsh.seed                   sbproxy-semantic-v2, 1 through 128 bytes
openai.timeout_ms          2000, 1 through 60000
openai.allow_private_base_url false
sidecar.timeout_ms         500, 1 through 60000
```

- [ ] **Step 3: Document admin and observability behavior**

In `docs/admin.md` and `docs/admin-api-reference.md`, document:

```text
GET /admin/cache/semantic?limit=N
POST /admin/cache/semantic/purge
{"scope":"all"}
{"scope":"origin","origin":"ai.example.com"}
```

State that purge is operator-authenticated, mutations require current RBAC and
CSRF controls, raw keys and prefixes are not accepted, and partial mesh or
Redis failures return non-2xx with safe counts.

List the tested status contract: 200 for status or a complete purge, 400 for
an invalid body or unknown origin, 401 for no operator, 403 for RBAC or CSRF,
405 for a wrong method, 409 when no cache is active, and 503 for an
incomplete backend purge.

Define `origin` as the configured origin route shown by status. For a
wildcard route such as `*.example.com`, that scope removes namespaces for
every concrete request host matched by the route. Concrete request hosts
remain separate compatibility identities during lookup.

Define `removed` and `purged_entries` as removed backend records, not distinct
model responses. One distributed response has one payload plus multiple LSH
membership records, so these counts are operational cleanup counts.

State that Redis SCAN purge is a complete pass over observed keys, not an
atomic barrier against concurrent writes.

State that mesh purge covers the current membership snapshot. A node already
removed while offline cannot be contacted; stranded cache records expire by
TTL and are not a durable revocation mechanism.

In `docs/observability.md`, add the two closed-label backend metrics from
Task 9 and explain the safe admin health states. Do not document raw keys,
namespace digests, or backend error strings.

- [ ] **Step 4: Remove stale architecture claims**

Remove text in `docs/architecture.md` claiming:

```text
semantic_cache is passed as opaque serde_json::Value
semantic_cache.streaming is read by an external implementation
the semantic lookup hook owns the active cache
```

Replace it with the compiled runtime registry and current OSS mesh ownership
model. Do not add a current proprietary edition or repository reference.

- [ ] **Step 5: Keep existing examples accurate without creating broad docs**

Update `examples/semantic-cache-local/README.md` to say omitted `backend`
means memory and preserves the full-scan local LRU.

Update `examples/semantic-cache-openai/README.md` to distinguish the OpenAI
embedding source from the cache storage backend. Its omitted backend remains
memory. Explain the public-only default, `allow_private_base_url` opt-in,
no-redirect behavior, DNS pinning, 1 MiB response cap, and which credential
and header changes do or do not change compatibility identity.

Do not add a new distributed example, Docker Compose stack, VHS tape, GIF, or
documentation hub in this pull request. The final documentation pull request
will decide the surviving walkthrough structure and record stable runtime
output.

Add focused construction fixtures in
`crates/sbproxy-core/tests/construct_examples.rs` for Redis and mesh backend
dependency errors and memory default success. These are test fixtures, not
new public example directories.

- [ ] **Step 6: Validate schema, references, examples, and generated text**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-config-schema.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-config --test validate_examples
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core --test construct_examples \
  -E 'test(semantic_cache)'
./scripts/regen-llms-full.sh
./scripts/regen-llms-full.sh --check
bash scripts/docs-ci.sh
```

Expected: generated schema and text are current, every existing example
config compiles, semantic construction fixtures pass, and documentation
links, anchors, and snippets pass.

- [ ] **Step 7: Commit the narrow documentation delta**

```bash
git add schemas/ai-semantic-cache.schema.json schemas/README.md \
  docs/ai-gateway.md docs/admin.md docs/admin-api-reference.md \
  docs/architecture.md docs/observability.md docs/llms-full.txt \
  examples/semantic-cache-local/README.md \
  examples/semantic-cache-openai/README.md \
  crates/sbproxy-core/tests/construct_examples.rs
git commit -m "docs: explain distributed semantic cache"
```

### Task 11: Run the Selective Pull Request Gate and Provenance Audit

**Files:**
- Verify all files changed in Tasks 1 through 10.

**Interfaces:**
- Consumes: the completed distributed semantic cache.
- Produces: one reviewable OSS pull request with no generated drift,
  unverified backend claims, copied historical implementation, secret
  material, or broad documentation churn.

- [ ] **Step 1: Review scope before expensive commands**

Run:

```bash
git status --short
git diff --stat origin/main...
git diff --name-only origin/main...
git diff --check origin/main...
```

Expected:

```text
only semantic cache, bounded mesh snapshot, admin, metrics, focused tests,
schema, and narrow reference files changed
no new public example directory or recording asset
no unrelated worktree files
no whitespace errors
```

If unrelated user changes are present, leave them untouched and keep them out
of this pull request.

- [ ] **Step 2: Run formatting and focused Clippy**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo fmt --all --check
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo clippy --locked -p sbproxy-ai --all-targets -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo clippy --locked -p sbproxy-mesh --all-targets -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo clippy --locked -p sbproxy-core --all-targets -- -D warnings
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo clippy --locked -p sbproxy-observe --all-targets -- -D warnings
```

Expected: no formatting or Clippy findings. Do not run workspace Clippy a
second time if the affected-crate commands are green.

- [ ] **Step 3: Run the affected unit and contract matrix once**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(semantic_cache)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-mesh \
  -E 'test(snapshot_prefix) | test(put_routed_by) | test(purge_prefix)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(semantic_cache) | test(key_capability) | test(compiled_pipeline_default) | test(hooks)'
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-observe \
  -E 'test(semantic_cache) | test(metric_registry)'
```

Expected: configuration, embedding endpoint policy, DNS pinning, redirect and
body caps, redacted Debug, identity, static-header compatibility, LSH, exact
reranking, memory, Redis RESP, mesh transport, authenticated capability gate,
two-node, registry, default pipeline, dispatch, admin, metric, and dead-hook
tests pass.

- [ ] **Step 4: Run the live Redis semantic contract once**

```bash
redis-server --version
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo test --locked -p sbproxy-core --lib \
  'semantic_cache_runtime::redis::tests::live_redis_semantic_' -- \
  --ignored --test-threads=1
```

Expected: bounded Lua indexes, TTL, NOSCRIPT recovery, namespace isolation,
and generated-prefix purge pass against disposable Redis processes.

- [ ] **Step 5: Run the real proxy regressions and distributed smoke**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo build --locked -p sbproxy
SBPROXY_E2E_BIN=/Users/rick/projects/soapbucket/sbproxy/target/debug/sbproxy \
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-e2e --test semantic_cache_e2e
SBPROXY_E2E_BIN=/Users/rick/projects/soapbucket/sbproxy/target/debug/sbproxy \
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-e2e \
  --test semantic_cache_sidecar_e2e
SBPROXY_E2E_BIN=/Users/rick/projects/soapbucket/sbproxy/target/debug/sbproxy \
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo test --locked -p sbproxy-e2e \
  --test semantic_cache_distributed_e2e -- \
  --ignored --test-threads=1
```

Expected: provider embedding and local sidecar paths still produce a real
miss, store, near-duplicate hit, unrelated miss, guardrail enforcement,
identity isolation, safe response replay, two-process Redis sharing, and
two-process mesh sharing. The sidecar fixture may use its existing explicit
model-fixture skip when those files are unavailable.

- [ ] **Step 6: Run schema, config, docs, and example gates**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-config-schema.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-config-readers.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  bash scripts/check-metrics-stability.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-config --test validate_examples
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core --test construct_examples \
  -E 'test(semantic_cache)'
./scripts/regen-llms-full.sh --check
bash scripts/docs-ci.sh
```

Expected: generated schemas and text are current, public configuration
compiles, narrow reference links resolve, and no broad docs artifact drift is
introduced.

- [ ] **Step 7: Run provenance, edition-reference, and secret scans**

Run:

```bash
if rg -n 'Proprietary|BUSL' \
  crates/sbproxy-ai/src/handler.rs \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/semantic_cache \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  crates/sbproxy-core/src/server/ai_support.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime \
  crates/sbproxy-core/src/key_capability.rs \
  crates/sbproxy-core/src/cluster.rs \
  crates/sbproxy-mesh/src/state/distributed_cache.rs \
  crates/sbproxy-mesh/src/transport \
  e2e/tests/semantic_cache_distributed_e2e.rs; then
  echo "private-license marker found in scoped OSS implementation"
  exit 1
fi

if rg -n 'sbproxy[_-]enterprise|enterprise semantic|enterprise implementation' \
  crates/sbproxy-ai crates/sbproxy-core crates/sbproxy-mesh \
  docs/ai-gateway.md docs/admin.md docs/admin-api-reference.md \
  docs/architecture.md docs/observability.md \
  examples/semantic-cache-local examples/semantic-cache-openai \
  e2e/tests/semantic_cache_distributed_e2e.rs; then
  echo "stale edition or repository reference found"
  exit 1
fi

if git diff --unified=0 origin/main... -- \
  crates/sbproxy-ai/src/handler.rs \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/semantic_cache \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  crates/sbproxy-core/src/server/ai_support.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime \
  crates/sbproxy-core/src/key_capability.rs \
  crates/sbproxy-core/src/cluster.rs \
  crates/sbproxy-mesh/src/state/distributed_cache.rs \
  crates/sbproxy-mesh/src/transport \
  docs/ai-gateway.md docs/admin.md docs/admin-api-reference.md \
  examples/semantic-cache-local examples/semantic-cache-openai \
  e2e/tests/semantic_cache_distributed_e2e.rs \
  | rg -n '^\+.*BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|^\+.*BEGIN CERTIFICATE'; then
  echo "PEM material found in scoped files"
  exit 1
fi

if git diff --unified=0 origin/main... -- \
  crates/sbproxy-ai/src/handler.rs \
  crates/sbproxy-ai/src/semantic_cache.rs \
  crates/sbproxy-ai/src/semantic_cache \
  crates/sbproxy-core/src/server/ai_dispatch.rs \
  crates/sbproxy-core/src/server/ai_support.rs \
  crates/sbproxy-core/src/semantic_cache_runtime.rs \
  crates/sbproxy-core/src/semantic_cache_runtime \
  crates/sbproxy-core/src/key_capability.rs \
  crates/sbproxy-core/src/cluster.rs \
  crates/sbproxy-mesh/src/state/distributed_cache.rs \
  crates/sbproxy-mesh/src/transport \
  docs/ai-gateway.md docs/admin.md docs/admin-api-reference.md \
  examples/semantic-cache-local examples/semantic-cache-openai \
  e2e/tests/semantic_cache_distributed_e2e.rs \
  | rg -n '^\+.*(sk-[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})'; then
  echo "credential-like material found in scoped files"
  exit 1
fi

git diff --check origin/main...
```

Expected: all scans are clean. Example placeholders such as
`${OPENAI_API_KEY}` and `${REDIS_URL}` are references, not values, and do not
match the credential patterns.

The implementation is an independent OSS rewrite. The pull request
description records:

```text
approved design: docs/superpowers/specs/2026-07-29-oss-feature-consolidation-design.md
canonical source: current OSS semantic cache, AsyncRedisKVStore, and sbproxy-mesh
historical code copied: none
historical concepts reused: random projection and versioned key namespaces only
current OSS improvements: safe scope digests, multi-table candidates, exact reranking,
bounded atomic Redis indexes, bounded mesh snapshots, truthful partial purge
```

- [ ] **Step 8: Review wire and security caveats explicitly**

Before claiming completion, confirm the pull request description states:

```text
mesh CacheOp and CacheResult gained appended postcard variants
mesh binding verifies semantic_cache_snapshot_v1 through authenticated typed
cluster state and rejects mixed, unknown, suspect, or unreachable membership
roll out the binary with mesh semantic cache disabled, wait for capability
announcements, then enable and reload
membership or incarnation changes stop semantic mesh operations until a
successful homogeneous reload supplies new evidence
standalone OpenAI embeddings use bounded httpkit clients, public-by-default
DNS resolution and connection pins, no redirects, and a 1 MiB body cap
sidecar embedding TCP endpoints are literal-loopback-only
Redis and mesh payloads contain sensitive response and embedding data
Redis TLS and cluster transport security remain operator responsibilities
this pull request does not add value-level at-rest encryption
this pull request does not add a value signature or MAC against a malicious backend
semantic cache is ephemeral and does not guarantee survival of mesh owner loss
request-path backend failures become misses
admin purge reports partial failure and Redis SCAN is not a concurrent-write barrier
mesh purge covers the current membership snapshot, not removed offline nodes
max_entries bounds only memory; distributed capacity needs backend and TTL policy
streaming semantic replay remains unsupported
memory remains the default and retains full-scan recall
```

Do not market cache persistence, transparent cross-version wire
compatibility, encrypted Redis values, arbitrary sidecar networking, or
streaming replay when this pull request does not implement them.

- [ ] **Step 9: Commit only mechanical gate fixes**

If formatting, schema generation, or `llms-full.txt` changed during the gate,
review that diff and commit only those mechanical updates:

```bash
git add Cargo.lock schemas/ai-semantic-cache.schema.json \
  docs/metrics-stability.md docs/llms-full.txt
git commit -m "chore: refresh semantic cache artifacts"
```

If there is no diff, do not create an empty commit.
