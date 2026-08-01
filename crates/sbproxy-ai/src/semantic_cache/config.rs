//! Typed wire configuration for an `ai_proxy` action's `semantic_cache:` block.
//!
//! `sbproxy-ai` owns this surface so the request path, the admin surface, and
//! the backend runtimes in `sbproxy-core` share one contract. Every bound is
//! enforced by [`EmbeddingCacheConfig::validate`] at config load, before any
//! runtime is built. The committed `schemas/ai-semantic-cache.schema.json` is
//! generated from these types (see the `generate-ai-semantic-cache-schema`
//! binary) and gated by `scripts/check-config-schema.sh`, so the generated
//! schema rejects the same values runtime construction rejects.
//!
//! Compatibility rules this module keeps:
//!
//! - `backend` defaults to [`SemanticCacheBackend::Memory`], so a
//!   configuration written before distributed backends existed keeps its
//!   process-local LRU behavior exactly.
//! - An omitted `max_response_bytes` preserves the current memory behavior.
//! - `max_entries` remains the memory LRU capacity.
//! - An enabled block whose source-specific sub-block is missing stays inert
//!   instead of failing the load, because the LiteLLM importer emits
//!   `semantic_cache: { enabled: true }` with nothing to vectorize with.
//!
//! Several of these types carry credentials, endpoints, or filesystem paths.
//! Those have hand-written redacted [`std::fmt::Debug`] implementations, and
//! validation errors name only the offending field and its safe bound.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hard cap on any embedding call timeout in milliseconds.
pub const MAX_EMBEDDING_TIMEOUT_MS: u64 = 60_000;
/// Hard cap on the bytes read from an embedding endpoint response.
pub const MAX_EMBEDDING_RESPONSE_BYTES: usize = 1024 * 1024;

/// Default number of LSH tables used for candidate generation.
pub const DEFAULT_LSH_TABLES: u8 = 8;
/// Hard cap on the number of LSH tables.
pub const MAX_LSH_TABLES: u8 = 16;
/// Default number of random projection planes per LSH table.
pub const DEFAULT_LSH_PLANES: u8 = 6;
/// Hard cap on the number of random projection planes per LSH table.
pub const MAX_LSH_PLANES: u8 = 63;
/// Default number of candidates read from one LSH bucket.
pub const DEFAULT_CANDIDATES_PER_BUCKET: usize = 32;
/// Hard cap on the number of candidates read from one LSH bucket.
pub const MAX_CANDIDATES_PER_BUCKET: usize = 256;
/// Hard cap on the configured memory LRU entry count.
pub const MAX_SEMANTIC_CACHE_ENTRIES: usize = 1_000_000;
/// Fixed ceiling on one encoded semantic wire entry in bytes.
pub const MAX_SEMANTIC_ENTRY_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on a cached response body in bytes, leaving room inside
/// [`MAX_SEMANTIC_ENTRY_BYTES`] for headers, embeddings, and framing.
pub const MAX_SEMANTIC_RESPONSE_BYTES: usize = 7 * 1024 * 1024;
/// Hard cap on an accepted embedding vector dimension count.
pub const MAX_EMBEDDING_DIMENSIONS: usize = 8_192;
/// Default LSH seed. Changing it changes every derived bucket.
pub const DEFAULT_LSH_SEED: &str = "sbproxy-semantic-v2";

/// Hard cap on the LSH seed length in bytes.
const MAX_LSH_SEED_BYTES: usize = 128;

/// Error returned when a `semantic_cache:` block fails validation at config
/// load.
///
/// The message names the offending field and its safe bound. It never carries
/// a URL, hostname, filesystem path, credential, header name, or header value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SemanticCacheConfigError(String);

/// Which store backs the semantic cache for this action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCacheBackend {
    /// Process-local LRU with a full same-namespace cosine scan. The default,
    /// so an existing configuration keeps today's behavior.
    #[default]
    Memory,
    /// Shared Redis, reusing the validated `proxy.l2_cache_settings`
    /// connection.
    Redis,
    /// The current cluster mesh, routed by key prefix over the authenticated
    /// transport.
    Mesh,
}

/// Deterministic locality-sensitive hashing bounds used for candidate
/// generation on the distributed backends.
///
/// The memory backend keeps its full same-namespace scan, so these values do
/// not change the recall of an existing memory deployment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticLshConfig {
    /// Number of independent hash tables, 1 through [`MAX_LSH_TABLES`].
    #[serde(default = "default_lsh_tables")]
    #[schemars(range(min = 1, max = 16))]
    pub tables: u8,
    /// Random projection planes per table, 1 through [`MAX_LSH_PLANES`].
    #[serde(default = "default_lsh_planes")]
    #[schemars(range(min = 1, max = 63))]
    pub planes: u8,
    /// Candidates read from one bucket, 1 through
    /// [`MAX_CANDIDATES_PER_BUCKET`].
    #[serde(default = "default_candidates_per_bucket")]
    #[schemars(range(min = 1, max = 256))]
    pub candidates_per_bucket: usize,
    /// Seed for the deterministic projections, 1 through 128 bytes. Two nodes
    /// must share this value to agree on buckets.
    #[serde(default = "default_lsh_seed")]
    #[schemars(length(min = 1, max = 128))]
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

/// Where the semantic cache gets prompt embeddings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmbeddingSource {
    /// Call an AI embedding provider's `/v1/embeddings` API (default,
    /// back-compat). Costs money and egresses the prompt.
    #[default]
    Provider,
    /// Call the local classifier sidecar's `Embed` RPC. Free, no egress.
    Sidecar,
    /// Run an in-process tract embedder. Single-binary, but loads a model
    /// into the proxy address space (opt-in).
    Inprocess,
    /// Call a standalone OpenAI-compatible `/v1/embeddings` endpoint that is
    /// not one of the origin's chat providers (another sbproxy, OpenRouter,
    /// ...). Decoupled from `providers`; carries its own URL and auth.
    Openai,
}

/// Which provider and model computes prompt embeddings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingProviderConfig {
    /// Provider name (must match an entry in the handler's `providers`).
    pub provider: String,
    /// Embedding model id, e.g. `text-embedding-3-small`.
    pub model: String,
}

/// Sidecar embedding endpoint config (for `source: sidecar`).
///
/// The sidecar is local by contract: `endpoint` must be an absolute HTTP or
/// HTTPS URL whose host is a literal loopback address and whose port is
/// explicit.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SidecarEmbeddingConfig {
    /// gRPC endpoint, e.g. `http://127.0.0.1:9440`.
    #[schemars(length(min = 1))]
    pub endpoint: String,
    /// Embedding model id (empty selects the sidecar default).
    #[serde(default)]
    pub model: String,
    /// Per-call timeout in milliseconds, 1 through
    /// [`MAX_EMBEDDING_TIMEOUT_MS`]. Defaults to 500.
    #[serde(default = "default_sidecar_timeout_ms")]
    #[schemars(range(min = 1, max = 60_000))]
    pub timeout_ms: u64,
}

/// In-process embedder config (for `source: inprocess`).
///
/// Provide explicit `model_path` and `tokenizer_path`. Known-model
/// auto-download for the in-process embedder is a follow-up; until then the
/// operator points at on-disk ONNX and tokenizer files.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InprocessEmbeddingConfig {
    /// Logical model id (informational; e.g. `all-MiniLM-L6-v2`).
    #[serde(default)]
    pub model: String,
    /// Path to the ONNX model file.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Path to the tokenizer.json file.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Max model size in bytes (guard). None uses the engine default.
    #[serde(default)]
    pub max_model_bytes: Option<u64>,
}

/// Standalone OpenAI-compatible embedding endpoint config (for
/// `source: openai`).
///
/// Unlike `source: provider`, this is not tied to the origin's chat
/// `providers`: point `base_url` at any OpenAI-compatible `/v1/embeddings`
/// route (another sbproxy, OpenRouter, ...). Auth defaults to
/// `Authorization: Bearer <api_key>`; set `auth_header` and `auth_prefix` for
/// `api-key` or `x-api-key` style endpoints, or omit `api_key` and carry the
/// auth in `headers`.
///
/// Public destinations are the default. A private or loopback destination
/// requires the explicit `allow_private_base_url` opt-in and is still
/// resolved and pinned on every call.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenAiEmbeddingConfig {
    /// OpenAI-compatible base URL, e.g. `https://api.openai.com/v1`.
    /// `/v1/embeddings` is appended (an overlapping trailing `/v1` is
    /// collapsed, matching the chat-provider path join).
    #[schemars(length(min = 1))]
    pub base_url: String,
    /// Embedding model id, e.g. `text-embedding-3-small`.
    #[serde(default)]
    pub model: String,
    /// Per-call timeout in milliseconds, 1 through
    /// [`MAX_EMBEDDING_TIMEOUT_MS`]. Defaults to 2000.
    #[serde(default = "default_openai_timeout_ms")]
    #[schemars(range(min = 1, max = 60_000))]
    pub timeout_ms: u64,
    /// API key. Interpolated (`${VAR}` or vault) by the config layer. When
    /// set, sent as `{auth_header}: {auth_prefix}{api_key}`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Auth header name. Defaults to `Authorization`.
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    /// Prefix prepended to the key in the auth header. Defaults to `Bearer `;
    /// set to `""` for raw-key headers like `api-key` or `x-api-key`.
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: String,
    /// Extra static headers, sent verbatim and applied after the auth header
    /// (e.g. OpenRouter `HTTP-Referer` and `X-Title`, or a custom auth header
    /// when `api_key` is omitted). Interpolated by the config layer.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Permit a private or loopback embedding destination. Public-only by
    /// default.
    #[serde(default)]
    pub allow_private_base_url: bool,
}

/// Operator config for the OSS embedding semantic cache, parsed from an
/// `ai_proxy` action's `semantic_cache:` block.
///
/// Unknown keys are rejected, so a stale `streaming:` or `key_template:`
/// entry fails the load instead of silently doing nothing.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingCacheConfig {
    /// Opt-in switch. The cache is inert unless this is `true`.
    #[serde(default)]
    pub enabled: bool,
    /// Which store backs this cache. Defaults to `memory`.
    #[serde(default)]
    pub backend: SemanticCacheBackend,
    /// Minimum cosine similarity (`0.0..=1.0`) for a near-duplicate prompt to
    /// be served from cache. Defaults to 0.85.
    #[serde(default = "default_threshold")]
    #[schemars(range(min = 0.0, max = 1.0))]
    pub threshold: f32,
    /// Entry time-to-live in seconds. Defaults to 3600.
    #[serde(default = "default_ttl_secs")]
    #[schemars(range(min = 1))]
    pub ttl_secs: u64,
    /// Memory LRU capacity, 1 through [`MAX_SEMANTIC_CACHE_ENTRIES`].
    /// Defaults to 1024. Redis and mesh accept the field for configuration
    /// compatibility and bound entries by TTL instead.
    #[serde(default = "default_max_entries")]
    #[schemars(range(min = 1, max = 1_000_000))]
    pub max_entries: usize,
    /// Optional cap on a cached response body in bytes, 1 through
    /// [`MAX_SEMANTIC_RESPONSE_BYTES`]. Omitted preserves the current memory
    /// behavior; Redis and mesh still enforce the fixed wire-entry ceiling.
    #[serde(default)]
    #[schemars(range(min = 1, max = 7_340_032))]
    pub max_response_bytes: Option<usize>,
    /// Candidate-generation bounds for the distributed backends.
    #[serde(default)]
    pub lsh: SemanticLshConfig,
    /// Where prompt embeddings come from. Defaults to `provider` so existing
    /// configs are unchanged.
    #[serde(default)]
    pub source: EmbeddingSource,
    /// Embedding provider and model used to vectorize prompts (for
    /// `source: provider`).
    #[serde(default)]
    pub embedding: Option<EmbeddingProviderConfig>,
    /// Local classifier-sidecar embedding endpoint (for `source: sidecar`).
    #[serde(default)]
    pub sidecar: Option<SidecarEmbeddingConfig>,
    /// In-process embedder (for `source: inprocess`).
    #[serde(default)]
    pub inprocess: Option<InprocessEmbeddingConfig>,
    /// Standalone OpenAI-compatible endpoint (for `source: openai`).
    #[serde(default)]
    pub openai: Option<OpenAiEmbeddingConfig>,
}

impl std::fmt::Debug for EmbeddingCacheConfig {
    /// Report tuning only. Every nested block goes through its own redacted
    /// implementation, so no endpoint, path, or credential can reach a log.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddingCacheConfig")
            .field("enabled", &self.enabled)
            .field("backend", &self.backend)
            .field("threshold", &self.threshold)
            .field("ttl_secs", &self.ttl_secs)
            .field("max_entries", &self.max_entries)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("lsh", &self.lsh)
            .field("source", &self.source)
            .field("embedding", &self.embedding)
            .field("sidecar", &self.sidecar)
            .field("inprocess", &self.inprocess)
            .field("openai", &self.openai)
            .finish()
    }
}

impl std::fmt::Debug for SidecarEmbeddingConfig {
    /// Report the model and timeout. The endpoint is withheld.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SidecarEmbeddingConfig")
            .field("model", &self.model)
            .field("timeout_ms", &self.timeout_ms)
            .field("endpoint", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for InprocessEmbeddingConfig {
    /// Report the model, the size guard, and whether each path is set. The
    /// filesystem paths themselves are withheld.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InprocessEmbeddingConfig")
            .field("model", &self.model)
            .field("max_model_bytes", &self.max_model_bytes)
            .field("model_path", &presence(self.model_path.is_some()))
            .field("tokenizer_path", &presence(self.tokenizer_path.is_some()))
            .finish()
    }
}

impl std::fmt::Debug for OpenAiEmbeddingConfig {
    /// Report the model, the timeout, whether a credential is present, the
    /// static header count, and the private opt-in. The base URL, auth header
    /// name, auth prefix, key, and header names and values are withheld.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_key = self.api_key.as_deref().is_some_and(|key| !key.is_empty());
        formatter
            .debug_struct("OpenAiEmbeddingConfig")
            .field("model", &self.model)
            .field("timeout_ms", &self.timeout_ms)
            .field("base_url", &"<redacted>")
            .field("api_key", &presence(has_key))
            .field("headers", &self.headers.len())
            .field("allow_private_base_url", &self.allow_private_base_url)
            .finish()
    }
}

/// Render a presence flag for a redacted field.
fn presence(present: bool) -> &'static str {
    if present {
        "set"
    } else {
        "unset"
    }
}

fn default_threshold() -> f32 {
    0.85
}

fn default_ttl_secs() -> u64 {
    3600
}

fn default_max_entries() -> usize {
    1024
}

fn default_sidecar_timeout_ms() -> u64 {
    500
}

fn default_openai_timeout_ms() -> u64 {
    2000
}

fn default_auth_header() -> String {
    "Authorization".to_string()
}

fn default_auth_prefix() -> String {
    "Bearer ".to_string()
}

fn default_lsh_tables() -> u8 {
    DEFAULT_LSH_TABLES
}

fn default_lsh_planes() -> u8 {
    DEFAULT_LSH_PLANES
}

fn default_candidates_per_bucket() -> usize {
    DEFAULT_CANDIDATES_PER_BUCKET
}

fn default_lsh_seed() -> String {
    DEFAULT_LSH_SEED.to_string()
}

impl EmbeddingCacheConfig {
    /// Validate every bound and endpoint policy before a runtime is built.
    ///
    /// Checks the similarity threshold, TTL, entry count, optional response
    /// cap, LSH bounds, the sidecar loopback-only endpoint policy, and the
    /// standalone OpenAI-compatible endpoint policy. An enabled block whose
    /// source-specific sub-block is missing stays inert and is not an error,
    /// so a generated `semantic_cache: { enabled: true }` keeps loading.
    ///
    /// Errors name only the offending field and its safe bound.
    pub fn validate(&self) -> Result<(), SemanticCacheConfigError> {
        if !self.threshold.is_finite() || !(0.0..=1.0).contains(&self.threshold) {
            return Err(invalid(
                "threshold",
                "must be a finite number between 0.0 and 1.0",
            ));
        }
        if self.ttl_secs == 0 {
            return Err(invalid("ttl_secs", "must be at least 1"));
        }
        if !(1..=MAX_SEMANTIC_CACHE_ENTRIES).contains(&self.max_entries) {
            return Err(invalid(
                "max_entries",
                format!("must be between 1 and {MAX_SEMANTIC_CACHE_ENTRIES}"),
            ));
        }
        if let Some(max_response_bytes) = self.max_response_bytes {
            if !(1..=MAX_SEMANTIC_RESPONSE_BYTES).contains(&max_response_bytes) {
                return Err(invalid(
                    "max_response_bytes",
                    format!("must be between 1 and {MAX_SEMANTIC_RESPONSE_BYTES}"),
                ));
            }
        }
        validate_lsh(&self.lsh)?;
        if let Some(sidecar) = self.sidecar.as_ref() {
            validate_sidecar(sidecar)?;
        }
        if let Some(openai) = self.openai.as_ref() {
            validate_openai(openai)?;
        }
        Ok(())
    }
}

fn invalid(field: &str, message: impl std::fmt::Display) -> SemanticCacheConfigError {
    SemanticCacheConfigError(format!("{field}: {message}"))
}

fn validate_lsh(lsh: &SemanticLshConfig) -> Result<(), SemanticCacheConfigError> {
    if !(1..=MAX_LSH_TABLES).contains(&lsh.tables) {
        return Err(invalid(
            "lsh.tables",
            format!("must be between 1 and {MAX_LSH_TABLES}"),
        ));
    }
    if !(1..=MAX_LSH_PLANES).contains(&lsh.planes) {
        return Err(invalid(
            "lsh.planes",
            format!("must be between 1 and {MAX_LSH_PLANES}"),
        ));
    }
    if !(1..=MAX_CANDIDATES_PER_BUCKET).contains(&lsh.candidates_per_bucket) {
        return Err(invalid(
            "lsh.candidates_per_bucket",
            format!("must be between 1 and {MAX_CANDIDATES_PER_BUCKET}"),
        ));
    }
    if !(1..=MAX_LSH_SEED_BYTES).contains(&lsh.seed.len()) {
        return Err(invalid(
            "lsh.seed",
            format!("must be between 1 and {MAX_LSH_SEED_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Validate the sidecar endpoint as a local-only transport.
///
/// Requires an absolute `http` or `https` URL with a literal IPv4 or IPv6
/// loopback host, an explicit port, no userinfo, query, or fragment, and an
/// empty or `/` path. `localhost`, public addresses, RFC1918 addresses,
/// link-local addresses, and any other hostname are rejected.
fn validate_sidecar(sidecar: &SidecarEmbeddingConfig) -> Result<(), SemanticCacheConfigError> {
    if !(1..=MAX_EMBEDDING_TIMEOUT_MS).contains(&sidecar.timeout_ms) {
        return Err(invalid(
            "sidecar.timeout_ms",
            format!("must be between 1 and {MAX_EMBEDDING_TIMEOUT_MS}"),
        ));
    }
    let parsed = parse_endpoint_url("sidecar.endpoint", &sidecar.endpoint)?;
    if !matches!(parsed.path(), "" | "/") {
        return Err(invalid("sidecar.endpoint", "must not carry a path"));
    }
    if parsed.port().is_none() {
        return Err(invalid("sidecar.endpoint", "must include an explicit port"));
    }
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if !loopback {
        return Err(invalid(
            "sidecar.endpoint",
            "must use a literal IPv4 or IPv6 loopback address",
        ));
    }
    sbproxy_classifier_client::ClassifierClient::validate_endpoint(&sidecar.endpoint)
        .map_err(|_| invalid("sidecar.endpoint", "is not a usable gRPC endpoint"))
}

/// Validate the standalone OpenAI-compatible endpoint.
///
/// Requires an absolute `http` or `https` base URL with a host, no userinfo,
/// query, or fragment, and a bounded timeout. Public destinations are the
/// default; a private or loopback destination needs
/// `allow_private_base_url: true`.
///
/// This checks the URL's shape only. Whether the destination is public is a
/// question about resolved addresses, and answering it here would put a
/// blocking DNS lookup in config validation: `sbproxy validate` and the
/// example-compilation sweep would need working DNS, would fail on an
/// offline machine, and would still be answering about addresses that can
/// change before the first request. The request path resolves, re-checks,
/// and pins the destination on every call, which is both hermetic here and
/// correct there. Same split as the RAG adapters: validation mode checks
/// syntax and never dials.
fn validate_openai(openai: &OpenAiEmbeddingConfig) -> Result<(), SemanticCacheConfigError> {
    if !(1..=MAX_EMBEDDING_TIMEOUT_MS).contains(&openai.timeout_ms) {
        return Err(invalid(
            "openai.timeout_ms",
            format!("must be between 1 and {MAX_EMBEDDING_TIMEOUT_MS}"),
        ));
    }
    parse_endpoint_url("openai.base_url", &openai.base_url)?;
    Ok(())
}

/// Parse an absolute HTTP or HTTPS endpoint URL with a host and no userinfo,
/// query, or fragment. Errors name only `field`.
fn parse_endpoint_url(
    field: &'static str,
    value: &str,
) -> Result<url::Url, SemanticCacheConfigError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| invalid(field, "must be an absolute http or https URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid(field, "URL scheme must be http or https"));
    }
    if parsed.host().is_none() {
        return Err(invalid(field, "URL must have a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid(field, "URL must not contain userinfo"));
    }
    if parsed.query().is_some() {
        return Err(invalid(field, "URL must not contain a query"));
    }
    if parsed.fragment().is_some() {
        return Err(invalid(field, "URL must not contain a fragment"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Parse a `semantic_cache` block without running validation.
    fn parse(value: serde_json::Value) -> Result<EmbeddingCacheConfig, String> {
        serde_json::from_value::<EmbeddingCacheConfig>(value).map_err(|error| error.to_string())
    }

    /// Parse a `semantic_cache` block and validate it, as config load does.
    fn parse_and_validate(value: serde_json::Value) -> Result<EmbeddingCacheConfig, String> {
        let config = parse(value)?;
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }

    /// The error from a block that must be rejected.
    fn rejection(value: serde_json::Value, label: &str) -> String {
        match parse_and_validate(value) {
            Ok(_) => panic!("{label} must be rejected"),
            Err(error) => error,
        }
    }

    /// Build a one-key JSON object.
    fn object(key: &str, value: serde_json::Value) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(key.to_string(), value);
        serde_json::Value::Object(map)
    }

    /// Parse an otherwise valid block with an explicit `backend` value.
    fn parse_backend(value: &str) -> Result<EmbeddingCacheConfig, String> {
        parse_and_validate(json!({
            "enabled": true,
            "backend": value,
            "embedding": {
                "provider": "openai",
                "model": "text-embedding-3-small"
            }
        }))
    }

    /// Parse an otherwise valid block carrying one extra key.
    fn parse_extra(key: &str, value: serde_json::Value) -> Result<EmbeddingCacheConfig, String> {
        let mut map = serde_json::Map::new();
        map.insert("enabled".to_string(), json!(true));
        map.insert(key.to_string(), value);
        parse_and_validate(serde_json::Value::Object(map))
    }

    /// Parse a block carrying only the given `sidecar` sub-block.
    fn parse_sidecar(sidecar: serde_json::Value) -> Result<EmbeddingCacheConfig, String> {
        parse_and_validate(json!({
            "enabled": true,
            "source": "sidecar",
            "sidecar": sidecar
        }))
    }

    /// Parse a block carrying only the given `openai` sub-block.
    fn parse_openai(openai: serde_json::Value) -> Result<EmbeddingCacheConfig, String> {
        parse_and_validate(json!({
            "enabled": true,
            "source": "openai",
            "openai": openai
        }))
    }

    /// The generated schema as JSON.
    fn generated_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(EmbeddingCacheConfig))
            .expect("schema serializes to JSON")
    }

    /// The closed set of string values a definition accepts, for both the
    /// flat `enum` shape and the documented-variant `oneOf` shape.
    fn enum_values(definition: &serde_json::Value) -> Vec<String> {
        if let Some(values) = definition.get("enum").and_then(|value| value.as_array()) {
            return values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect();
        }
        definition
            .get("oneOf")
            .and_then(|value| value.as_array())
            .map(|variants| {
                variants
                    .iter()
                    .filter_map(|variant| {
                        variant
                            .get("enum")?
                            .as_array()?
                            .first()?
                            .as_str()
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// One numeric or length keyword of a property, as `f64`.
    fn bound(schema: &serde_json::Value, pointer: &str) -> f64 {
        schema
            .pointer(pointer)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_else(|| panic!("schema is missing {pointer}"))
    }

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
        config.validate().expect("an existing config still loads");
        assert_eq!(config.max_response_bytes, None);
        assert_eq!(config.lsh.seed, DEFAULT_LSH_SEED);
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

    #[test]
    fn unknown_fields_are_rejected_instead_of_becoming_unused_policy() {
        let error = parse_extra("backends", json!(["redis"])).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn threshold_rejects_nan_infinity_and_out_of_range_values() {
        let mut config = parse(json!({"enabled": true})).unwrap();
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            config.threshold = bad;
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains("threshold"), "{error}");
        }
        for bad in [json!(-0.1), json!(1.1)] {
            let error = rejection(object("threshold", bad), "threshold");
            assert!(error.contains("threshold"), "{error}");
        }
        parse_and_validate(json!({"threshold": 0.0})).unwrap();
        parse_and_validate(json!({"threshold": 1.0})).unwrap();
    }

    #[test]
    fn ttl_secs_rejects_zero() {
        let error = rejection(json!({"ttl_secs": 0}), "ttl_secs 0");
        assert!(error.contains("ttl_secs"), "{error}");
        parse_and_validate(json!({"ttl_secs": 1})).unwrap();
    }

    #[test]
    fn max_entries_rejects_zero_and_values_above_one_million() {
        for bad in [json!(0), json!(1_000_001)] {
            let error = rejection(object("max_entries", bad), "max_entries");
            assert!(error.contains("max_entries"), "{error}");
        }
        parse_and_validate(json!({"max_entries": MAX_SEMANTIC_CACHE_ENTRIES})).unwrap();
    }

    #[test]
    fn max_response_bytes_rejects_zero_and_values_above_seven_mib() {
        for bad in [json!(0), json!(MAX_SEMANTIC_RESPONSE_BYTES + 1)] {
            let error = rejection(object("max_response_bytes", bad), "max_response_bytes");
            assert!(error.contains("max_response_bytes"), "{error}");
        }
        let config = parse_and_validate(json!({"max_response_bytes": 1024})).unwrap();
        assert_eq!(config.max_response_bytes, Some(1024));
    }

    #[test]
    fn lsh_bounds_are_enforced() {
        for (field, value) in [
            ("tables", json!(0)),
            ("tables", json!(17)),
            ("planes", json!(0)),
            ("planes", json!(64)),
            ("candidates_per_bucket", json!(0)),
            ("candidates_per_bucket", json!(257)),
        ] {
            let error = rejection(object("lsh", object(field, value)), field);
            assert!(error.contains(field), "{error}");
        }
        let config = parse_and_validate(json!({
            "lsh": {"tables": 16, "planes": 63, "candidates_per_bucket": 256}
        }))
        .unwrap();
        assert_eq!(config.lsh.tables, MAX_LSH_TABLES);
        assert_eq!(config.lsh.planes, MAX_LSH_PLANES);
        assert_eq!(config.lsh.candidates_per_bucket, MAX_CANDIDATES_PER_BUCKET);
    }

    #[test]
    fn lsh_seed_rejects_empty_and_over_long_values() {
        let too_long = "s".repeat(MAX_LSH_SEED_BYTES + 1);
        for bad in ["", too_long.as_str()] {
            let error = rejection(object("lsh", object("seed", json!(bad))), "lsh.seed");
            assert!(error.contains("lsh.seed"), "{error}");
        }
        let at_cap = "s".repeat(MAX_LSH_SEED_BYTES);
        parse_and_validate(object("lsh", object("seed", json!(at_cap)))).unwrap();
    }

    #[test]
    fn disabled_config_accepts_a_missing_source_block() {
        for source in ["provider", "sidecar", "inprocess", "openai"] {
            parse_and_validate(json!({"enabled": false, "source": source}))
                .unwrap_or_else(|error| panic!("disabled {source} must load: {error}"));
        }
    }

    #[test]
    fn enabled_source_without_its_block_stays_inert_for_compatibility() {
        for source in ["provider", "sidecar", "inprocess", "openai"] {
            let config = parse_and_validate(json!({"enabled": true, "source": source}))
                .unwrap_or_else(|error| panic!("enabled {source} must still load: {error}"));
            assert!(config.enabled);
            assert!(config.embedding.is_none());
            assert!(config.sidecar.is_none());
            assert!(config.inprocess.is_none());
            assert!(config.openai.is_none());
        }
    }

    #[test]
    fn sidecar_accepts_only_a_literal_loopback_endpoint_with_a_port() {
        for good in [
            "http://127.0.0.1:9440",
            "http://127.0.0.1:9440/",
            "https://127.0.0.1:9440",
            "http://[::1]:9440",
        ] {
            parse_sidecar(json!({"endpoint": good}))
                .unwrap_or_else(|error| panic!("{good} must be accepted: {error}"));
        }
    }

    #[test]
    fn sidecar_rejects_every_non_loopback_endpoint_shape() {
        for bad in [
            "http://localhost:9440",
            "http://sidecar.internal:9440",
            "http://93.184.216.34:9440",
            "http://10.0.0.5:9440",
            "http://169.254.169.254:9440",
            "http://user:secret@127.0.0.1:9440",
            "http://127.0.0.1:9440?q=1",
            "http://127.0.0.1:9440#frag",
            "http://127.0.0.1:9440/embed",
            "http://127.0.0.1",
            "unix:///var/run/sidecar.sock",
            "not-a-url",
        ] {
            let error = match parse_sidecar(json!({"endpoint": bad})) {
                Ok(_) => panic!("{bad} must be rejected"),
                Err(error) => error,
            };
            assert!(error.contains("sidecar.endpoint"), "{bad}: {error}");
        }
    }

    #[test]
    fn sidecar_and_openai_reject_zero_and_over_long_timeouts() {
        for bad in [json!(0), json!(MAX_EMBEDDING_TIMEOUT_MS + 1)] {
            let error = match parse_sidecar(json!({
                "endpoint": "http://127.0.0.1:9440",
                "timeout_ms": bad
            })) {
                Ok(_) => panic!("sidecar timeout {bad} must be rejected"),
                Err(error) => error,
            };
            assert!(error.contains("sidecar.timeout_ms"), "{error}");

            let error = match parse_openai(json!({
                "base_url": "http://127.0.0.1:9440/v1",
                "allow_private_base_url": true,
                "timeout_ms": bad
            })) {
                Ok(_) => panic!("openai timeout {bad} must be rejected"),
                Err(error) => error,
            };
            assert!(error.contains("openai.timeout_ms"), "{error}");
        }
    }

    #[test]
    fn openai_rejects_malformed_base_urls() {
        for bad in [
            "not-a-url",
            "ftp://127.0.0.1/v1",
            "http://user:secret@127.0.0.1/v1",
            "http://127.0.0.1/v1?q=1",
            "http://127.0.0.1/v1#frag",
        ] {
            let error = match parse_openai(json!({
                "base_url": bad,
                "allow_private_base_url": true
            })) {
                Ok(_) => panic!("{bad} must be rejected"),
                Err(error) => error,
            };
            assert!(error.contains("openai.base_url"), "{bad}: {error}");
        }
    }

    #[test]
    fn openai_endpoint_validation_is_hermetic_and_defers_the_address_check() {
        // Config load answers only the question it can answer offline: is
        // this a well-formed absolute endpoint. Whether the destination is
        // public depends on resolved addresses, which can change between
        // validation and the first request, so the request path owns that
        // check and this one must never resolve DNS. Keeping it here would
        // make `sbproxy validate` and the example sweep require working DNS.
        for private in ["http://127.0.0.1:9440/v1", "http://localhost:9440/v1"] {
            for opted_in in [false, true] {
                parse_openai(json!({
                    "base_url": private,
                    "allow_private_base_url": opted_in
                }))
                .unwrap_or_else(|error| {
                    panic!("{private} (opt-in {opted_in}) must pass shape validation: {error}")
                });
            }
        }
        // The opt-in still round-trips, because the runtime reads it to decide
        // whether a resolved private address is allowed.
        let config = parse_openai(json!({
            "base_url": "http://127.0.0.1:9440/v1",
            "allow_private_base_url": true
        }))
        .expect("opted-in endpoint loads");
        assert!(config.openai.expect("openai block").allow_private_base_url);
        let config = parse_openai(json!({"base_url": "https://api.openai.com/v1"}))
            .expect("public endpoint loads");
        assert!(!config.openai.expect("openai block").allow_private_base_url);
    }

    #[test]
    fn generated_schema_closes_the_backend_and_source_enums() {
        let schema = generated_schema();
        let backend = schema
            .pointer("/definitions/SemanticCacheBackend")
            .expect("backend definition");
        assert_eq!(enum_values(backend), ["memory", "redis", "mesh"]);
        let source = schema
            .pointer("/definitions/EmbeddingSource")
            .expect("source definition");
        assert_eq!(
            enum_values(source),
            ["provider", "sidecar", "inprocess", "openai"]
        );
        assert_eq!(
            schema.pointer("/additionalProperties"),
            Some(&json!(false)),
            "unknown keys must be closed in the schema too"
        );
    }

    #[test]
    fn generated_schema_matches_every_runtime_numeric_and_length_bound() {
        let schema = generated_schema();
        assert_eq!(bound(&schema, "/properties/threshold/minimum"), 0.0);
        assert_eq!(bound(&schema, "/properties/threshold/maximum"), 1.0);
        assert_eq!(bound(&schema, "/properties/ttl_secs/minimum"), 1.0);
        assert_eq!(bound(&schema, "/properties/max_entries/minimum"), 1.0);
        assert_eq!(
            bound(&schema, "/properties/max_entries/maximum"),
            MAX_SEMANTIC_CACHE_ENTRIES as f64
        );
        assert_eq!(
            bound(&schema, "/properties/max_response_bytes/minimum"),
            1.0
        );
        assert_eq!(
            bound(&schema, "/properties/max_response_bytes/maximum"),
            MAX_SEMANTIC_RESPONSE_BYTES as f64
        );

        let lsh = "/definitions/SemanticLshConfig/properties";
        assert_eq!(bound(&schema, &format!("{lsh}/tables/minimum")), 1.0);
        assert_eq!(
            bound(&schema, &format!("{lsh}/tables/maximum")),
            f64::from(MAX_LSH_TABLES)
        );
        assert_eq!(bound(&schema, &format!("{lsh}/planes/minimum")), 1.0);
        assert_eq!(
            bound(&schema, &format!("{lsh}/planes/maximum")),
            f64::from(MAX_LSH_PLANES)
        );
        assert_eq!(
            bound(&schema, &format!("{lsh}/candidates_per_bucket/minimum")),
            1.0
        );
        assert_eq!(
            bound(&schema, &format!("{lsh}/candidates_per_bucket/maximum")),
            MAX_CANDIDATES_PER_BUCKET as f64
        );
        assert_eq!(bound(&schema, &format!("{lsh}/seed/minLength")), 1.0);
        assert_eq!(
            bound(&schema, &format!("{lsh}/seed/maxLength")),
            MAX_LSH_SEED_BYTES as f64
        );

        for endpoint in [
            "/definitions/SidecarEmbeddingConfig/properties/timeout_ms",
            "/definitions/OpenAiEmbeddingConfig/properties/timeout_ms",
        ] {
            assert_eq!(bound(&schema, &format!("{endpoint}/minimum")), 1.0);
            assert_eq!(
                bound(&schema, &format!("{endpoint}/maximum")),
                MAX_EMBEDDING_TIMEOUT_MS as f64
            );
        }
    }

    #[test]
    fn embedding_cache_debug_redacts_every_endpoint_path_key_header_and_credential() {
        let config = parse(json!({
            "enabled": true,
            "source": "openai",
            "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
            "sidecar": {"endpoint": "http://sentinelsidecarhost.invalid:9440"},
            "inprocess": {
                "model_path": "/sentinelmodelpath/model.onnx",
                "tokenizer_path": "/sentineltokenizerpath/tokenizer.json"
            },
            "openai": {
                "base_url": "https://sentinelbaseurl.invalid/v1",
                "api_key": "sentinelapikey",
                "auth_header": "Sentinel-Auth-Header",
                "auth_prefix": "SentinelPrefix ",
                "headers": [["Sentinel-Header-Name", "sentinelheadervalue"]]
            }
        }))
        .unwrap();

        let formatted = format!("{config:?}");
        for secret in [
            "sentinelsidecarhost",
            "sentinelmodelpath",
            "sentineltokenizerpath",
            "sentinelbaseurl",
            "sentinelapikey",
            "Sentinel-Auth-Header",
            "SentinelPrefix",
            "Sentinel-Header-Name",
            "sentinelheadervalue",
        ] {
            assert!(!formatted.contains(secret), "{secret} leaked: {formatted}");
        }
        // The safe tuning fields still print, so the redaction is not a
        // blanket opaque marker.
        assert!(formatted.contains("backend: Memory"), "{formatted}");
        assert!(formatted.contains("source: Openai"), "{formatted}");
        assert!(formatted.contains("api_key: \"set\""), "{formatted}");
        assert!(formatted.contains("headers: 1"), "{formatted}");
    }
}
