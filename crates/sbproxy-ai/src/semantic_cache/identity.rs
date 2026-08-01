//! Fixed digest namespaces, prompt digests, and internal key construction.
//!
//! Every semantic cache key is built here so no backend ever concatenates an
//! operator supplied prefix, a Redis glob, a URL, or a raw request value. A
//! rendered key contains only fixed lowercase ASCII labels and lowercase
//! hexadecimal digests. Raw prompts, tenant identifiers, subjects, API key
//! identifiers, authorization values, model names, hostnames, URLs,
//! filesystem paths, and policy JSON never appear in a key, a log line, or an
//! admin response.
//!
//! The keyspace starts at version 2 so it can neither read nor overwrite an
//! older experimental `v1` semantic namespace:
//!
//! ```text
//! sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:entry:<64hex>
//! sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:index:t:<2hex>:b:<16hex>
//! sbproxy:semcache:v2:o:<64hex>:s:<64hex>:c:<64hex>:index:t:<2hex>:b:<16hex>:member:<64hex>
//! ```
//!
//! Each boundary is hashed under its own fixed domain label with a
//! deterministic length delimited field encoding, so a concatenation alias
//! cannot merge two different identities and the digest does not depend on
//! the host architecture.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use super::config::{
    EmbeddingCacheConfig, EmbeddingSource, OpenAiEmbeddingConfig, SemanticCacheBackend,
};
use super::lsh::SemanticBucket;

/// Fixed label that opens every semantic cache key in the v2 keyspace.
pub const SEMANTIC_KEY_PREFIX: &str = "sbproxy:semcache:v2";

/// Keyspace version carried by [`SEMANTIC_KEY_PREFIX`].
///
/// A future incompatible key or digest change bumps this and the domain
/// labels together, which retires the old keyspace instead of reinterpreting
/// it.
pub const SEMANTIC_KEYSPACE_VERSION: u16 = 2;

/// Fixed credential identity used when a request carries no credential.
pub const SEMANTIC_ANONYMOUS_CREDENTIAL: &str = "anonymous";

/// Domain for the compiled origin route digest.
const ORIGIN_DOMAIN: &[u8] = b"sbproxy-semcache-origin-v2";
/// Domain for the tenant and credential scope digest.
const SCOPE_DOMAIN: &[u8] = b"sbproxy-semcache-scope-v2";
/// Domain for the request compatibility digest.
const COMPAT_DOMAIN: &[u8] = b"sbproxy-semcache-compat-v2";
/// Domain for the semantic prompt digest.
const PROMPT_DOMAIN: &[u8] = b"sbproxy-semcache-prompt-v2";
/// Domain for the secret safe semantic configuration projection.
const CONFIG_DOMAIN: &[u8] = b"sbproxy-semcache-config-v2";
/// Domain for endpoint, base URL, and local file path identity.
///
/// Those values are secret bearing, so only their digest reaches the
/// configuration encoding. The raw text is never formatted or retained.
const OPAQUE_DOMAIN: &[u8] = b"sbproxy-semcache-opaque-v2";
/// Domain for a normalized static header name.
const HEADER_NAME_DOMAIN: &[u8] = b"sbproxy-semcache-header-name-v2";
/// Domain for a static header value.
const HEADER_VALUE_DOMAIN: &[u8] = b"sbproxy-semcache-header-value-v2";

/// Fixed tag that separates the generated credential header inputs from the
/// static header pairs, so the two can never alias each other.
const GENERATED_AUTH_TAG: &str = "generated-auth";

/// Deterministic domain separated field encoder.
///
/// The encoding starts with the literal domain bytes and one zero byte. Each
/// ordered field then contributes its length as one unsigned 64 bit big
/// endian integer, the field bytes, and one zero byte. Integers use their
/// fixed field width in big endian form and child digests are fed as raw
/// bytes, never as hexadecimal text.
struct FieldDigest {
    /// Running SHA-256 state over the encoded fields.
    hasher: Sha256,
}

impl FieldDigest {
    /// Open an encoding under one fixed domain label.
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([0u8]);
        Self { hasher }
    }

    /// Append one length delimited byte field.
    fn bytes(&mut self, field: &[u8]) -> &mut Self {
        self.hasher.update(field_width(field.len()).to_be_bytes());
        self.hasher.update(field);
        self.hasher.update([0u8]);
        self
    }

    /// Append one UTF-8 text field.
    fn text(&mut self, field: &str) -> &mut Self {
        self.bytes(field.as_bytes())
    }

    /// Append one 32 byte child digest as raw bytes.
    fn child(&mut self, digest: &[u8; 32]) -> &mut Self {
        self.bytes(digest)
    }

    /// Append one unsigned 8 bit field.
    fn byte(&mut self, value: u8) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Append one unsigned 16 bit big endian field.
    fn u16_be(&mut self, value: u16) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Append one unsigned 32 bit big endian field.
    fn u32_be(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Append one unsigned 64 bit big endian field.
    fn u64_be(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Append one host sized count at the fixed 64 bit field width.
    fn count(&mut self, value: usize) -> &mut Self {
        self.u64_be(field_width(value))
    }

    /// Append one boolean field.
    fn flag(&mut self, value: bool) -> &mut Self {
        self.byte(u8::from(value))
    }

    /// Append one optional byte field as a presence flag plus its value.
    ///
    /// The presence flag keeps an absent field distinct from a present empty
    /// field, which an empty length prefix alone cannot express.
    fn optional_bytes(&mut self, field: Option<&[u8]>) -> &mut Self {
        match field {
            Some(bytes) => self.flag(true).bytes(bytes),
            None => self.flag(false).bytes(&[]),
        }
    }

    /// Append one optional UTF-8 text field.
    fn optional_text(&mut self, field: Option<&str>) -> &mut Self {
        self.optional_bytes(field.map(str::as_bytes))
    }

    /// Append one optional 32 byte child digest.
    fn optional_child(&mut self, digest: Option<&[u8; 32]>) -> &mut Self {
        self.optional_bytes(digest.map(|digest| digest.as_slice()))
    }

    /// Append one optional unsigned 64 bit big endian field.
    fn optional_u64(&mut self, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => self.flag(true).u64_be(value),
            None => self.flag(false).bytes(&[]),
        }
    }

    /// Append one optional boolean field.
    fn optional_flag(&mut self, value: Option<bool>) -> &mut Self {
        match value {
            Some(value) => self.flag(true).flag(value),
            None => self.flag(false).bytes(&[]),
        }
    }

    /// Close the encoding and return the digest.
    fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

/// Widen a host sized length to the fixed 64 bit field width.
///
/// Every supported target has a `usize` no wider than 64 bits, so this is
/// lossless. The saturating fallback keeps the encoder total on a wider
/// hypothetical target instead of silently truncating a length prefix.
fn field_width(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Encode one single field value under one domain.
fn digest_one(domain: &[u8], field: &[u8]) -> [u8; 32] {
    let mut digest = FieldDigest::new(domain);
    digest.bytes(field);
    digest.finish()
}

/// Normalize a DNS name for digest input.
///
/// Names are compared ASCII case insensitively and at most one trailing DNS
/// dot is removed, so `Api.Example.com.` and `api.example.com` share one
/// namespace while `api.example.com..` does not.
fn normalize_dns_name(value: &str) -> String {
    let trimmed = value.strip_suffix('.').unwrap_or(value);
    trimmed.to_ascii_lowercase()
}

/// Digest one secret bearing endpoint, base URL, or filesystem path.
fn opaque_digest(value: &str) -> [u8; 32] {
    digest_one(OPAQUE_DOMAIN, value.as_bytes())
}

/// Normalize and digest one header name.
fn header_name_digest(name: &str) -> [u8; 32] {
    digest_one(HEADER_NAME_DOMAIN, normalize_header_name(name).as_bytes())
}

/// Digest one header value.
fn header_value_digest(value: &[u8]) -> [u8; 32] {
    digest_one(HEADER_VALUE_DOMAIN, value)
}

/// Normalize a header name with the same rules the request path applies.
///
/// A valid name is rendered through its canonical lowercase HTTP form. An
/// invalid name cannot be sent at all, so it falls back to ASCII lowercase
/// and still participates in identity rather than disappearing from it.
fn normalize_header_name(name: &str) -> String {
    match reqwest::header::HeaderName::from_bytes(name.as_bytes()) {
        Ok(parsed) => parsed.as_str().to_string(),
        Err(_) => name.to_ascii_lowercase(),
    }
}

/// Project the effective static embedding headers to ordered digest pairs.
///
/// This mirrors the `HeaderMap::insert` semantics of the request builder:
/// names are matched case insensitively and only the final value for a
/// duplicated name survives. The effective map is then sorted by normalized
/// name so reordering distinct headers or changing name case cannot split a
/// namespace, while a duplicate reorder that changes the final value does.
/// Only the two child digests leave this function; a raw name or value is
/// never formatted or retained.
fn effective_header_digests(headers: &[(String, String)]) -> Vec<([u8; 32], [u8; 32])> {
    let mut effective: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, value) in headers {
        effective.insert(normalize_header_name(name), value.as_bytes().to_vec());
    }
    effective
        .into_iter()
        .map(|(name, value)| {
            (
                digest_one(HEADER_NAME_DOMAIN, name.as_bytes()),
                header_value_digest(&value),
            )
        })
        .collect()
}

/// Fixed label for one cache backend.
fn backend_label(backend: SemanticCacheBackend) -> &'static str {
    match backend {
        SemanticCacheBackend::Memory => "memory",
        SemanticCacheBackend::Redis => "redis",
        SemanticCacheBackend::Mesh => "mesh",
    }
}

/// Fixed label for one embedding source.
fn source_label(source: EmbeddingSource) -> &'static str {
    match source {
        EmbeddingSource::Provider => "provider",
        EmbeddingSource::Sidecar => "sidecar",
        EmbeddingSource::Inprocess => "inprocess",
        EmbeddingSource::Openai => "openai",
    }
}

/// Whether the standalone embedding request injects a generated credential.
///
/// This repeats the nonempty key check the request builder performs, so
/// adding or removing credential injection changes compatibility identity
/// while rotating the key value does not.
fn openai_credential_present(config: &OpenAiEmbeddingConfig) -> bool {
    config
        .api_key
        .as_deref()
        .filter(|key| !key.is_empty())
        .is_some()
}

/// Ordered identity inputs for one semantic cache namespace.
///
/// This type deliberately has no `Debug` implementation. It borrows raw
/// tenant, credential, model, and host values that must never reach a log
/// line, a trace, or an admin response. Only the derived digests escape.
#[derive(Clone)]
pub struct SemanticNamespaceInput<'a> {
    /// Compiled origin route, which may be a leading wildcard such as
    /// `*.example.com`.
    pub origin_route: &'a str,
    /// Concrete request hostname taken from the request context.
    pub request_host: &'a str,
    /// Resolved tenant identifier.
    pub tenant_id: &'a str,
    /// Safe credential identity from [`semantic_credential_identity`].
    pub credential_identity: &'a str,
    /// Model the caller requested.
    pub requested_model: &'a str,
    /// API surface the request arrived on.
    pub api_surface: &'a str,
    /// Digest of the canonical non prompt request context.
    pub request_context_digest: &'a [u8; 32],
    /// Embedding source and model identity.
    pub embedding_identity: &'a str,
    /// Embedding vector width.
    pub embedding_dimensions: usize,
    /// Digest of the compiled semantic configuration.
    pub semantic_config_digest: &'a [u8; 32],
    /// Digest of the static action policy plus the pinned governed revision.
    pub response_policy_digest: &'a [u8; 32],
    /// Semantic wire and keyspace version.
    pub schema_version: u16,
}

/// Isolated namespace that a stored entry must match before replay.
///
/// The three digests split one identity into the scopes an operator can act
/// on. The origin digest covers the compiled origin route, so an admin origin
/// purge removes every concrete host matched by one wildcard route. The scope
/// digest covers tenant and credential identity. The compatibility digest
/// covers everything that must match before a response may be replayed at
/// all: concrete request host, requested model, API surface, normalized
/// request context, embedding identity and dimensions, semantic
/// configuration, response policy, and the semantic wire version.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticNamespace {
    /// Digest of the normalized compiled origin route.
    origin_digest: [u8; 32],
    /// Digest of the tenant and credential identity.
    scope_digest: [u8; 32],
    /// Digest of the request compatibility fence.
    compatibility_digest: [u8; 32],
}

impl SemanticNamespace {
    /// Derive a namespace from one complete identity input.
    pub fn derive(input: SemanticNamespaceInput<'_>) -> Self {
        let origin_digest = semantic_origin_route_digest(input.origin_route);

        let mut scope = FieldDigest::new(SCOPE_DOMAIN);
        scope.text(input.tenant_id).text(input.credential_identity);

        let mut compatibility = FieldDigest::new(COMPAT_DOMAIN);
        compatibility
            .text(&normalize_dns_name(input.request_host))
            .text(input.requested_model)
            .text(input.api_surface)
            .child(input.request_context_digest)
            .text(input.embedding_identity)
            .count(input.embedding_dimensions)
            .child(input.semantic_config_digest)
            .child(input.response_policy_digest)
            .u16_be(input.schema_version);

        Self {
            origin_digest,
            scope_digest: scope.finish(),
            compatibility_digest: compatibility.finish(),
        }
    }

    /// Digest of the compiled origin route this namespace belongs to.
    pub fn origin_digest(&self) -> [u8; 32] {
        self.origin_digest
    }

    /// Key prefix that selects every entry under this compiled origin route.
    pub fn origin_prefix(&self) -> String {
        semantic_origin_prefix(&self.origin_digest)
    }

    /// Key prefix that selects every entry in this exact namespace.
    ///
    /// The prefix ends with the field separator, so a scan can never reach a
    /// neighbouring scope or compatibility digest.
    pub fn namespace_prefix(&self) -> String {
        format!(
            "{SEMANTIC_KEY_PREFIX}:o:{}:s:{}:c:{}:",
            hex::encode(self.origin_digest),
            hex::encode(self.scope_digest),
            hex::encode(self.compatibility_digest),
        )
    }
}

impl fmt::Debug for SemanticNamespace {
    /// Render only the three digests. Every identity input is already hashed,
    /// so this formatting cannot leak a tenant, credential, host, or model.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticNamespace")
            .field("origin_digest", &hex::encode(self.origin_digest))
            .field("scope_digest", &hex::encode(self.scope_digest))
            .field(
                "compatibility_digest",
                &hex::encode(self.compatibility_digest),
            )
            .finish()
    }
}

/// One candidate bucket index for a stored entry.
///
/// A backend writes the manifest and the member under the same bucket, and a
/// lookup reads the manifest to find candidates. The candidates still pass
/// schema, namespace, expiry, dimension, finite vector, and exact cosine
/// checks before any replay, so a bucket collision can never decide a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticBucketIndex {
    /// Key of the bucket manifest that lists candidate members.
    pub manifest_key: String,
    /// Prefix that a member key extends with the prompt digest.
    pub member_prefix: String,
    /// Stable routing token for this bucket.
    ///
    /// A backend that places keys on an owner must route the manifest and
    /// every member of the bucket with this token. Routing on the full member
    /// key would scatter one bucket across owners and turn a candidate read
    /// into a guaranteed miss.
    pub routing_key: String,
}

impl SemanticBucketIndex {
    /// Build the member key for one prompt digest inside this bucket.
    pub fn member_key(&self, prompt_digest: &[u8; 32]) -> String {
        format!("{}{}", self.member_prefix, hex::encode(prompt_digest))
    }
}

/// Complete key set for one stored semantic entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEntryKeys {
    /// Key of the payload record.
    pub entry_key: String,
    /// One index per configured LSH table.
    pub bucket_indexes: SmallVec<[SemanticBucketIndex; 8]>,
}

/// Build every key one stored entry needs.
///
/// Multi table index writes may complete partially. A payload without an
/// index and an index without a payload are both safe misses, so no partial
/// write can create a false hit.
pub fn semantic_entry_keys(
    namespace: &SemanticNamespace,
    prompt_digest: &[u8; 32],
    buckets: &[SemanticBucket],
) -> SemanticEntryKeys {
    let namespace_prefix = namespace.namespace_prefix();
    let entry_key = format!("{namespace_prefix}entry:{}", hex::encode(prompt_digest));
    let bucket_indexes = buckets
        .iter()
        .map(|bucket| {
            let table = bucket.table;
            let value = bucket.value;
            let manifest_key = format!("{namespace_prefix}index:t:{table:02x}:b:{value:016x}");
            SemanticBucketIndex {
                member_prefix: format!("{manifest_key}:member:"),
                routing_key: manifest_key.clone(),
                manifest_key,
            }
        })
        .collect();
    SemanticEntryKeys {
        entry_key,
        bucket_indexes,
    }
}

/// Rebuild the payload key for one namespace and prompt digest.
pub fn semantic_entry_key(namespace: &SemanticNamespace, prompt_digest: &[u8; 32]) -> String {
    format!(
        "{}entry:{}",
        namespace.namespace_prefix(),
        hex::encode(prompt_digest)
    )
}

/// Build the purge prefix for one compiled origin route digest.
///
/// Every purge prefix comes from this builder. An operator supplied prefix or
/// Redis glob is never concatenated into a key.
pub fn semantic_origin_prefix(origin_digest: &[u8; 32]) -> String {
    format!("{SEMANTIC_KEY_PREFIX}:o:{}:", hex::encode(origin_digest))
}

/// Digest one compiled origin route.
///
/// The route is the compiler validated value, which may be a leading wildcard
/// such as `*.example.com`. It is never taken from an operator supplied Redis
/// prefix, URL, or path.
pub fn semantic_origin_route_digest(compiled_origin_route: &str) -> [u8; 32] {
    digest_one(
        ORIGIN_DOMAIN,
        normalize_dns_name(compiled_origin_route).as_bytes(),
    )
}

/// Digest the exact semantic prompt text.
///
/// The digest covers only the prompt domain and the UTF-8 bytes of the
/// extracted semantic prompt. There is no second backend specific text
/// normalization step, so every backend agrees on one prompt identity.
pub fn semantic_prompt_digest(prompt: &str) -> [u8; 32] {
    digest_one(PROMPT_DOMAIN, prompt.as_bytes())
}

/// Digest the secret safe compatibility projection of one semantic block.
///
/// The projection covers backend, threshold bits, TTL, the memory capacity
/// when the backend is memory, the explicit response cap, the LSH settings,
/// the embedding source, and the embedding identity. Endpoint, base URL,
/// filesystem path, header, and credential text are hashed before they enter
/// the encoding, so the raw values never appear in a formatted digest input.
///
/// The generated `api_key` value is excluded so ordinary credential rotation
/// does not fragment the namespace. Credential presence, the auth header
/// name, and the auth prefix are included because they change request
/// behavior. Every entry in `headers` stays in identity, even one an operator
/// uses as a custom credential; operators who need rotation stable
/// credentials should use `api_key` with `auth_header` and `auth_prefix`.
pub fn semantic_configuration_digest(config: &EmbeddingCacheConfig) -> [u8; 32] {
    let mut digest = FieldDigest::new(CONFIG_DOMAIN);
    digest
        .text(backend_label(config.backend))
        .u32_be(config.threshold.to_bits())
        .u64_be(config.ttl_secs)
        // The LRU capacity is a memory backend lever. Redis and mesh accept
        // the field for configuration compatibility and must not fragment a
        // distributed namespace on it.
        .optional_u64(match config.backend {
            SemanticCacheBackend::Memory => Some(field_width(config.max_entries)),
            SemanticCacheBackend::Redis | SemanticCacheBackend::Mesh => None,
        })
        .optional_u64(config.max_response_bytes.map(field_width))
        .byte(config.lsh.tables)
        .byte(config.lsh.planes)
        .count(config.lsh.candidates_per_bucket)
        .text(&config.lsh.seed)
        .text(source_label(config.source));

    match config.source {
        EmbeddingSource::Provider => {
            let provider = config.embedding.as_ref();
            digest
                .optional_text(provider.map(|block| block.provider.as_str()))
                .optional_text(provider.map(|block| block.model.as_str()));
        }
        EmbeddingSource::Sidecar => {
            let sidecar = config.sidecar.as_ref();
            let endpoint = sidecar.map(|block| opaque_digest(&block.endpoint));
            digest
                .optional_child(endpoint.as_ref())
                .optional_text(sidecar.map(|block| block.model.as_str()))
                .optional_u64(sidecar.map(|block| block.timeout_ms));
        }
        EmbeddingSource::Inprocess => {
            let inprocess = config.inprocess.as_ref();
            let model_path = inprocess
                .and_then(|block| block.model_path.as_deref())
                .map(opaque_digest);
            let tokenizer_path = inprocess
                .and_then(|block| block.tokenizer_path.as_deref())
                .map(opaque_digest);
            digest
                .optional_text(inprocess.map(|block| block.model.as_str()))
                .optional_child(model_path.as_ref())
                .optional_child(tokenizer_path.as_ref())
                .optional_u64(inprocess.and_then(|block| block.max_model_bytes));
        }
        EmbeddingSource::Openai => {
            let openai = config.openai.as_ref();
            let base_url = openai.map(|block| opaque_digest(&block.base_url));
            let auth_name = openai.map(|block| header_name_digest(&block.auth_header));
            let auth_prefix = openai.map(|block| header_value_digest(block.auth_prefix.as_bytes()));
            let headers = openai
                .map(|block| effective_header_digests(&block.headers))
                .unwrap_or_default();
            digest
                .optional_child(base_url.as_ref())
                .optional_text(openai.map(|block| block.model.as_str()))
                .optional_u64(openai.map(|block| block.timeout_ms))
                .optional_flag(openai.map(|block| block.allow_private_base_url))
                // The generated credential inputs sit behind their own tag so
                // they cannot alias a static header pair.
                .text(GENERATED_AUTH_TAG)
                .optional_flag(openai.map(openai_credential_present))
                .optional_child(auth_name.as_ref())
                .optional_child(auth_prefix.as_ref())
                .count(headers.len());
            for (name, value) in &headers {
                digest.child(name).child(value);
            }
        }
    }

    digest.finish()
}

/// Build the safe credential identity for the scope digest.
///
/// Selection follows one fixed order: the API key identifier when it is
/// nonempty, then the principal source with a nonempty subject, then the
/// SHA-256 of the authorization value when a header exists, then the fixed
/// anonymous marker. The raw authorization value is never returned.
///
/// The result is a digest input only. It is hashed into the scope digest and
/// never rendered into a key, a log line, a metric label, or an admin
/// response.
pub fn semantic_credential_identity(
    api_key_id: &str,
    principal_source: &str,
    subject: &str,
    authorization: Option<&str>,
) -> String {
    if !api_key_id.is_empty() {
        return format!("api_key_id:{api_key_id}");
    }
    if !subject.is_empty() {
        // PrincipalSource labels are closed fixed identifiers, so the two
        // parts cannot be reassociated across this separator.
        return format!("principal:{principal_source}:{subject}");
    }
    if let Some(authorization) = authorization {
        let mut hasher = Sha256::new();
        hasher.update(authorization.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        return format!("authorization:{}", hex::encode(digest));
    }
    SEMANTIC_ANONYMOUS_CREDENTIAL.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Sentinel values that must never appear in a rendered key.
    const TENANT: &str = "tenant-secret-a";
    const API_KEY_ID: &str = "sk-secret-value";
    const SUBJECT: &str = "subject-secret-a";
    const HEADER_NAME: &str = "X-Secret-Embedding-Route";
    const HEADER_VALUE: &str = "header-secret-value";
    const PROMPT: &str = "refund policy";
    const BASE_URL: &str = "https://private.example/v1";

    static CONTEXT_DIGEST: [u8; 32] = [0x11; 32];
    static CONFIG_DIGEST: [u8; 32] = [0x22; 32];
    static POLICY_DIGEST: [u8; 32] = [0x33; 32];

    fn base_input() -> SemanticNamespaceInput<'static> {
        SemanticNamespaceInput {
            origin_route: "*.example.com",
            request_host: "api.example.com",
            tenant_id: TENANT,
            credential_identity: "api_key_id:sk-secret-value",
            requested_model: "gpt-4o-mini",
            api_surface: "openai.chat",
            request_context_digest: &CONTEXT_DIGEST,
            embedding_identity: "openai:text-embedding-3-small",
            embedding_dimensions: 1536,
            semantic_config_digest: &CONFIG_DIGEST,
            response_policy_digest: &POLICY_DIGEST,
            schema_version: SEMANTIC_KEYSPACE_VERSION,
        }
    }

    fn base_namespace() -> SemanticNamespace {
        SemanticNamespace::derive(base_input())
    }

    fn sentinels() -> Vec<String> {
        vec![
            TENANT.to_string(),
            API_KEY_ID.to_string(),
            SUBJECT.to_string(),
            HEADER_NAME.to_string(),
            HEADER_NAME.to_ascii_lowercase(),
            HEADER_VALUE.to_string(),
            PROMPT.to_string(),
            BASE_URL.to_string(),
            "gpt-4o-mini".to_string(),
            "api.example.com".to_string(),
            "example.com".to_string(),
            "text-embedding-3-small".to_string(),
        ]
    }

    fn openai_config(api_key: Option<&str>, headers: serde_json::Value) -> EmbeddingCacheConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "source": "openai",
            "openai": {
                "base_url": BASE_URL,
                "model": "text-embedding-3-small",
                "api_key": api_key,
                "headers": headers,
            },
        }))
        .expect("openai semantic cache configuration parses")
    }

    fn base_openai_config() -> EmbeddingCacheConfig {
        openai_config(
            Some(API_KEY_ID),
            json!([[HEADER_NAME, HEADER_VALUE], ["X-Title", "sbproxy"]]),
        )
    }

    #[test]
    fn namespace_changes_with_origin() {
        let mut other = base_input();
        other.origin_route = "*.other.example.com";
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_request_host_under_the_same_wildcard_origin() {
        let mut other = base_input();
        other.request_host = "eu.example.com";
        let other = SemanticNamespace::derive(other);
        // The wildcard origin is shared, so one origin purge still reaches
        // both hosts, but a response may never cross between them.
        assert_eq!(base_namespace().origin_digest(), other.origin_digest());
        assert_ne!(base_namespace(), other);
    }

    #[test]
    fn namespace_changes_with_tenant() {
        let mut other = base_input();
        other.tenant_id = "tenant-secret-b";
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_api_key_id() {
        let left = semantic_credential_identity(API_KEY_ID, "", "", None);
        let right = semantic_credential_identity("sk-other-value", "", "", None);
        assert_ne!(left, right);

        let mut first = base_input();
        first.credential_identity = &left;
        let mut second = base_input();
        second.credential_identity = &right;
        assert_ne!(
            SemanticNamespace::derive(first),
            SemanticNamespace::derive(second)
        );
    }

    #[test]
    fn namespace_changes_with_principal_subject_fallback() {
        // An empty API key identifier falls through to the principal source
        // and subject.
        let left = semantic_credential_identity("", "oidc", SUBJECT, None);
        let right = semantic_credential_identity("", "oidc", "subject-secret-b", None);
        let source_change = semantic_credential_identity("", "mtls", SUBJECT, None);
        assert_ne!(left, right);
        assert_ne!(left, source_change);

        let mut first = base_input();
        first.credential_identity = &left;
        let mut second = base_input();
        second.credential_identity = &right;
        assert_ne!(
            SemanticNamespace::derive(first),
            SemanticNamespace::derive(second)
        );
    }

    #[test]
    fn namespace_changes_with_unnamed_authorization_digest() {
        let left = semantic_credential_identity("", "", "", Some("Bearer sk-secret-value"));
        let right = semantic_credential_identity("", "", "", Some("Bearer sk-other-value"));
        let anonymous = semantic_credential_identity("", "", "", None);
        assert_ne!(left, right);
        assert_ne!(left, anonymous);
        assert_eq!(anonymous, SEMANTIC_ANONYMOUS_CREDENTIAL);
        // The raw authorization value never survives the helper.
        assert!(!left.contains(API_KEY_ID));
        assert!(!left.contains("Bearer"));

        let mut first = base_input();
        first.credential_identity = &left;
        let mut second = base_input();
        second.credential_identity = &right;
        assert_ne!(
            SemanticNamespace::derive(first),
            SemanticNamespace::derive(second)
        );
    }

    #[test]
    fn namespace_changes_with_requested_model() {
        let mut other = base_input();
        other.requested_model = "gpt-4o";
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_api_surface() {
        let mut other = base_input();
        other.api_surface = "anthropic.messages";
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_request_context() {
        static OTHER_CONTEXT: [u8; 32] = [0x44; 32];
        let mut other = base_input();
        other.request_context_digest = &OTHER_CONTEXT;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_embedding_model() {
        let mut other = base_input();
        other.embedding_identity = "openai:text-embedding-3-large";
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_embedding_dimensions() {
        let mut other = base_input();
        other.embedding_dimensions = 3072;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_semantic_configuration() {
        static OTHER_CONFIG: [u8; 32] = [0x55; 32];
        let mut other = base_input();
        other.semantic_config_digest = &OTHER_CONFIG;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_static_action_policy() {
        // The response policy digest carries the static action policy, so a
        // guardrail, provider, or response shaping edit lands here.
        static OTHER_POLICY: [u8; 32] = [0x66; 32];
        let mut other = base_input();
        other.response_policy_digest = &OTHER_POLICY;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_governed_policy_revision() {
        // The same digest slot also carries the request pinned governed
        // revision, so a governed key policy change fences replay.
        static REVISED_POLICY: [u8; 32] = [0x77; 32];
        let mut other = base_input();
        other.response_policy_digest = &REVISED_POLICY;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_changes_with_schema_version() {
        let mut other = base_input();
        other.schema_version = SEMANTIC_KEYSPACE_VERSION + 1;
        assert_ne!(base_namespace(), SemanticNamespace::derive(other));
    }

    #[test]
    fn namespace_is_stable_across_openai_api_key_rotation() {
        let rotated = openai_config(
            Some("sk-rotated-value"),
            json!([[HEADER_NAME, HEADER_VALUE], ["X-Title", "sbproxy"]]),
        );
        let first = semantic_configuration_digest(&base_openai_config());
        let second = semantic_configuration_digest(&rotated);
        assert_eq!(first, second);

        let mut left = base_input();
        left.semantic_config_digest = &first;
        let mut right = base_input();
        right.semantic_config_digest = &second;
        assert_eq!(
            SemanticNamespace::derive(left),
            SemanticNamespace::derive(right)
        );
    }

    #[test]
    fn namespace_changes_with_static_embedding_header_behavior() {
        let changed = openai_config(
            Some(API_KEY_ID),
            json!([[HEADER_NAME, "header-other-value"], ["X-Title", "sbproxy"]]),
        );
        let first = semantic_configuration_digest(&base_openai_config());
        let second = semantic_configuration_digest(&changed);
        assert_ne!(first, second);

        let mut left = base_input();
        left.semantic_config_digest = &first;
        let mut right = base_input();
        right.semantic_config_digest = &second;
        assert_ne!(
            SemanticNamespace::derive(left),
            SemanticNamespace::derive(right)
        );
    }

    #[test]
    fn semantic_configuration_changes_with_backend_threshold_lsh_model_endpoint_or_local_path() {
        let base: EmbeddingCacheConfig = serde_json::from_value(json!({
            "enabled": true,
            "source": "sidecar",
            "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
        }))
        .expect("sidecar semantic cache configuration parses");
        let baseline = semantic_configuration_digest(&base);

        let variants = vec![
            json!({
                "enabled": true, "backend": "redis", "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "threshold": 0.9, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "ttl_secs": 120, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "max_entries": 4096, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "max_response_bytes": 65536, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "lsh": {"tables": 4}, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "lsh": {"planes": 8}, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "lsh": {"candidates_per_bucket": 64}, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "lsh": {"seed": "other-seed"}, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "minilm"},
            }),
            json!({
                "enabled": true, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9440", "model": "other-model"},
            }),
            json!({
                "enabled": true, "source": "sidecar",
                "sidecar": {"endpoint": "http://127.0.0.1:9441", "model": "minilm"},
            }),
            json!({
                "enabled": true, "source": "inprocess",
                "inprocess": {"model": "minilm", "model_path": "/models/a.onnx"},
            }),
            json!({
                "enabled": true, "source": "inprocess",
                "inprocess": {"model": "minilm", "model_path": "/models/b.onnx"},
            }),
        ];

        let mut digests = vec![baseline];
        for variant in variants {
            let config: EmbeddingCacheConfig =
                serde_json::from_value(variant).expect("variant parses");
            let digest = semantic_configuration_digest(&config);
            assert!(
                !digests.contains(&digest),
                "each behavior bearing field must produce a new namespace"
            );
            digests.push(digest);
        }
    }

    #[test]
    fn semantic_configuration_ignores_openai_api_key_rotation() {
        let first = semantic_configuration_digest(&openai_config(Some(API_KEY_ID), json!([])));
        let second =
            semantic_configuration_digest(&openai_config(Some("sk-rotated-value"), json!([])));
        assert_eq!(first, second);
    }

    #[test]
    fn semantic_configuration_changes_when_openai_api_key_presence_changes() {
        let present = semantic_configuration_digest(&openai_config(Some(API_KEY_ID), json!([])));
        let absent = semantic_configuration_digest(&openai_config(None, json!([])));
        let empty = semantic_configuration_digest(&openai_config(Some(""), json!([])));
        assert_ne!(present, absent);
        // An empty key injects no header, exactly as the request builder
        // decides, so it shares the absent namespace.
        assert_eq!(absent, empty);
    }

    #[test]
    fn semantic_configuration_changes_with_auth_header_or_prefix() {
        let base: EmbeddingCacheConfig = serde_json::from_value(json!({
            "enabled": true, "source": "openai",
            "openai": {"base_url": BASE_URL, "api_key": API_KEY_ID},
        }))
        .expect("openai configuration parses");
        let renamed: EmbeddingCacheConfig = serde_json::from_value(json!({
            "enabled": true, "source": "openai",
            "openai": {"base_url": BASE_URL, "api_key": API_KEY_ID, "auth_header": "api-key"},
        }))
        .expect("openai configuration parses");
        let reprefixed: EmbeddingCacheConfig = serde_json::from_value(json!({
            "enabled": true, "source": "openai",
            "openai": {"base_url": BASE_URL, "api_key": API_KEY_ID, "auth_prefix": ""},
        }))
        .expect("openai configuration parses");

        let baseline = semantic_configuration_digest(&base);
        assert_ne!(baseline, semantic_configuration_digest(&renamed));
        assert_ne!(baseline, semantic_configuration_digest(&reprefixed));
    }

    #[test]
    fn semantic_configuration_changes_with_static_header_name_or_value() {
        let base = openai_config(None, json!([[HEADER_NAME, HEADER_VALUE]]));
        let renamed = openai_config(None, json!([["X-Other-Route", HEADER_VALUE]]));
        let revalued = openai_config(None, json!([[HEADER_NAME, "header-other-value"]]));
        let baseline = semantic_configuration_digest(&base);
        assert_ne!(baseline, semantic_configuration_digest(&renamed));
        assert_ne!(baseline, semantic_configuration_digest(&revalued));
    }

    #[test]
    fn semantic_configuration_canonicalizes_distinct_static_header_order_and_name_case() {
        let low = HEADER_NAME.to_ascii_lowercase();
        let one = openai_config(None, json!([[HEADER_NAME, HEADER_VALUE], ["X-Title", "s"]]));
        let two = openai_config(None, json!([["X-Title", "s"], [HEADER_NAME, HEADER_VALUE]]));
        let three = openai_config(None, json!([[low, HEADER_VALUE], ["x-title", "s"]]));
        let baseline = semantic_configuration_digest(&one);
        assert_eq!(baseline, semantic_configuration_digest(&two));
        assert_eq!(baseline, semantic_configuration_digest(&three));
    }

    #[test]
    fn semantic_configuration_changes_when_duplicate_header_order_changes_the_final_value() {
        let other = "header-other-value";
        let one = openai_config(
            None,
            json!([[HEADER_NAME, HEADER_VALUE], [HEADER_NAME, other]]),
        );
        let two = openai_config(
            None,
            json!([[HEADER_NAME, other], [HEADER_NAME, HEADER_VALUE]]),
        );
        assert_ne!(
            semantic_configuration_digest(&one),
            semantic_configuration_digest(&two)
        );
    }

    #[test]
    fn semantic_configuration_never_renders_static_header_names_or_values() {
        let digest = semantic_configuration_digest(&base_openai_config());
        let rendered = hex::encode(digest);
        for sentinel in sentinels() {
            assert!(
                !rendered.contains(&hex::encode(sentinel.as_bytes())),
                "configuration digest must not carry raw configuration text"
            );
        }
        assert!(!format!("{digest:?}").contains(HEADER_VALUE));
    }

    #[test]
    fn fixed_namespace_prompt_and_key_fixture_matches_the_v2_byte_encoding() {
        // Independent transcription of the documented v2 field encoding:
        // domain bytes, one zero byte, then each field as a 64 bit big endian
        // length, the field bytes, and one zero byte.
        fn encode(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(domain);
            bytes.push(0);
            for field in fields {
                bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
                bytes.extend_from_slice(field);
                bytes.push(0);
            }
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.finalize().into()
        }

        let origin = encode(b"sbproxy-semcache-origin-v2", &[b"*.example.com"]);
        let scope = encode(
            b"sbproxy-semcache-scope-v2",
            &[TENANT.as_bytes(), b"api_key_id:sk-secret-value"],
        );
        let compatibility = encode(
            b"sbproxy-semcache-compat-v2",
            &[
                b"api.example.com",
                b"gpt-4o-mini",
                b"openai.chat",
                &CONTEXT_DIGEST,
                b"openai:text-embedding-3-small",
                &1536u64.to_be_bytes(),
                &CONFIG_DIGEST,
                &POLICY_DIGEST,
                &2u16.to_be_bytes(),
            ],
        );
        let prompt = encode(b"sbproxy-semcache-prompt-v2", &[PROMPT.as_bytes()]);

        let namespace = base_namespace();
        assert_eq!(namespace.origin_digest(), origin);
        assert_eq!(semantic_origin_route_digest("*.example.com"), origin);
        assert_eq!(semantic_prompt_digest(PROMPT), prompt);
        assert_eq!(
            namespace.namespace_prefix(),
            format!(
                "sbproxy:semcache:v2:o:{}:s:{}:c:{}:",
                hex::encode(origin),
                hex::encode(scope),
                hex::encode(compatibility),
            )
        );
        assert_eq!(
            semantic_entry_key(&namespace, &prompt),
            format!(
                "sbproxy:semcache:v2:o:{}:s:{}:c:{}:entry:{}",
                hex::encode(origin),
                hex::encode(scope),
                hex::encode(compatibility),
                hex::encode(prompt),
            )
        );
    }

    /// Characters the fixed key grammar is allowed to contain.
    fn is_key_character(character: char) -> bool {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == ':'
    }

    /// Every string one entry renders, for the secret absence sweeps.
    fn rendered_keys(namespace: &SemanticNamespace, keys: &SemanticEntryKeys) -> Vec<String> {
        let prompt = semantic_prompt_digest(PROMPT);
        let mut rendered = vec![
            namespace.origin_prefix(),
            namespace.namespace_prefix(),
            keys.entry_key.clone(),
        ];
        for index in &keys.bucket_indexes {
            rendered.push(index.manifest_key.clone());
            rendered.push(index.member_prefix.clone());
            rendered.push(index.routing_key.clone());
            rendered.push(index.member_key(&prompt));
        }
        rendered
    }

    #[test]
    fn keys_contain_only_fixed_labels_and_lowercase_hex() {
        let namespace = base_namespace();
        let prompt = semantic_prompt_digest(PROMPT);
        let buckets = [
            SemanticBucket { table: 0, value: 0 },
            SemanticBucket {
                table: 10,
                value: 0x0123_4567_89ab_cdef,
            },
        ];
        let keys = semantic_entry_keys(&namespace, &prompt, &buckets);

        for key in rendered_keys(&namespace, &keys) {
            assert!(
                key.chars().all(is_key_character),
                "key {key} must contain only fixed lowercase labels and hex"
            );
            assert!(key.starts_with("sbproxy:semcache:v2:o:"));
        }
        let first = &keys.bucket_indexes[0].manifest_key;
        let second = &keys.bucket_indexes[1].manifest_key;
        assert!(first.ends_with("index:t:00:b:0000000000000000"));
        assert!(second.ends_with("index:t:0a:b:0123456789abcdef"));
    }

    #[test]
    fn keys_do_not_contain_any_raw_identity_or_prompt_value() {
        let namespace = base_namespace();
        let prompt = semantic_prompt_digest(PROMPT);
        let buckets = [SemanticBucket {
            table: 3,
            value: 42,
        }];
        let keys = semantic_entry_keys(&namespace, &prompt, &buckets);

        let mut rendered = rendered_keys(&namespace, &keys);
        rendered.push(format!("{namespace:?}"));
        rendered.push(format!("{keys:?}"));

        for value in &rendered {
            for sentinel in sentinels() {
                assert!(
                    !value.contains(&sentinel),
                    "rendered value must not carry {sentinel}"
                );
            }
        }
    }

    #[test]
    fn origin_and_namespace_prefixes_select_only_their_intended_scope() {
        let namespace = base_namespace();
        let prompt = semantic_prompt_digest(PROMPT);

        let mut other_host = base_input();
        other_host.request_host = "eu.example.com";
        let other_host = SemanticNamespace::derive(other_host);

        let mut other_origin = base_input();
        other_origin.origin_route = "*.other.example.com";
        let other_origin = SemanticNamespace::derive(other_origin);

        let key = semantic_entry_key(&namespace, &prompt);
        let other_host_key = semantic_entry_key(&other_host, &prompt);
        let other_origin_key = semantic_entry_key(&other_origin, &prompt);

        assert!(key.starts_with(&namespace.origin_prefix()));
        assert!(key.starts_with(&namespace.namespace_prefix()));
        // One wildcard origin purge reaches every concrete host it matched.
        assert!(other_host_key.starts_with(&namespace.origin_prefix()));
        // A namespace scan never crosses into a different compatibility fence.
        assert!(!other_host_key.starts_with(&namespace.namespace_prefix()));
        assert!(!other_origin_key.starts_with(&namespace.origin_prefix()));

        let origin_prefix = namespace.origin_prefix();
        assert_eq!(
            origin_prefix,
            semantic_origin_prefix(&namespace.origin_digest())
        );
        assert!(namespace.namespace_prefix().starts_with(&origin_prefix));
    }

    #[test]
    fn entry_key_rebuilds_from_a_valid_prompt_digest() {
        let namespace = base_namespace();
        let prompt = semantic_prompt_digest(PROMPT);
        let keys = semantic_entry_keys(&namespace, &prompt, &[]);
        assert!(keys.bucket_indexes.is_empty());
        assert_eq!(keys.entry_key, semantic_entry_key(&namespace, &prompt));
        assert_ne!(
            keys.entry_key,
            semantic_entry_key(&namespace, &semantic_prompt_digest("refund policies"))
        );
    }

    #[test]
    fn origin_and_request_host_case_and_one_trailing_dot_normalize_identically() {
        let mut normalized = base_input();
        normalized.origin_route = "*.Example.COM.";
        normalized.request_host = "API.Example.com.";
        assert_eq!(base_namespace(), SemanticNamespace::derive(normalized));

        // Only one trailing dot is removed, so a second dot is a different name.
        let mut doubled = base_input();
        doubled.request_host = "api.example.com..";
        assert_ne!(base_namespace(), SemanticNamespace::derive(doubled));
    }
}
