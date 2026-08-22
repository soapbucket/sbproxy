//! Bounded process-local state shared by replica-aware routing strategies.

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PREFIX_DIGEST_DOMAIN: &[u8] = b"sbproxy.prefix-affinity.v1\0";
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const TOKEN_WINDOW_NANOS: u64 = 60 * NANOS_PER_SECOND;

/// Maximum canonical prompt-prefix bytes included in an affinity digest.
pub const MAX_NORMALIZED_PREFIX_BYTES: usize = 1_024;

/// Default prefix-holder lifetime of five minutes.
pub const DEFAULT_PREFIX_TTL_SECS: u64 = 300;

/// Default maximum number of remembered prefixes for each provider.
pub const DEFAULT_MAX_PREFIXES_PER_PROVIDER: usize = 1_024;

/// Opaque SHA-256 identity for the stable prompt prefix used by replica routing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixDigest([u8; 32]);

impl PrefixDigest {
    /// Borrow the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render the digest as canonical lowercase hexadecimal.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for PrefixDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrefixDigest(<digest>)")
    }
}

impl fmt::Display for PrefixDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Bounds for the process-local prefix-affinity directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PrefixAffinityConfig {
    /// Seconds a recorded holder remains live.
    pub ttl_secs: u64,
    /// Maximum prefix digests retained independently for each provider.
    pub max_prefixes_per_provider: usize,
}

impl Default for PrefixAffinityConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_PREFIX_TTL_SECS,
            max_prefixes_per_provider: DEFAULT_MAX_PREFIXES_PER_PROVIDER,
        }
    }
}

impl PrefixAffinityConfig {
    /// Reject bounds that would disable expiry or make an LRU unconstructable.
    pub fn validate(&self) -> Result<(), PrefixAffinityConfigError> {
        if self.ttl_secs == 0 {
            return Err(PrefixAffinityConfigError::ZeroTtl);
        }
        if self.max_prefixes_per_provider == 0 {
            return Err(PrefixAffinityConfigError::ZeroCapacity);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PrefixAffinityConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
            ttl_secs: u64,
            max_prefixes_per_provider: usize,
        }

        impl Default for Wire {
            fn default() -> Self {
                Self {
                    ttl_secs: DEFAULT_PREFIX_TTL_SECS,
                    max_prefixes_per_provider: DEFAULT_MAX_PREFIXES_PER_PROVIDER,
                }
            }
        }

        let wire = Wire::deserialize(deserializer)?;
        let config = Self {
            ttl_secs: wire.ttl_secs,
            max_prefixes_per_provider: wire.max_prefixes_per_provider,
        };
        config.validate().map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

/// Invalid prefix-affinity state bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrefixAffinityConfigError {
    /// A zero TTL would expire every recorded holder immediately.
    #[error("prefix affinity ttl_secs must be greater than zero")]
    ZeroTtl,
    /// A zero per-provider capacity cannot retain a holder.
    #[error("prefix affinity max_prefixes_per_provider must be greater than zero")]
    ZeroCapacity,
}

/// Default cache-affinity lease lifetime of five minutes.
pub(crate) const DEFAULT_CACHE_AFFINITY_TTL_SECS: u64 = 300;

/// Default maximum number of remembered leases for each provider.
pub(crate) const DEFAULT_MAX_CACHE_KEYS_PER_PROVIDER: usize = 1_024;

/// Domain separator for the caller-scoped prompt-cache lease identity.
const CACHE_AFFINITY_KEY_DOMAIN: &[u8] = b"sbproxy.cache-affinity.v1";

/// Opaque SHA-256 identity for one caller's prompt-cache lease.
///
/// Derived from [`CacheAffinityKeyInput`], which mixes the caller-chosen
/// cache key with the tenant, the credential, the origin, and the API
/// surface. The caller controls only one of those five fields, so two
/// tenants that send the same string never share a lease.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheAffinityKey([u8; 32]);

/// Identity inputs for one prompt-cache lease.
///
/// Every field is hashed. Nothing here is retained in cleartext, logged, or
/// rendered, so a caller-chosen key cannot leak out of the routing table.
#[derive(Clone, Copy, Debug)]
pub struct CacheAffinityKeyInput<'a> {
    /// Resolved tenant identifier.
    pub tenant_id: &'a str,
    /// Safe credential identity, normally the API key id.
    pub credential_identity: &'a str,
    /// Origin the request was matched to.
    pub origin: &'a str,
    /// API surface label the request arrived on.
    ///
    /// Included because provider prompt caches are per endpoint: the same
    /// key sent to `/v1/chat/completions` and to `/v1/responses` names two
    /// separate upstream caches, so it has to name two separate leases.
    pub api_surface: &'a str,
    /// The caller-chosen cache key, verbatim.
    pub caller_key: &'a str,
}

impl CacheAffinityKey {
    /// Derive a lease identity from one complete scope.
    #[must_use]
    pub fn derive(input: CacheAffinityKeyInput<'_>) -> Self {
        // Same length-delimited field encoding the semantic cache uses for
        // its namespace digests, under a distinct domain label, so a digest
        // from one feature can never collide with a digest from the other.
        let mut digest =
            crate::semantic_cache::identity::FieldDigest::new(CACHE_AFFINITY_KEY_DOMAIN);
        digest
            .text(input.tenant_id)
            .text(input.credential_identity)
            .text(input.origin)
            .text(input.api_surface)
            .text(input.caller_key);
        Self(digest.finish())
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render the digest as canonical lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CacheAffinityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheAffinityKey(<digest>)")
    }
}

impl fmt::Display for CacheAffinityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Route a caller's repeated requests back to the provider that already
/// holds their warm prompt cache.
///
/// When a request carries a prompt cache key (`prompt_cache_key`, or `user`
/// when that is absent), the gateway remembers which provider served it and
/// prefers that provider for the caller's next request with the same key. It
/// is a preference, never a pin: an unhealthy, ejected, or policy-ineligible
/// provider is still skipped, and a request whose resolved model changed
/// starts a fresh lease.
///
/// The lease is scoped to the tenant, the credential, the origin, and the API
/// surface, so one caller's key can never steer another's routing. Nothing
/// writes the key; a request that does not send one is routed by the
/// configured strategy alone.
///
/// State lives in this gateway process only. It does not survive a restart
/// and is not shared between replicas, so behind a load balancer the hit
/// rate is per instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CacheAffinityConfig {
    /// Seconds a recorded lease remains live. Defaults to 300.
    ///
    /// Set this near the provider's own prompt-cache lifetime. A lease that
    /// outlives the upstream cache steers traffic for no benefit.
    pub ttl_secs: u64,
    /// Maximum leases retained for each provider. Defaults to 1024.
    ///
    /// The least recently used lease is dropped when the bound is reached.
    pub max_keys_per_provider: usize,
}

impl Default for CacheAffinityConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_CACHE_AFFINITY_TTL_SECS,
            max_keys_per_provider: DEFAULT_MAX_CACHE_KEYS_PER_PROVIDER,
        }
    }
}

impl CacheAffinityConfig {
    /// Reject bounds that would disable expiry or make an LRU unconstructable.
    pub fn validate(&self) -> Result<(), CacheAffinityConfigError> {
        if self.ttl_secs == 0 {
            return Err(CacheAffinityConfigError::ZeroTtl);
        }
        if self.max_keys_per_provider == 0 {
            return Err(CacheAffinityConfigError::ZeroCapacity);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CacheAffinityConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
            ttl_secs: u64,
            max_keys_per_provider: usize,
        }

        impl Default for Wire {
            fn default() -> Self {
                Self {
                    ttl_secs: DEFAULT_CACHE_AFFINITY_TTL_SECS,
                    max_keys_per_provider: DEFAULT_MAX_CACHE_KEYS_PER_PROVIDER,
                }
            }
        }

        let wire = Wire::deserialize(deserializer)?;
        let config = Self {
            ttl_secs: wire.ttl_secs,
            max_keys_per_provider: wire.max_keys_per_provider,
        };
        config.validate().map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

/// Invalid cache-affinity state bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CacheAffinityConfigError {
    /// A zero TTL would expire every recorded lease immediately.
    #[error("cache affinity ttl_secs must be greater than zero")]
    ZeroTtl,
    /// A zero per-provider capacity cannot retain a lease.
    #[error("cache affinity max_keys_per_provider must be greater than zero")]
    ZeroCapacity,
}

/// Outcome of one cache-affinity lease lookup.
///
/// Every variant except [`Self::Hit`] leaves the configured strategy's own
/// pick in place. The variants exist so the operator can tell a cold table
/// apart from a lease whose holder was ejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheAffinityLookup {
    /// A live lease named an eligible provider serving the same model.
    Hit(usize),
    /// No live lease for this key on any provider.
    Miss,
    /// A live lease exists, but its holder is not in the eligible set.
    Ineligible,
    /// A lease existed for a different resolved model and was dropped.
    ModelChanged,
}

/// Build a stable affinity identity from the leading instructions and first
/// user turn in a translated JSON request.
///
/// Later conversation turns and unrelated request fields are deliberately
/// ignored. The selected messages are canonicalized, capped without splitting
/// a UTF-8 code point, namespaced by the resolved model or deployment, and
/// hashed with a versioned domain separator.
pub fn normalize_prefix(body: &Value, namespace: &str) -> Option<PrefixDigest> {
    let messages = body.get("messages")?.as_array()?;
    let first_user = messages
        .iter()
        .position(|message| message.get("role").and_then(Value::as_str) == Some("user"))?;

    let mut selected = messages[..first_user]
        .iter()
        .take_while(|message| {
            matches!(
                message.get("role").and_then(Value::as_str),
                Some("system" | "developer")
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    selected.push(messages[first_user].clone());

    let canonical = serde_json_canonicalizer::to_vec(&Value::Array(selected)).ok()?;
    let canonical = std::str::from_utf8(&canonical).ok()?;
    let canonical = truncate_utf8(canonical, MAX_NORMALIZED_PREFIX_BYTES);

    let mut hasher = Sha256::new();
    hasher.update(PREFIX_DIGEST_DOMAIN);
    hasher.update((namespace.len() as u64).to_be_bytes());
    hasher.update(namespace.as_bytes());
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical.as_bytes());
    Some(PrefixDigest(hasher.finalize().into()))
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    let mut end = value.len().min(max_bytes);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

trait MonotonicClock: Send + Sync {
    fn now_nanos(&self) -> u64;
}

struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemClock {
    fn now_nanos(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

struct ReplicaRoutingInner {
    holders: Vec<LruCache<PrefixDigest, u64>>,
    /// Caller-keyed prompt-cache leases, one bounded table per provider.
    /// Empty unless the origin configured `cache_affinity`, so an origin
    /// that did not ask for the feature allocates nothing for it.
    cache_holders: Vec<LruCache<CacheAffinityKey, (u64, String)>>,
    recent_tokens: Vec<u64>,
    token_window_started_at: u64,
}

impl ReplicaRoutingInner {
    fn rotate_token_window(&mut self, now: u64) {
        if now.saturating_sub(self.token_window_started_at) >= TOKEN_WINDOW_NANOS {
            self.recent_tokens.fill(0);
            self.token_window_started_at = now;
        }
    }
}

/// Bounded local holder directory and recent-token load shared by replica
/// routing strategies.
pub struct ReplicaRoutingState {
    config: PrefixAffinityConfig,
    ttl_nanos: u64,
    /// `None` until an origin enables caller-keyed cache affinity.
    cache_config: Option<CacheAffinityConfig>,
    cache_ttl_nanos: u64,
    clock: Arc<dyn MonotonicClock>,
    inner: Mutex<ReplicaRoutingInner>,
}

impl fmt::Debug for ReplicaRoutingState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let provider_count = self.inner.lock().holders.len();
        formatter
            .debug_struct("ReplicaRoutingState")
            .field("config", &self.config)
            .field("provider_count", &provider_count)
            .finish_non_exhaustive()
    }
}

impl ReplicaRoutingState {
    /// Create empty state for a fixed number of provider indices.
    pub fn new(
        provider_count: usize,
        config: PrefixAffinityConfig,
    ) -> Result<Self, PrefixAffinityConfigError> {
        Self::new_with_clock(provider_count, config, Arc::new(SystemClock::new()))
    }

    fn new_with_clock(
        provider_count: usize,
        config: PrefixAffinityConfig,
        clock: Arc<dyn MonotonicClock>,
    ) -> Result<Self, PrefixAffinityConfigError> {
        config.validate()?;
        let capacity = NonZeroUsize::new(config.max_prefixes_per_provider)
            .ok_or(PrefixAffinityConfigError::ZeroCapacity)?;
        let now = clock.now_nanos();
        Ok(Self {
            config,
            ttl_nanos: config.ttl_secs.saturating_mul(NANOS_PER_SECOND),
            cache_config: None,
            cache_ttl_nanos: 0,
            clock,
            inner: Mutex::new(ReplicaRoutingInner {
                holders: (0..provider_count)
                    .map(|_| LruCache::new(capacity))
                    .collect(),
                cache_holders: Vec::new(),
                recent_tokens: vec![0; provider_count],
                token_window_started_at: now,
            }),
        })
    }

    /// Select the least-loaded eligible provider known to hold `prefix`.
    ///
    /// The caller supplies the final enabled and policy-eligible indices.
    /// Missing, expired, out-of-range, and ineligible holders are never
    /// returned.
    pub fn select_holder(
        &self,
        prefix: &PrefixDigest,
        eligible_provider_indices: &[usize],
    ) -> Option<usize> {
        let now = self.clock.now_nanos();
        let (selected, ttl_evictions) = {
            let mut inner = self.inner.lock();
            inner.rotate_token_window(now);
            let mut holders = Vec::new();
            let mut ttl_evictions = 0;

            for &provider_idx in eligible_provider_indices {
                if holders.contains(&provider_idx) {
                    continue;
                }
                let Some(provider_holders) = inner.holders.get_mut(provider_idx) else {
                    continue;
                };
                let Some(recorded_at) = provider_holders.get(prefix).copied() else {
                    continue;
                };
                if now.saturating_sub(recorded_at) >= self.ttl_nanos {
                    provider_holders.pop(prefix);
                    ttl_evictions += 1;
                    continue;
                }
                holders.push(provider_idx);
            }

            let selected = holders
                .into_iter()
                .min_by_key(|provider_idx| inner.recent_tokens[*provider_idx]);
            (selected, ttl_evictions)
        };

        for _ in 0..ttl_evictions {
            crate::ai_metrics::record_prefix_affinity_eviction("ttl");
        }
        selected
    }

    /// Select the lowest recent-token load from the eligible provider indices.
    ///
    /// Exact load ties rotate deterministically in caller-supplied order using
    /// `tie_cursor`, which lets the owning router reuse its round-robin cursor.
    pub fn least_loaded(
        &self,
        eligible_provider_indices: &[usize],
        tie_cursor: u64,
    ) -> Option<usize> {
        let now = self.clock.now_nanos();
        let mut inner = self.inner.lock();
        inner.rotate_token_window(now);

        let mut eligible = Vec::new();
        for &provider_idx in eligible_provider_indices {
            if provider_idx < inner.recent_tokens.len() && !eligible.contains(&provider_idx) {
                eligible.push(provider_idx);
            }
        }
        let minimum = eligible
            .iter()
            .map(|provider_idx| inner.recent_tokens[*provider_idx])
            .min()?;
        let tied = eligible
            .into_iter()
            .filter(|provider_idx| inner.recent_tokens[*provider_idx] == minimum)
            .collect::<Vec<_>>();
        if tied.len() == 1 {
            return tied.first().copied();
        }

        Some(tied[(tie_cursor % tied.len() as u64) as usize])
    }

    /// Record that an accepted response left `provider_idx` holding `prefix`.
    ///
    /// Re-recording refreshes both TTL and recency. A new entry beyond the
    /// provider's configured capacity evicts its least recently used digest.
    pub fn record_prefix(&self, provider_idx: usize, prefix: PrefixDigest) {
        let now = self.clock.now_nanos();
        let capacity_evicted = {
            let mut inner = self.inner.lock();
            let Some(provider_holders) = inner.holders.get_mut(provider_idx) else {
                return;
            };
            provider_holders
                .push(prefix, now)
                .is_some_and(|(evicted, _)| evicted != prefix)
        };
        if capacity_evicted {
            crate::ai_metrics::record_prefix_affinity_eviction("capacity");
        }
    }

    /// Arm the caller-keyed prompt-cache lease table for `provider_count`
    /// providers.
    ///
    /// Called once, at router construction, when the origin configures
    /// `cache_affinity`. Leaving it uncalled keeps the tables empty and every
    /// lookup an immediate [`CacheAffinityLookup::Miss`].
    pub fn enable_cache_affinity(
        &mut self,
        provider_count: usize,
        config: CacheAffinityConfig,
    ) -> Result<(), CacheAffinityConfigError> {
        config.validate()?;
        let capacity = NonZeroUsize::new(config.max_keys_per_provider)
            .ok_or(CacheAffinityConfigError::ZeroCapacity)?;
        self.cache_config = Some(config);
        self.cache_ttl_nanos = config.ttl_secs.saturating_mul(NANOS_PER_SECOND);
        self.inner.lock().cache_holders = (0..provider_count)
            .map(|_| LruCache::new(capacity))
            .collect();
        Ok(())
    }

    /// Whether caller-keyed prompt-cache affinity is armed.
    #[must_use]
    pub fn cache_affinity_enabled(&self) -> bool {
        self.cache_config.is_some()
    }

    /// Look up the provider holding this caller's warm prompt cache.
    ///
    /// Expired leases and leases recorded against a different resolved model
    /// are dropped as they are found, so the table self-heals without a
    /// sweep. A live lease whose holder is missing from
    /// `eligible_provider_indices` is reported rather than returned: the
    /// caller keeps the strategy's own pick, and the operator gets to see
    /// that affinity lost to health or policy rather than to a cold table.
    ///
    /// When more than one provider holds a live lease for the key, which
    /// happens after the first holder is ejected and a second one serves the
    /// caller, the most recently recorded eligible holder wins because its
    /// upstream cache is the warmer of the two.
    pub fn select_cache_holder(
        &self,
        key: &CacheAffinityKey,
        resolved_model: &str,
        eligible_provider_indices: &[usize],
    ) -> CacheAffinityLookup {
        if self.cache_config.is_none() {
            return CacheAffinityLookup::Miss;
        }
        let now = self.clock.now_nanos();
        let (lookup, ttl_evictions, model_evictions) = {
            let mut inner = self.inner.lock();
            let mut ttl_evictions = 0usize;
            let mut model_evictions = 0usize;
            let mut live: Vec<(usize, u64)> = Vec::new();

            for provider_idx in 0..inner.cache_holders.len() {
                let Some(table) = inner.cache_holders.get_mut(provider_idx) else {
                    continue;
                };
                let Some((recorded_at, held_model)) = table.get(key) else {
                    continue;
                };
                let recorded_at = *recorded_at;
                let model_matches = held_model.as_str() == resolved_model;
                if now.saturating_sub(recorded_at) >= self.cache_ttl_nanos {
                    table.pop(key);
                    ttl_evictions += 1;
                    continue;
                }
                if !model_matches {
                    table.pop(key);
                    model_evictions += 1;
                    continue;
                }
                live.push((provider_idx, recorded_at));
            }

            let eligible_holder = live
                .iter()
                .filter(|(provider_idx, _)| eligible_provider_indices.contains(provider_idx))
                .max_by_key(|(_, recorded_at)| *recorded_at)
                .map(|(provider_idx, _)| *provider_idx);
            let lookup = match eligible_holder {
                Some(provider_idx) => CacheAffinityLookup::Hit(provider_idx),
                None if !live.is_empty() => CacheAffinityLookup::Ineligible,
                None if model_evictions > 0 => CacheAffinityLookup::ModelChanged,
                None => CacheAffinityLookup::Miss,
            };
            (lookup, ttl_evictions, model_evictions)
        };

        for _ in 0..ttl_evictions {
            crate::ai_metrics::record_cache_affinity_eviction("ttl");
        }
        for _ in 0..model_evictions {
            crate::ai_metrics::record_cache_affinity_eviction("model_changed");
        }
        lookup
    }

    /// Record that an accepted response left `provider_idx` holding this
    /// caller's warm prompt cache for `resolved_model`.
    ///
    /// Re-recording refreshes both TTL and recency. A new lease beyond the
    /// provider's configured capacity evicts its least recently used lease.
    pub fn record_cache_holder(
        &self,
        provider_idx: usize,
        key: CacheAffinityKey,
        resolved_model: &str,
    ) {
        if self.cache_config.is_none() {
            return;
        }
        let now = self.clock.now_nanos();
        let capacity_evicted = {
            let mut inner = self.inner.lock();
            let Some(table) = inner.cache_holders.get_mut(provider_idx) else {
                return;
            };
            table
                .push(key, (now, resolved_model.to_string()))
                .is_some_and(|(evicted, _)| evicted != key)
        };
        if capacity_evicted {
            crate::ai_metrics::record_cache_affinity_eviction("capacity");
        }
    }

    /// Add observed tokens to a provider's lazy 60-second load window.
    pub fn record_tokens(&self, provider_idx: usize, tokens: u64) {
        let now = self.clock.now_nanos();
        let mut inner = self.inner.lock();
        inner.rotate_token_window(now);
        if let Some(recent_tokens) = inner.recent_tokens.get_mut(provider_idx) {
            *recent_tokens = recent_tokens.saturating_add(tokens);
        }
    }

    /// Clear every recent-token counter and begin a fresh 60-second window.
    pub fn reset_tokens(&self) {
        let now = self.clock.now_nanos();
        let mut inner = self.inner.lock();
        inner.recent_tokens.fill(0);
        inner.token_window_started_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn conversation(messages: Vec<Value>) -> Value {
        json!({ "messages": messages })
    }

    fn digest(label: &str) -> PrefixDigest {
        normalize_prefix(
            &conversation(vec![json!({"role": "user", "content": label})]),
            "model:test",
        )
        .expect("prefix")
    }

    #[derive(Debug, Default)]
    struct ManualClock {
        now_nanos: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.now_nanos.fetch_add(
                u64::try_from(duration.as_nanos()).expect("test duration fits"),
                Ordering::Relaxed,
            );
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_nanos(&self) -> u64 {
            self.now_nanos.load(Ordering::Relaxed)
        }
    }

    fn test_state(
        provider_count: usize,
        ttl_secs: u64,
        max_prefixes_per_provider: usize,
    ) -> (ReplicaRoutingState, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        let state = ReplicaRoutingState::new_with_clock(
            provider_count,
            PrefixAffinityConfig {
                ttl_secs,
                max_prefixes_per_provider,
            },
            clock.clone(),
        )
        .expect("valid test config");
        (state, clock)
    }

    #[test]
    fn normalization_ignores_turns_after_the_first_user_message() {
        let first_turn = vec![
            json!({"role": "system", "content": "Be concise."}),
            json!({"role": "developer", "content": "Return JSON."}),
            json!({"role": "user", "content": "Summarize this."}),
        ];
        let initial = conversation(first_turn.clone());
        let mut continued = first_turn;
        continued.extend([
            json!({"role": "assistant", "content": "A summary."}),
            json!({"role": "user", "content": "Make it shorter."}),
        ]);

        assert_eq!(
            normalize_prefix(&initial, "deployment:summary"),
            normalize_prefix(&conversation(continued), "deployment:summary")
        );
    }

    #[test]
    fn normalization_includes_leading_instructions_and_first_user_message() {
        let baseline = conversation(vec![
            json!({"role": "system", "content": "Be concise."}),
            json!({"role": "developer", "content": "Return JSON."}),
            json!({"role": "user", "content": "Summarize this."}),
        ]);
        let changed_developer = conversation(vec![
            json!({"role": "system", "content": "Be concise."}),
            json!({"role": "developer", "content": "Return plain text."}),
            json!({"role": "user", "content": "Summarize this."}),
        ]);
        let changed_user = conversation(vec![
            json!({"role": "system", "content": "Be concise."}),
            json!({"role": "developer", "content": "Return JSON."}),
            json!({"role": "user", "content": "Translate this."}),
        ]);

        let baseline = normalize_prefix(&baseline, "deployment:summary").expect("prefix");
        assert_ne!(
            baseline,
            normalize_prefix(&changed_developer, "deployment:summary").expect("prefix")
        );
        assert_ne!(
            baseline,
            normalize_prefix(&changed_user, "deployment:summary").expect("prefix")
        );
    }

    #[test]
    fn normalization_canonicalizes_json_object_keys() {
        let first: Value = serde_json::from_str(
            r#"{"messages":[{"role":"system","content":{"b":2,"a":1}},{"role":"user","content":[{"type":"text","text":"Hello"}]}]}"#,
        )
        .expect("fixture");
        let reordered: Value = serde_json::from_str(
            r#"{"messages":[{"content":{"a":1,"b":2},"role":"system"},{"content":[{"text":"Hello","type":"text"}],"role":"user"}]}"#,
        )
        .expect("fixture");

        assert_eq!(
            normalize_prefix(&first, "model:gpt"),
            normalize_prefix(&reordered, "model:gpt")
        );
    }

    #[test]
    fn normalization_is_domain_separated_and_namespaced() {
        let body = conversation(vec![
            json!({"role": "system", "content": "Be precise."}),
            json!({
                "role": "user",
                "content": [{"type": "text", "text": "Hello"}]
            }),
        ]);
        let digest = normalize_prefix(&body, "deployment:gpt-4o").expect("prefix");

        assert_eq!(
            digest.to_hex(),
            "278efe9d02a3a23b51962dedb2c07d8b729d88b5a714e7cb5f91e742298029b6"
        );
        assert_ne!(
            digest,
            normalize_prefix(&body, "deployment:gpt-4o-mini").expect("prefix")
        );
    }

    #[test]
    fn utf8_cap_never_splits_a_code_point() {
        let mut input = "a".repeat(MAX_NORMALIZED_PREFIX_BYTES - 1);
        input.push('🦀');
        input.push_str("tail");

        let capped = truncate_utf8(&input, MAX_NORMALIZED_PREFIX_BYTES);

        assert_eq!(capped, "a".repeat(MAX_NORMALIZED_PREFIX_BYTES - 1));
        assert!(capped.len() <= MAX_NORMALIZED_PREFIX_BYTES);
    }

    #[test]
    fn normalization_ignores_content_past_the_bounded_prefix() {
        let shared = "é".repeat(MAX_NORMALIZED_PREFIX_BYTES);
        let first = conversation(vec![json!({
            "role": "user",
            "content": format!("{shared} first tail"),
        })]);
        let second = conversation(vec![json!({
            "role": "user",
            "content": format!("{shared} second tail"),
        })]);

        assert_eq!(
            normalize_prefix(&first, "model:gpt"),
            normalize_prefix(&second, "model:gpt")
        );
    }

    #[test]
    fn normalization_preserves_content_part_order() {
        let text_then_image = conversation(vec![json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "Describe this"},
                {"type": "image_url", "image_url": {"url": "https://example.test/a.png"}}
            ],
        })]);
        let image_then_text = conversation(vec![json!({
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": "https://example.test/a.png"}},
                {"type": "text", "text": "Describe this"}
            ],
        })]);

        assert_ne!(
            normalize_prefix(&text_then_image, "model:gpt"),
            normalize_prefix(&image_then_text, "model:gpt")
        );
    }

    #[test]
    fn normalization_requires_a_first_user_message() {
        let body = conversation(vec![
            json!({"role": "system", "content": "Be precise."}),
            json!({"role": "developer", "content": "Return JSON."}),
        ]);

        assert_eq!(normalize_prefix(&body, "model:gpt"), None);
        assert_eq!(
            normalize_prefix(&json!({"prompt": "legacy"}), "model:gpt"),
            None
        );
    }

    #[test]
    fn config_has_bounded_defaults_and_rejects_zero_bounds() {
        let defaults: PrefixAffinityConfig =
            serde_json::from_value(json!({})).expect("default config");
        assert_eq!(
            defaults,
            PrefixAffinityConfig {
                ttl_secs: 300,
                max_prefixes_per_provider: 1_024,
            }
        );
        assert_eq!(defaults.validate(), Ok(()));
        assert_eq!(
            PrefixAffinityConfig {
                ttl_secs: 0,
                ..defaults
            }
            .validate(),
            Err(PrefixAffinityConfigError::ZeroTtl)
        );
        assert_eq!(
            PrefixAffinityConfig {
                max_prefixes_per_provider: 0,
                ..defaults
            }
            .validate(),
            Err(PrefixAffinityConfigError::ZeroCapacity)
        );
        assert!(serde_json::from_value::<PrefixAffinityConfig>(json!({"ttl_secs": 0})).is_err());
        assert!(serde_json::from_value::<PrefixAffinityConfig>(
            json!({"max_prefixes_per_provider": 0})
        )
        .is_err());
    }

    #[test]
    fn live_holder_wins_and_shared_token_load_breaks_holder_ties() {
        let (state, _) = test_state(3, 300, 8);
        let prefix = digest("shared prompt");
        state.record_prefix(0, prefix);
        state.record_prefix(1, prefix);
        state.record_tokens(0, 500);
        state.record_tokens(1, 10);

        assert_eq!(state.select_holder(&prefix, &[0, 1, 2]), Some(1));
        assert_eq!(state.least_loaded(&[0, 1], 0), Some(1));
    }

    #[test]
    fn ineligible_holder_is_skipped_before_least_load_fallback() {
        let (state, _) = test_state(3, 300, 8);
        let prefix = digest("held only by disabled provider");
        state.record_prefix(0, prefix);
        state.record_tokens(1, 500);
        state.record_tokens(2, 10);

        assert_eq!(state.select_holder(&prefix, &[1, 2]), None);
        assert_eq!(state.least_loaded(&[1, 2], 0), Some(2));
    }

    #[test]
    fn least_load_fallback_round_robins_only_exact_ties() {
        let (state, _) = test_state(3, 300, 8);
        state.record_tokens(0, 100);
        state.record_tokens(1, 10);
        state.record_tokens(2, 10);

        assert_eq!(state.least_loaded(&[2, 1, 0], 0), Some(2));
        assert_eq!(state.least_loaded(&[2, 1, 0], 1), Some(1));
        assert_eq!(state.least_loaded(&[2, 1, 0], 2), Some(2));
    }

    #[test]
    fn recent_tokens_rotate_lazily_after_sixty_seconds() {
        let (state, clock) = test_state(2, 300, 8);
        state.record_tokens(0, 80);
        state.record_tokens(1, 10);

        clock.advance(Duration::from_secs(59));
        assert_eq!(state.least_loaded(&[0, 1], 0), Some(1));

        clock.advance(Duration::from_secs(1));
        assert_eq!(state.least_loaded(&[0, 1], 0), Some(0));
        assert_eq!(state.least_loaded(&[0, 1], 1), Some(1));
    }

    #[test]
    fn explicit_token_reset_preserves_manual_reset_semantics() {
        let (state, _) = test_state(2, 300, 8);
        state.record_tokens(0, 80);
        state.record_tokens(1, 10);
        assert_eq!(state.least_loaded(&[0, 1], 0), Some(1));

        state.reset_tokens();

        assert_eq!(state.least_loaded(&[0, 1], 0), Some(0));
    }

    #[test]
    fn prefix_holder_expires_at_the_configured_ttl() {
        let (state, clock) = test_state(1, 300, 8);
        let prefix = digest("expiring prompt");
        state.record_prefix(0, prefix);

        clock.advance(Duration::from_secs(299));
        assert_eq!(state.select_holder(&prefix, &[0]), Some(0));

        clock.advance(Duration::from_secs(1));
        assert_eq!(state.select_holder(&prefix, &[0]), None);
        assert_eq!(state.select_holder(&prefix, &[0]), None);
    }

    #[test]
    fn prefix_capacity_evicts_the_least_recently_used_holder_per_provider() {
        let (state, _) = test_state(2, 300, 2);
        let first = digest("first");
        let second = digest("second");
        let third = digest("third");
        state.record_prefix(0, first);
        state.record_prefix(0, second);
        assert_eq!(state.select_holder(&first, &[0]), Some(0));
        state.record_prefix(0, third);

        assert_eq!(state.select_holder(&first, &[0]), Some(0));
        assert_eq!(state.select_holder(&second, &[0]), None);
        assert_eq!(state.select_holder(&third, &[0]), Some(0));

        state.record_prefix(1, second);
        assert_eq!(state.select_holder(&second, &[1]), Some(1));
    }

    #[test]
    fn unknown_provider_indices_are_ignored() {
        let (state, _) = test_state(1, 300, 2);
        let prefix = digest("unknown provider");
        state.record_prefix(9, prefix);
        state.record_tokens(9, 100);

        assert_eq!(state.select_holder(&prefix, &[9]), None);
        assert_eq!(state.least_loaded(&[9], 0), None);
        assert_eq!(state.least_loaded(&[], 0), None);
    }

    fn cache_test_state(
        provider_count: usize,
        ttl_secs: u64,
        max_keys_per_provider: usize,
    ) -> (ReplicaRoutingState, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        let mut state = ReplicaRoutingState::new_with_clock(
            provider_count,
            PrefixAffinityConfig::default(),
            clock.clone(),
        )
        .expect("valid test config");
        state
            .enable_cache_affinity(
                provider_count,
                CacheAffinityConfig {
                    ttl_secs,
                    max_keys_per_provider,
                },
            )
            .expect("valid cache affinity config");
        (state, clock)
    }

    fn cache_key(tenant: &str, caller_key: &str) -> CacheAffinityKey {
        CacheAffinityKey::derive(CacheAffinityKeyInput {
            tenant_id: tenant,
            credential_identity: "key-1",
            origin: "ai.test",
            api_surface: "chat_completions",
            caller_key,
        })
    }

    /// The security property: the caller controls one of five hashed
    /// fields. Without the tenant in the scope, a caller who guesses another
    /// tenant's cache key steers that tenant's routing.
    #[test]
    fn one_tenants_cache_key_cannot_steer_another_tenants_routing() {
        let mine = cache_key("tenant-a", "shared-string");
        let theirs = cache_key("tenant-b", "shared-string");
        assert_ne!(mine, theirs);

        let (state, _) = cache_test_state(2, 300, 8);
        state.record_cache_holder(0, mine, "gpt-4o");

        assert_eq!(
            state.select_cache_holder(&mine, "gpt-4o", &[0, 1]),
            CacheAffinityLookup::Hit(0)
        );
        assert_eq!(
            state.select_cache_holder(&theirs, "gpt-4o", &[0, 1]),
            CacheAffinityLookup::Miss,
            "a second tenant sending the same string must not inherit the lease"
        );
    }

    /// The credential, the origin, and the surface are scope too. A lease
    /// leaking across any of them is the same oracle in a smaller blast
    /// radius.
    #[test]
    fn every_scope_field_changes_the_lease_identity() {
        let base = CacheAffinityKeyInput {
            tenant_id: "tenant-a",
            credential_identity: "key-1",
            origin: "ai.test",
            api_surface: "chat_completions",
            caller_key: "session-7",
        };
        let baseline = CacheAffinityKey::derive(base);
        for altered in [
            CacheAffinityKeyInput {
                tenant_id: "tenant-b",
                ..base
            },
            CacheAffinityKeyInput {
                credential_identity: "key-2",
                ..base
            },
            CacheAffinityKeyInput {
                origin: "other.test",
                ..base
            },
            CacheAffinityKeyInput {
                api_surface: "responses",
                ..base
            },
            CacheAffinityKeyInput {
                caller_key: "session-8",
                ..base
            },
        ] {
            assert_ne!(baseline, CacheAffinityKey::derive(altered));
        }
    }

    /// A lease that outlives the model it was recorded against would pin a
    /// caller to a provider whose upstream cache holds a different prompt.
    #[test]
    fn a_resolved_model_change_invalidates_the_lease() {
        let (state, _) = cache_test_state(2, 300, 8);
        let key = cache_key("tenant-a", "session-7");
        state.record_cache_holder(0, key, "gpt-4o");

        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o-mini", &[0, 1]),
            CacheAffinityLookup::ModelChanged
        );
        // The mismatched lease is dropped rather than left to age out, so
        // the next lookup for the original model is a plain miss.
        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0, 1]),
            CacheAffinityLookup::Miss
        );
    }

    #[test]
    fn a_lease_expires_at_its_configured_ttl() {
        let (state, clock) = cache_test_state(1, 300, 8);
        let key = cache_key("tenant-a", "session-7");
        state.record_cache_holder(0, key, "gpt-4o");

        clock.advance(Duration::from_secs(299));
        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0]),
            CacheAffinityLookup::Hit(0)
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0]),
            CacheAffinityLookup::Miss
        );
    }

    /// A live lease whose holder was filtered out is a distinct outcome from
    /// a cold table, because the two ask the operator to look at different
    /// things.
    #[test]
    fn a_lease_holder_outside_the_eligible_set_is_reported_not_returned() {
        let (state, _) = cache_test_state(2, 300, 8);
        let key = cache_key("tenant-a", "session-7");
        state.record_cache_holder(1, key, "gpt-4o");

        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0]),
            CacheAffinityLookup::Ineligible
        );
        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0, 1]),
            CacheAffinityLookup::Hit(1)
        );
    }

    #[test]
    fn cache_capacity_evicts_the_least_recently_used_lease_per_provider() {
        let (state, _) = cache_test_state(1, 300, 2);
        let first = cache_key("tenant-a", "first");
        let second = cache_key("tenant-a", "second");
        let third = cache_key("tenant-a", "third");
        state.record_cache_holder(0, first, "gpt-4o");
        state.record_cache_holder(0, second, "gpt-4o");
        assert_eq!(
            state.select_cache_holder(&first, "gpt-4o", &[0]),
            CacheAffinityLookup::Hit(0)
        );
        state.record_cache_holder(0, third, "gpt-4o");

        assert_eq!(
            state.select_cache_holder(&first, "gpt-4o", &[0]),
            CacheAffinityLookup::Hit(0)
        );
        assert_eq!(
            state.select_cache_holder(&second, "gpt-4o", &[0]),
            CacheAffinityLookup::Miss
        );
    }

    /// An origin that did not configure affinity allocates no tables and
    /// records nothing, so the feature cannot cost an unconfigured operator
    /// memory or a lock.
    #[test]
    fn an_unarmed_state_never_leases() {
        let (state, _) = test_state(2, 300, 8);
        let key = cache_key("tenant-a", "session-7");
        assert!(!state.cache_affinity_enabled());
        state.record_cache_holder(0, key, "gpt-4o");
        assert_eq!(
            state.select_cache_holder(&key, "gpt-4o", &[0, 1]),
            CacheAffinityLookup::Miss
        );
    }

    #[test]
    fn cache_affinity_config_refuses_zero_bounds() {
        assert!(
            serde_json::from_value::<CacheAffinityConfig>(serde_json::json!({}))
                .expect("defaults parse")
                .validate()
                .is_ok()
        );
        assert!(
            serde_json::from_value::<CacheAffinityConfig>(serde_json::json!({"ttl_secs": 0}))
                .is_err()
        );
        assert!(serde_json::from_value::<CacheAffinityConfig>(
            serde_json::json!({"max_keys_per_provider": 0})
        )
        .is_err());
        assert!(serde_json::from_value::<CacheAffinityConfig>(
            serde_json::json!({"max_prefixes_per_provider": 8})
        )
        .is_err());
    }
}
