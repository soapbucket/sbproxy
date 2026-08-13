// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The two cache decision events: `cache.key` and `cache.admit`.
//!
//! Caching had no expression surface anywhere. `ResponseCacheConfig` is
//! entirely static: fixed `ttl_secs`, fixed `cacheable_methods`, fixed
//! `cacheable_status`, fixed `vary`, fixed `query_normalize`. Whether a
//! response is stored, for how long, and under what key could not depend
//! on the request.
//!
//! ## Why this is two events rather than one
//!
//! The obvious framing is a single "cache policy". That is wrong, and
//! the reason is a hard ordering constraint rather than a preference.
//!
//! **Key derivation happens before the upstream call.** You cannot look
//! up a cache entry without already knowing its key, so the key decision
//! runs on the request with no response in scope.
//!
//! **Admission and TTL happen after the response arrives.** Whether
//! something is worth storing, and for how long, depends on status,
//! size, content, and cost, none of which exist at request time.
//!
//! One event cannot serve both without either denying the key decision
//! its purpose or giving the admission decision a context it cannot
//! have.
//!
//! ## Poisoning is the risk this is designed against
//!
//! A key policy that omits a dimension it should have included serves
//! one tenant's response to another. That is a worse failure than
//! anything routing can do, so the safety story is structural rather
//! than advisory: **a policy chooses additional dimensions to vary on,
//! and cannot remove any.**
//!
//! A dimension name is either `query` or a request header written
//! `header:<name>`. Anything else is **refused at decode**, because a
//! name resolving to nothing would contribute the same empty value to
//! every request, partition nothing, and merge every caller into one
//! cache entry. That refusal is load bearing: a silently-inert dimension
//! is the poisoning bug wearing a working config's clothes.
//!
//! `compute_cache_key` builds `<workspace>:<hostname>:<method>:<path>:
//! <query>:<vary-fingerprint>`, and a policy reaches only the last
//! segment. Every earlier segment is stamped by the host whatever the
//! policy returns, so a policy can narrow a key and there is no
//! document it can return that widens one.
//!
//! Worth being precise about which segment does the separating, because
//! the obvious answer is wrong in this build: `workspace` is passed as
//! the empty string on every production path, so tenant separation
//! comes from `hostname` plus the per-origin store handle
//! (`cache_store_for(origin)`), not from a workspace prefix. The
//! structural property holds either way, since a plan only ever
//! produces vary pairs and those are hashed into the last segment.
//!
//! ## Determinism is a correctness property, not a preference
//!
//! A `cache.key` policy returning different dimensions for two identical
//! requests produces a cache that silently never hits: every store lands
//! under a key no later lookup reproduces. Nothing fails, latency just
//! quietly stops improving, and the hit-rate panel reads zero with no
//! error anywhere.
//!
//! [`CacheKeyPlan::vary`] is therefore normalized on decode (trimmed,
//! lowercased, deduplicated, sorted) so a policy that returns the same
//! set in a different order produces the same key. That removes the
//! most common accidental source of it. A policy that varies on
//! something genuinely non-deterministic, a timestamp or a request id,
//! is still able to defeat its own cache, and no amount of normalizing
//! fixes that: it is a bug in the rule.
//!
//! ## Declining falls through to static config
//!
//! As with routing, the common case is a rule for some requests and the
//! configured default for the rest. A policy that returns nothing gets
//! today's behavior exactly.

use serde::{Deserialize, Serialize};

/// Upper bound on vary dimensions one key plan may add.
///
/// Each dimension is a segment of the fingerprint input, so what this
/// caps is key-derivation cost: how much work one key costs to build and
/// how long the string that work reads gets.
///
/// **It does not cap how many distinct keys a policy produces.** That is
/// set by the value cardinality of the dimensions chosen, and this
/// counts dimensions. A single dimension under the cap is enough to
/// defeat the cache: `header:user-agent`, or any request-id header,
/// takes a distinct value on nearly every request, so every lookup
/// misses, every response is stored, and a memory store at
/// `response_cache.max_size` evicts the entries that were earning their
/// keep to make room for entries nothing will ask for a second time.
///
/// The client drives that from outside the moment a policy names a
/// header the client controls, and no count-based cap can see it coming.
/// The real bound is which dimensions a policy picks, not this number.
pub const MAX_CACHE_VARY_DIMENSIONS: usize = 16;

/// Upper bound on a single vary dimension name, in bytes.
pub const MAX_CACHE_VARY_NAME_BYTES: usize = 128;

/// Prefix marking a vary dimension that names a request header.
///
/// Explicit rather than implied, because a bare name that silently
/// resolved against headers is how `{"vary": ["tenant"]}` looks correct,
/// contributes an empty value for every request, partitions nothing, and
/// serves one customer's response to another.
pub const CACHE_VARY_HEADER_PREFIX: &str = "header:";

/// Dimension names the host resolves itself, without a prefix.
///
/// A name outside this set and without [`CACHE_VARY_HEADER_PREFIX`] is
/// **refused** rather than resolved to nothing. That refusal is the
/// difference between a typo that fails loudly and a typo that quietly
/// merges every caller into one cache bucket.
pub const CACHE_VARY_HOST_DIMENSIONS: &[&str] = &["query"];

/// Upper bound on a policy-chosen TTL, in seconds (30 days).
///
/// A policy that returns a larger TTL is clamped rather than refused. An
/// unbounded TTL is how a cache entry outlives the config that produced
/// it and then cannot be explained by reading that config.
pub const MAX_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Upper bound on a `reason` string, in bytes.
pub const MAX_CACHE_REASON_BYTES: usize = 512;

/// What a `cache.key` event returned: which dimensions to add to the
/// key, and whether to skip the lookup entirely.
///
/// `#[non_exhaustive]` because a key decision has room to say more than
/// this: a store selector or a per-request bypass reason are additive
/// here and breaking for anything downstream that spelled the struct out
/// as a literal. Nothing outside this crate constructs one today, so the
/// attribute costs nothing now and is unaffordable later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CacheKeyPlan {
    /// Extra dimensions folded into the vary fingerprint, normalized on
    /// decode so ordering cannot change the resulting key.
    ///
    /// These are **added** to the host's key material. Nothing here can
    /// remove the workspace, hostname, method, or path segments, which
    /// is what makes cross-tenant poisoning unreachable from a policy.
    pub vary: Vec<String>,
    /// Skip the cache lookup for this request and go upstream.
    ///
    /// Distinct from refusing to store: a request can legitimately want
    /// fresh data while its response is still worth caching for others.
    #[serde(default)]
    pub skip_lookup: bool,
    /// Why this plan was chosen.
    ///
    /// Decoded and bounded to [`MAX_CACHE_REASON_BYTES`], and then it
    /// goes nowhere. Nothing in this workspace builds an audit record
    /// yet, and the `cache.key` call site records the outcome without
    /// ever reading this field. Wiring it to the audit record is
    /// outstanding, not done.
    ///
    /// It is kept because a reason is what makes a cache decision
    /// diagnosable, and a debug line is not somewhere to keep one:
    /// `release_max_level_info` compiles `debug!` out of release builds,
    /// so a reason that lives only there does not exist in production,
    /// which is exactly where an operator asks why nothing is caching.
    #[serde(default)]
    pub reason: String,
}

/// What a `cache.admit` event returned: whether to store the response
/// and for how long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CacheAdmitPlan {
    /// Store this response.
    pub store: bool,
    /// TTL override in seconds, clamped to [`MAX_CACHE_TTL_SECS`].
    /// `None` keeps the configured `ttl_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Why this response was admitted or refused.
    ///
    /// Decoded and bounded to [`MAX_CACHE_REASON_BYTES`], and then it
    /// goes nowhere. Nothing in this workspace builds an audit record
    /// yet, and the `cache.admit` call site records the outcome without
    /// ever reading this field. Wiring it to the audit record is
    /// outstanding, not done.
    ///
    /// It is kept because a reason is what makes a cache decision
    /// diagnosable, and a debug line is not somewhere to keep one:
    /// `release_max_level_info` compiles `debug!` out of release builds,
    /// so a reason that lives only there does not exist in production,
    /// which is exactly where an operator asks why a response was never
    /// stored.
    #[serde(default)]
    pub reason: String,
}

impl Default for CacheAdmitPlan {
    /// Store, with no TTL override and no reason.
    ///
    /// This is what a deployment without the event does, which is why it
    /// is also the fallback for a declined, absent, or faulted one: the
    /// four are separated on the metric rather than in behavior.
    ///
    /// Exists so the type can be `#[non_exhaustive]` without blocking
    /// the fallback its caller needs to construct.
    fn default() -> Self {
        Self {
            store: true,
            ttl_secs: None,
            reason: String::new(),
        }
    }
}

/// What a cache decision event returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheDecision<T> {
    /// No opinion. The static `ResponseCacheConfig` applies unchanged.
    Decline,
    /// Use this plan.
    Plan(T),
}

/// Why a returned cache document was refused.
///
/// `#[non_exhaustive]` because this is the part of the surface most
/// certain to grow. Every bound worth enforcing and every dimension the
/// host learns to resolve arrives here as a variant, and adding one to
/// an exhaustive public enum breaks every downstream `match` that
/// listed the old set. Refusals should be cheap to add; a refusal that
/// is a breaking change is a refusal that does not get added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheEventError {
    /// The document was not an object.
    NotAnObject,
    /// `vary` was present but not an array of strings.
    VaryNotStrings,
    /// More vary dimensions than [`MAX_CACHE_VARY_DIMENSIONS`].
    TooManyVaryDimensions {
        /// How many were returned.
        count: usize,
    },
    /// A vary dimension name was longer than
    /// [`MAX_CACHE_VARY_NAME_BYTES`].
    VaryNameTooLong {
        /// The offending name, truncated for the message.
        name: String,
    },
    /// A vary dimension named something the host cannot resolve.
    UnknownVaryDimension {
        /// The offending name.
        name: String,
    },
    /// `store` was missing on a `cache.admit` document.
    ///
    /// Unlike every other field this one has no safe default. Guessing
    /// `true` caches something the policy never approved; guessing
    /// `false` silently disables the cache. Both are worse than saying
    /// the document is incomplete.
    AdmitMissingStore,
}

impl std::fmt::Display for CacheEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "cache event must return an object or null"),
            Self::VaryNotStrings => write!(f, "cache.key `vary` must be an array of strings"),
            Self::TooManyVaryDimensions { count } => write!(
                f,
                "cache.key returned {count} vary dimensions, the cap is \
                 {MAX_CACHE_VARY_DIMENSIONS}"
            ),
            Self::VaryNameTooLong { name } => {
                write!(f, "cache.key vary dimension `{name}` is too long")
            }
            Self::UnknownVaryDimension { name } => write!(
                f,
                "cache.key vary dimension `{name}` is not a dimension the host resolves \
                 (expected one of {CACHE_VARY_HOST_DIMENSIONS:?}, or `header:<name>`). A \
                 dimension the host cannot resolve would contribute the same empty value to \
                 every request and partition nothing, which merges callers into one cache entry."
            ),
            Self::AdmitMissingStore => {
                write!(
                    f,
                    "cache.admit must return `store`; there is no safe default"
                )
            }
        }
    }
}

impl std::error::Error for CacheEventError {}

/// Decode a `cache.key` document.
///
/// Declining spells as `null`, `{}`, or an object with no `vary` and no
/// `skip_lookup`.
pub fn decode_cache_key(
    value: &serde_json::Value,
) -> Result<CacheDecision<CacheKeyPlan>, CacheEventError> {
    if value.is_null() {
        return Ok(CacheDecision::Decline);
    }
    let object = value.as_object().ok_or(CacheEventError::NotAnObject)?;

    let mut vary = Vec::new();
    if let Some(raw) = object.get("vary").filter(|raw| !raw.is_null()) {
        let array = raw.as_array().ok_or(CacheEventError::VaryNotStrings)?;
        if array.len() > MAX_CACHE_VARY_DIMENSIONS {
            return Err(CacheEventError::TooManyVaryDimensions { count: array.len() });
        }
        for entry in array {
            let name = entry
                .as_str()
                .ok_or(CacheEventError::VaryNotStrings)?
                .trim();
            if name.is_empty() {
                continue;
            }
            if name.len() > MAX_CACHE_VARY_NAME_BYTES {
                return Err(CacheEventError::VaryNameTooLong {
                    name: bounded(name, 64),
                });
            }
            let lowered = name.to_ascii_lowercase();
            let resolvable = CACHE_VARY_HOST_DIMENSIONS.contains(&lowered.as_str())
                || lowered
                    .strip_prefix(CACHE_VARY_HEADER_PREFIX)
                    .is_some_and(|header| !header.is_empty());
            if !resolvable {
                return Err(CacheEventError::UnknownVaryDimension { name: lowered });
            }
            vary.push(lowered);
        }
    }
    // Determinism: the same set in a different order must produce the
    // same key, or the cache silently never hits.
    vary.sort_unstable();
    vary.dedup();

    let skip_lookup = object
        .get("skip_lookup")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let reason = object
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(|reason| bounded(reason.trim(), MAX_CACHE_REASON_BYTES))
        .unwrap_or_default();

    if vary.is_empty() && !skip_lookup {
        return Ok(CacheDecision::Decline);
    }
    Ok(CacheDecision::Plan(CacheKeyPlan {
        vary,
        skip_lookup,
        reason,
    }))
}

/// Decode a `cache.admit` document.
///
/// Declining spells as `null` or `{}`. An object carrying anything other
/// than `store` is incomplete rather than declining, because a partial
/// admission document is a policy bug and guessing either way is worse
/// than saying so.
pub fn decode_cache_admit(
    value: &serde_json::Value,
) -> Result<CacheDecision<CacheAdmitPlan>, CacheEventError> {
    if value.is_null() {
        return Ok(CacheDecision::Decline);
    }
    let object = value.as_object().ok_or(CacheEventError::NotAnObject)?;
    if object.is_empty() {
        return Ok(CacheDecision::Decline);
    }
    let store = object
        .get("store")
        .and_then(serde_json::Value::as_bool)
        .ok_or(CacheEventError::AdmitMissingStore)?;
    let ttl_secs = object
        .get("ttl_secs")
        .and_then(serde_json::Value::as_u64)
        .map(|ttl| ttl.min(MAX_CACHE_TTL_SECS));
    let reason = object
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(|reason| bounded(reason.trim(), MAX_CACHE_REASON_BYTES))
        .unwrap_or_default();
    Ok(CacheDecision::Plan(CacheAdmitPlan {
        store,
        ttl_secs,
        reason,
    }))
}

impl CacheKeyPlan {
    /// Fold this plan's dimensions into the caller's vary pair list.
    ///
    /// `host` resolves the unprefixed dimensions in
    /// [`CACHE_VARY_HOST_DIMENSIONS`]; `header` resolves anything
    /// carrying [`CACHE_VARY_HEADER_PREFIX`]. Decoding already refused
    /// every other name, so neither resolver is asked for something it
    /// cannot answer.
    ///
    /// A header the request does not carry contributes an empty value
    /// rather than being dropped, so "header absent" and "header present
    /// and empty" stay distinguishable: collapsing them would let a
    /// client choose its cache bucket by omitting a header.
    ///
    /// Returns pairs ready for `vary_fingerprint`, sorted for
    /// determinism.
    pub fn fold_into_vary(
        &self,
        host: impl Fn(&str) -> String,
        header: impl Fn(&str) -> Option<String>,
    ) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .vary
            .iter()
            .map(|name| {
                let value = match name.strip_prefix(CACHE_VARY_HEADER_PREFIX) {
                    Some(header_name) => header(header_name).unwrap_or_default(),
                    None => host(name),
                };
                (name.clone(), value)
            })
            .collect();
        out.sort_unstable();
        out
    }
}

/// Truncate on a character boundary.
fn bounded(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn declining_falls_through_to_static_config() {
        for value in [json!(null), json!({}), json!({"reason": "no opinion"})] {
            assert_eq!(
                decode_cache_key(&value),
                Ok(CacheDecision::Decline),
                "{value} must decline"
            );
        }
        for value in [json!(null), json!({})] {
            assert_eq!(decode_cache_admit(&value), Ok(CacheDecision::Decline));
        }
    }

    #[test]
    fn vary_order_cannot_change_the_key() {
        // A policy returning the same set in a different order must
        // produce the same key. Otherwise every store lands under a key
        // no later lookup reproduces and the cache silently never hits,
        // with nothing failing and the hit-rate panel reading zero.
        let a = decode_cache_key(&json!({"vary": ["query", "header:x-tier", "header:x-region"]}));
        let b = decode_cache_key(&json!({"vary": ["header:x-region", "query", "header:x-tier"]}));
        assert_eq!(a, b);
    }

    #[test]
    fn vary_names_are_case_insensitive_and_deduplicated() {
        let CacheDecision::Plan(plan) =
            decode_cache_key(&json!({"vary": ["Query", "query", "QUERY", "Header:X-Tier"]}))
                .unwrap()
        else {
            panic!("expected a plan");
        };
        assert_eq!(plan.vary, vec!["header:x-tier", "query"]);
    }

    #[test]
    fn a_policy_can_narrow_a_key_but_never_escape_its_tenant() {
        // The poisoning defense, stated as a test rather than a comment.
        // There is no document a policy can return that reaches the
        // workspace segment, because it only ever produces vary pairs
        // and the host stamps the prefix itself.
        let CacheDecision::Plan(plan) = decode_cache_key(&json!({
            "vary": ["query", "header:x-tenant-override", "header:../../other-tenant"],
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        let folded = plan.fold_into_vary(
            |name| format!("host-{name}"),
            |name| Some(format!("header-{name}")),
        );

        // Whatever the names are, they only ever reach the vary
        // fingerprint, which is a hash. A dimension name carrying the
        // key's own `:` separator, or a traversal-looking one, cannot
        // inject a segment into the key: it is hashed with the rest.
        assert_eq!(folded.len(), 3);
        let key_a = crate::response::compute_cache_key(
            "tenant-a",
            "api.local",
            "GET",
            "/v1/thing",
            None,
            &crate::response::QueryMode::Sort,
            &folded,
        );
        let key_b = crate::response::compute_cache_key(
            "tenant-b",
            "api.local",
            "GET",
            "/v1/thing",
            None,
            &crate::response::QueryMode::Sort,
            &folded,
        );
        assert_ne!(
            key_a, key_b,
            "identical policy output under two tenants must not collide"
        );
        assert!(key_a.starts_with("tenant-a:"));
        assert!(key_b.starts_with("tenant-b:"));
    }

    #[test]
    fn an_absent_dimension_is_not_the_same_as_an_empty_one_being_dropped() {
        // Collapsing "header absent" into "dimension not applied" would
        // let a client pick its cache bucket by omitting a header.
        let CacheDecision::Plan(plan) =
            decode_cache_key(&json!({"vary": ["header:x-tier"]})).unwrap()
        else {
            panic!("expected a plan");
        };
        let absent = plan.fold_into_vary(|name| name.to_owned(), |_| None);
        let present = plan.fold_into_vary(|name| name.to_owned(), |_| Some("gold".to_owned()));
        assert_eq!(absent, vec![("header:x-tier".to_owned(), String::new())]);
        assert_ne!(absent, present);
    }

    #[test]
    fn skip_lookup_alone_is_a_plan_not_a_decline() {
        // "Go upstream for this request" is a real decision, and it is
        // distinct from refusing to store the result for others.
        let CacheDecision::Plan(plan) =
            decode_cache_key(&json!({"skip_lookup": true, "reason": "live data"})).unwrap()
        else {
            panic!("skip_lookup must be a plan");
        };
        assert!(plan.skip_lookup);
        assert!(plan.vary.is_empty());
        assert_eq!(plan.reason, "live data");
    }

    #[test]
    fn admit_requires_store_because_neither_default_is_safe() {
        // Guessing `true` caches something the policy never approved;
        // guessing `false` silently disables the cache.
        assert_eq!(
            decode_cache_admit(&json!({"ttl_secs": 300})),
            Err(CacheEventError::AdmitMissingStore)
        );
        assert_eq!(
            decode_cache_admit(&json!({"reason": "why"})),
            Err(CacheEventError::AdmitMissingStore)
        );
    }

    #[test]
    fn admit_decodes_store_and_ttl() {
        let CacheDecision::Plan(plan) = decode_cache_admit(&json!({
            "store": true,
            "ttl_secs": 300,
            "reason": "deterministic completion, temperature 0",
        }))
        .unwrap() else {
            panic!("expected a plan");
        };
        assert!(plan.store);
        assert_eq!(plan.ttl_secs, Some(300));
        assert_eq!(plan.reason, "deterministic completion, temperature 0");
    }

    #[test]
    fn a_runaway_ttl_is_clamped_rather_than_refused() {
        // An unbounded TTL is how an entry outlives the config that
        // produced it and then cannot be explained by reading it.
        let CacheDecision::Plan(plan) =
            decode_cache_admit(&json!({"store": true, "ttl_secs": u64::MAX})).unwrap()
        else {
            panic!("expected a plan");
        };
        assert_eq!(plan.ttl_secs, Some(MAX_CACHE_TTL_SECS));
    }

    #[test]
    fn a_dimension_the_host_cannot_resolve_is_refused() {
        // The bug this exists to stop: a bare `tenant` looks correct,
        // resolves against nothing, contributes the same empty value to
        // every request, and merges every caller into one cache entry.
        // Refusing is the difference between a typo that fails loudly
        // and a typo that serves one customer's response to another.
        let error = decode_cache_key(&json!({"vary": ["x-tier"]})).unwrap_err();
        assert_eq!(
            error,
            CacheEventError::UnknownVaryDimension {
                name: "x-tier".to_owned()
            }
        );
        assert!(
            error.to_string().contains("header:"),
            "the message must name the prefix that would have worked: {error}"
        );
        // A bare header prefix names no header.
        assert!(decode_cache_key(&json!({"vary": ["header:"]})).is_err());
    }

    #[test]
    fn the_host_dimensions_resolve_without_a_prefix() {
        let CacheDecision::Plan(plan) =
            decode_cache_key(&json!({"vary": CACHE_VARY_HOST_DIMENSIONS})).unwrap()
        else {
            panic!("every host dimension must be accepted");
        };
        let folded = plan.fold_into_vary(|name| format!("v-{name}"), |_| None);
        assert_eq!(folded.len(), CACHE_VARY_HOST_DIMENSIONS.len());
        assert!(
            folded.iter().all(|(_, value)| value.starts_with("v-")),
            "a host dimension must reach the host resolver, not the header one"
        );
    }

    #[test]
    fn a_runaway_vary_list_is_refused() {
        let vary: Vec<_> = (0..MAX_CACHE_VARY_DIMENSIONS + 1)
            .map(|i| format!("d{i}"))
            .collect();
        assert_eq!(
            decode_cache_key(&json!({"vary": vary})),
            Err(CacheEventError::TooManyVaryDimensions {
                count: MAX_CACHE_VARY_DIMENSIONS + 1
            })
        );
    }

    #[test]
    fn one_client_controlled_dimension_is_accepted_with_unbounded_cardinality() {
        // The failure this pins: MAX_CACHE_VARY_DIMENSIONS caps how many
        // dimensions a plan carries, not how many keys those dimensions
        // produce, and nothing on this path refuses a dimension whose
        // value the client picks. A single accepted dimension, far under
        // the cap, gives every request its own key. Every lookup then
        // misses, every response is stored, and a bounded store evicts
        // the entries that were earning their keep to make room for
        // entries nothing will ask for twice. Nothing errors; the cache
        // just stops being one, and the client drove it from outside.
        //
        // This is not a decoder bug, it is the limit of what the decoder
        // can see. It is executable here so the cap's doc cannot drift
        // back into claiming it bounds cache fan-out.
        let CacheDecision::Plan(plan) =
            decode_cache_key(&json!({"vary": ["header:x-request-id"]})).unwrap()
        else {
            panic!("a client-controlled header is still a resolvable dimension, so it is accepted");
        };
        assert_eq!(plan.vary.len(), 1, "one dimension, far under the cap");

        // One policy, one request line, one header the caller chose.
        let keys: std::collections::HashSet<String> = (0..64)
            .map(|i| {
                let folded =
                    plan.fold_into_vary(|name| name.to_owned(), |_| Some(format!("req-{i}")));
                crate::response::compute_cache_key(
                    "tenant-a",
                    "api.local",
                    "GET",
                    "/v1/thing",
                    None,
                    &crate::response::QueryMode::Sort,
                    &folded,
                )
            })
            .collect();
        assert_eq!(
            keys.len(),
            64,
            "64 requests differing only in a client-set header produced 64 keys, so the cap \
             bounds dimension count and not the number of cache entries a policy can create"
        );
    }

    #[test]
    fn a_non_string_vary_entry_is_refused() {
        assert_eq!(
            decode_cache_key(&json!({"vary": ["query", 7]})),
            Err(CacheEventError::VaryNotStrings)
        );
        assert_eq!(
            decode_cache_key(&json!({"vary": "query"})),
            Err(CacheEventError::VaryNotStrings)
        );
    }

    #[test]
    fn a_non_object_document_is_refused_on_both_events() {
        for value in [json!("tenant"), json!(7), json!([])] {
            assert_eq!(decode_cache_key(&value), Err(CacheEventError::NotAnObject));
            assert_eq!(
                decode_cache_admit(&value),
                Err(CacheEventError::NotAnObject)
            );
        }
    }

    #[test]
    fn an_overlong_vary_name_is_refused_with_a_bounded_message() {
        let long = "x".repeat(MAX_CACHE_VARY_NAME_BYTES + 1);
        let error = decode_cache_key(&json!({"vary": [long]})).unwrap_err();
        let CacheEventError::VaryNameTooLong { name } = &error else {
            panic!("expected VaryNameTooLong, got {error:?}");
        };
        assert!(
            name.len() <= 64,
            "the error message must not echo the whole runaway name"
        );
    }

    #[test]
    fn an_overlong_reason_is_truncated_on_a_character_boundary() {
        let reason = "\u{00e9}".repeat(MAX_CACHE_REASON_BYTES);
        let CacheDecision::Plan(plan) =
            decode_cache_admit(&json!({"store": true, "reason": reason})).unwrap()
        else {
            panic!("expected a plan");
        };
        assert!(plan.reason.len() <= MAX_CACHE_REASON_BYTES);
        assert!(plan.reason.chars().all(|c| c == '\u{00e9}'));
    }
}
