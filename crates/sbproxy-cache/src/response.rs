//! Response cache logic: key computation, cacheability checks, and configuration.
//!
//! This module is the canonical home for the cache-key wire format
//! shared by both the runtime cache lookup path (in `sbproxy-core`) and
//! the unit tests below. The key format is:
//!
//! `<workspace>:<hostname>:<method>:<path>:<query-canonical>:<vary-fingerprint>`
//!
//! Each segment is colon-delimited so that key collisions across
//! tenants, hostnames, methods, paths, query variants, and Vary
//! variants are impossible without two of the segments simultaneously
//! matching. The `vary-fingerprint` is a stable hash of the
//! lowercased header name plus value pairs, so cardinality is bounded
//! even when callers send long Vary header values.

use serde::Deserialize;

/// Configuration for response caching on an origin.
///
/// This struct is a legacy mirror of the canonical
/// `sbproxy_config::types::ResponseCacheConfig`. The runtime path uses
/// the config-crate version. This one is kept around for any external
/// consumers that depend on the public re-export.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseCacheConfig {
    /// Cache TTL in seconds.
    #[serde(default = "default_ttl")]
    pub ttl: u64,

    /// HTTP methods to cache. Defaults to GET and HEAD if empty.
    #[serde(default)]
    pub methods: Vec<String>,

    /// Headers whose values are included in the cache key.
    #[serde(default)]
    pub vary_headers: Vec<String>,

    /// If set, serve stale content for this many seconds while revalidating.
    #[serde(default)]
    pub stale_while_revalidate: Option<u64>,
}

fn default_ttl() -> u64 {
    300
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            ttl: default_ttl(),
            methods: Vec::new(),
            vary_headers: Vec::new(),
            stale_while_revalidate: None,
        }
    }
}

/// Query-string normalization mode used at cache-key build time.
///
/// Mirrors `sbproxy_config::types::QueryNormalize` but lives here as a
/// plain enum so that this crate has no dependency on the config crate.
/// The runtime call-site translates the config enum into this one.
#[derive(Debug, Clone, Default)]
pub enum QueryMode {
    /// Drop the query entirely from the cache key.
    IgnoreAll,
    /// Sort params alphabetically by name; preserve duplicates and values.
    /// This is the default and matches the pre-Wave-4 behavior closely.
    #[default]
    Sort,
    /// Keep only the listed param names; drop the rest. Retained params
    /// are sorted for deterministic keys.
    Allowlist(Vec<String>),
}

/// Compute a cache key from request attributes.
///
/// The key format is:
/// `<workspace>:<hostname>:<method>:<path>:<query-canonical>:<vary-fingerprint>`
///
/// `workspace` may be empty for the OSS single-tenant path. `query` is
/// canonicalized per `QueryMode` (sort by name, drop entirely, or
/// allowlist a subset). `vary_headers` is a slice of `(lowercased
/// name, value)` pairs that the caller already canonicalized; the
/// fingerprint is a stable BLAKE3 hash so the key length stays bounded.
pub fn compute_cache_key(
    workspace: &str,
    hostname: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    query_mode: &QueryMode,
    vary_headers: &[(String, String)],
) -> String {
    use std::fmt::Write;
    let canonical_query = canonicalize_query(query, query_mode);
    let vary_fp = vary_fingerprint(vary_headers);
    let mut key = String::with_capacity(
        workspace.len() + hostname.len() + method.len() + path.len() + canonical_query.len() + 32,
    );
    write!(
        key,
        "{}:{}:{}:{}:{}:{}",
        workspace, hostname, method, path, canonical_query, vary_fp
    )
    .unwrap();
    key
}

/// Compute the path-only key prefix used for `POST` invalidation.
///
/// The mutation-handler walks every cache entry sharing this prefix and
/// drops them. The prefix is everything up to (but not including) the
/// `<query-canonical>` segment so a `POST /users/42` invalidates every
/// `GET /users/42?...` variant regardless of query string or Vary
/// fingerprint.
pub fn path_invalidation_prefix(workspace: &str, hostname: &str, path: &str) -> String {
    format!("{}:{}:GET:{}:", workspace, hostname, path)
}

/// Apply the configured query-string normalization rule and return a
/// canonical string suitable for inclusion in a cache key. Returns an
/// empty string when the result is empty or the query is missing.
pub fn canonicalize_query(query: Option<&str>, mode: &QueryMode) -> String {
    let raw = match query {
        Some(q) if !q.is_empty() => q,
        _ => return String::new(),
    };

    match mode {
        QueryMode::IgnoreAll => String::new(),
        QueryMode::Sort => sort_query(raw),
        QueryMode::Allowlist(allow) => {
            let filtered: Vec<(&str, &str)> = parse_query(raw)
                .into_iter()
                .filter(|(k, _)| allow.iter().any(|a| a == k))
                .collect();
            join_sorted(filtered)
        }
    }
}

fn sort_query(raw: &str) -> String {
    let parts = parse_query(raw);
    join_sorted(parts)
}

fn parse_query(raw: &str) -> Vec<(&str, &str)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k, v),
            None => (p, ""),
        })
        .collect()
}

fn join_sorted(mut parts: Vec<(&str, &str)>) -> String {
    parts.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));
    let mut out = String::with_capacity(parts.iter().map(|(k, v)| k.len() + v.len() + 2).sum());
    for (i, (k, v)) in parts.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Compute a stable fingerprint over the ordered (name, value) pairs
/// of varying request headers. Names must already be lowercased by the
/// caller. Returns the empty string when no Vary headers participated,
/// which collapses identical keys for non-varying requests.
pub fn vary_fingerprint(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (name, value) in headers {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    // 16-hex-char prefix is plenty for collision avoidance per origin
    // and keeps cache keys short. The full digest would bloat every
    // key for no practical gain.
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Check if a request method is cacheable given the allowed methods list.
///
/// If `allowed_methods` is empty, only GET and HEAD are cacheable.
pub fn is_cacheable_method(method: &str, allowed_methods: &[String]) -> bool {
    if allowed_methods.is_empty() {
        method == "GET" || method == "HEAD"
    } else {
        allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// HTTP methods that should trigger cache invalidation when
/// `invalidate_on_mutation` is enabled.
pub fn is_mutation_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- compute_cache_key tests ---

    #[test]
    fn test_basic_cache_key() {
        let key = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/api/v1",
            None,
            &QueryMode::Sort,
            &[],
        );
        // Trailing two empty segments (`::`) reflect "no query, no vary".
        assert_eq!(key, ":example.com:GET:/api/v1::");
    }

    #[test]
    fn test_cache_key_with_query_sort() {
        let a = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/search",
            Some("b=2&a=1"),
            &QueryMode::Sort,
            &[],
        );
        let b = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/search",
            Some("a=1&b=2"),
            &QueryMode::Sort,
            &[],
        );
        assert_eq!(
            a, b,
            "Sort mode must produce identical keys for permutations"
        );
        assert!(
            a.contains(":a=1&b=2:"),
            "expected sorted query in key, got: {}",
            a
        );
    }

    #[test]
    fn test_cache_key_with_query_ignore_all() {
        let with_q = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            Some("a=1&b=2"),
            &QueryMode::IgnoreAll,
            &[],
        );
        let without_q = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::IgnoreAll,
            &[],
        );
        assert_eq!(with_q, without_q, "IgnoreAll must drop the query entirely");
    }

    #[test]
    fn test_cache_key_with_query_allowlist() {
        let allow = QueryMode::Allowlist(vec!["a".to_string()]);
        let key = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            Some("a=1&utm_source=foo&b=2"),
            &allow,
            &[],
        );
        assert!(key.contains(":a=1:"), "only `a` should survive: {}", key);
        assert!(!key.contains("utm_source"), "utm_source should be dropped");
        assert!(!key.contains("b=2"), "b should be dropped");
    }

    #[test]
    fn test_cache_key_vary_segments_keys() {
        let gzip = vec![("accept-encoding".to_string(), "gzip".to_string())];
        let br = vec![("accept-encoding".to_string(), "br".to_string())];
        let key_gzip = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::Sort,
            &gzip,
        );
        let key_br = compute_cache_key("", "example.com", "GET", "/x", None, &QueryMode::Sort, &br);
        assert_ne!(
            key_gzip, key_br,
            "different Accept-Encoding values must produce different cache keys"
        );
    }

    #[test]
    fn test_cache_key_workspace_segments_keys() {
        let a = compute_cache_key(
            "ws-1",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::Sort,
            &[],
        );
        let b = compute_cache_key(
            "ws-2",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::Sort,
            &[],
        );
        assert_ne!(a, b, "different workspaces must not collide");
    }

    #[test]
    fn test_path_invalidation_prefix() {
        let prefix = path_invalidation_prefix("", "example.com", "/users/42");
        let get_key = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/users/42",
            Some("a=1"),
            &QueryMode::Sort,
            &[("accept".to_string(), "json".to_string())],
        );
        assert!(
            get_key.starts_with(&prefix),
            "GET cache key {} must start with invalidation prefix {}",
            get_key,
            prefix
        );
    }

    // --- canonicalize_query ---

    #[test]
    fn test_canonicalize_empty() {
        assert_eq!(canonicalize_query(None, &QueryMode::Sort), "");
        assert_eq!(canonicalize_query(Some(""), &QueryMode::Sort), "");
    }

    #[test]
    fn test_canonicalize_sort_preserves_duplicates() {
        // Duplicates are preserved; ordering is by (name, value) so
        // the result is fully deterministic.
        let out = canonicalize_query(Some("a=1&a=2&b=3"), &QueryMode::Sort);
        assert_eq!(out, "a=1&a=2&b=3");
    }

    // --- vary_fingerprint ---

    #[test]
    fn test_vary_fingerprint_stable() {
        let h1 = vec![("accept".to_string(), "json".to_string())];
        let h2 = vec![("accept".to_string(), "json".to_string())];
        assert_eq!(vary_fingerprint(&h1), vary_fingerprint(&h2));
    }

    #[test]
    fn test_vary_fingerprint_empty() {
        assert_eq!(vary_fingerprint(&[]), "");
    }

    // --- is_cacheable_method tests ---

    #[test]
    fn test_default_cacheable_methods() {
        let empty: Vec<String> = vec![];
        assert!(is_cacheable_method("GET", &empty));
        assert!(is_cacheable_method("HEAD", &empty));
        assert!(!is_cacheable_method("POST", &empty));
        assert!(!is_cacheable_method("PUT", &empty));
        assert!(!is_cacheable_method("DELETE", &empty));
    }

    #[test]
    fn test_custom_cacheable_methods() {
        let methods = vec!["GET".to_string(), "POST".to_string()];
        assert!(is_cacheable_method("GET", &methods));
        assert!(is_cacheable_method("POST", &methods));
        assert!(is_cacheable_method("post", &methods));
        assert!(!is_cacheable_method("PUT", &methods));
    }

    // --- is_mutation_method ---

    #[test]
    fn test_mutation_methods() {
        assert!(is_mutation_method("POST"));
        assert!(is_mutation_method("put"));
        assert!(is_mutation_method("PATCH"));
        assert!(is_mutation_method("DELETE"));
        assert!(!is_mutation_method("GET"));
        assert!(!is_mutation_method("HEAD"));
    }

    // --- CachedResponse::is_expired tests ---

    #[test]
    fn test_cached_response_not_expired() {
        use crate::store::CachedResponse;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let resp = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now,
            ttl_secs: 300,
        };
        assert!(!resp.is_expired());
    }

    #[test]
    fn test_cached_response_expired() {
        use crate::store::CachedResponse;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let resp = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now.saturating_sub(500),
            ttl_secs: 100,
        };
        assert!(resp.is_expired());
    }

    // --- ResponseCacheConfig serde defaults ---

    #[test]
    fn test_config_defaults() {
        let json = "{}";
        let config: ResponseCacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.ttl, 300);
        assert!(config.methods.is_empty());
        assert!(config.vary_headers.is_empty());
        assert!(config.stale_while_revalidate.is_none());
    }

    #[test]
    fn test_config_custom_values() {
        let json = r#"{
            "ttl": 60,
            "methods": ["GET", "POST"],
            "vary_headers": ["accept"],
            "stale_while_revalidate": 30
        }"#;
        let config: ResponseCacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.ttl, 60);
        assert_eq!(config.methods, vec!["GET", "POST"]);
        assert_eq!(config.vary_headers, vec!["accept"]);
        assert_eq!(config.stale_while_revalidate, Some(30));
    }
}
