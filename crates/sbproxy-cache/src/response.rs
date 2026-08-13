//! Response cache logic: key computation, cacheability checks, and configuration.
//!
//! This module is the canonical home for the cache-key wire format
//! shared by both the runtime cache lookup path (in `sbproxy-core`) and
//! the unit tests below. The key format is:
//!
//! `<workspace>:<hostname>:<method>:<path>:<query-canonical>:<vary-fingerprint>:<config-fingerprint>`
//!
//! Each segment is colon-delimited so that key collisions across
//! tenants, hostnames, methods, paths, query variants, and Vary
//! variants are impossible without two of the segments simultaneously
//! matching. The `vary-fingerprint` is a stable hash of the
//! lowercased header name plus value pairs, so cardinality is bounded
//! even when callers send long Vary header values.
//!
//! The `config-fingerprint` names the origin config that produced the
//! entry. A shared store (Redis, memcached, a file store on a shared
//! volume) is one flat key space across every node, so without this
//! segment a fleet mid-rolling-change serves entries written under a
//! config that no longer applies. See
//! `sbproxy_config::cache_identity` for what feeds it.

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
///
/// `config_fp` identifies the origin config that produced the entry, so
/// two nodes running different cache-relevant config cannot read each
/// other's entries out of a shared store (WOR-2407). It is computed
/// once per origin at compile time by
/// `sbproxy_config::cache_identity::origin_cache_fingerprint`, never
/// per request. It is the **last** segment on purpose:
/// [`path_invalidation_prefix`] stops before the query segment, so a
/// mutation still evicts every cached variant of a path whatever config
/// wrote it.
pub fn compute_cache_key(
    workspace: &str,
    hostname: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    query_mode: &QueryMode,
    vary_headers: &[(String, String)],
    config_fp: &str,
) -> String {
    use std::fmt::Write;
    let canonical_query = canonicalize_query(query, query_mode);
    let vary_fp = vary_fingerprint(vary_headers);
    let mut key = String::with_capacity(
        workspace.len()
            + hostname.len()
            + method.len()
            + path.len()
            + canonical_query.len()
            + config_fp.len()
            + 32,
    );
    write!(
        key,
        "{}:{}:{}:{}:{}:{}:{}",
        workspace, hostname, method, path, canonical_query, vary_fp, config_fp
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

// WOR-2342: `is_cacheable_method` stood here and had zero production call
// sites. The request path decides this inline in
// `server::request_phase`, against `cache_cfg.cacheable_methods`.
//
// Deleted rather than wired, because the two had already drifted: this
// one admitted HEAD on an empty list and the live gate admits GET only.
// A helper that disagrees with the code actually making the decision is
// worse than no helper, since the next reader has to work out which of
// the two is authoritative.
//
// The method allowlist is now validated at config compile
// (`compiler.rs`), which refuses anything other than GET and HEAD.

/// HTTP methods that should trigger cache invalidation when
/// `invalidate_on_mutation` is enabled.
pub fn is_mutation_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Result of evaluating request validators against a stored `200 OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedPrecondition {
    /// Return the stored status, headers, and representation data.
    ServeRepresentation,
    /// Return `304 Not Modified` without representation data.
    NotModified,
    /// Return `412 Precondition Failed` without performing an unsafe method.
    PreconditionFailed,
}

/// Evaluate cache-applicable request preconditions against stored headers.
///
/// `If-None-Match` uses weak entity-tag comparison and takes precedence
/// whenever at least one field value is present. `If-Modified-Since` is
/// evaluated only for `GET` and `HEAD`, only when `If-None-Match` is absent,
/// and only when the stored response has a valid `Last-Modified` value.
///
/// A cache evaluates these fields only for a stored `200 OK`. Other stored
/// statuses are replayed unchanged so a cached redirect or error cannot be
/// hidden behind a synthetic `304`.
pub fn evaluate_cached_preconditions(
    method: &str,
    cached_status: u16,
    cached_headers: &[(String, String)],
    if_none_match: &[&[u8]],
    if_modified_since: Option<&[u8]>,
) -> CachedPrecondition {
    if cached_status != 200 {
        return CachedPrecondition::ServeRepresentation;
    }

    if !if_none_match.is_empty() {
        let current_etag = header_value(cached_headers, "etag");
        if if_none_match_matches(if_none_match, current_etag) {
            return if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                CachedPrecondition::NotModified
            } else {
                CachedPrecondition::PreconditionFailed
            };
        }
        return CachedPrecondition::ServeRepresentation;
    }

    if !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) {
        return CachedPrecondition::ServeRepresentation;
    }
    let Some(if_modified_since) = if_modified_since else {
        return CachedPrecondition::ServeRepresentation;
    };
    let Some(last_modified) = header_value(cached_headers, "last-modified") else {
        return CachedPrecondition::ServeRepresentation;
    };
    let Some(if_modified_since) = parse_http_date(if_modified_since) else {
        return CachedPrecondition::ServeRepresentation;
    };
    let Some(last_modified) = parse_http_date(last_modified.as_bytes()) else {
        return CachedPrecondition::ServeRepresentation;
    };
    if last_modified <= if_modified_since {
        CachedPrecondition::NotModified
    } else {
        CachedPrecondition::ServeRepresentation
    }
}

/// Select stored metadata that is relevant to a `304 Not Modified` response.
///
/// Representation fields such as `Content-Type` and `Content-Length` are
/// omitted. `Last-Modified` is retained because it can guide a cache update
/// when an entity tag is unavailable.
pub fn headers_for_not_modified(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "cache-control"
                    | "content-location"
                    | "date"
                    | "etag"
                    | "expires"
                    | "last-modified"
                    | "vary"
            )
        })
        .cloned()
        .collect()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_http_date(value: &[u8]) -> Option<std::time::SystemTime> {
    let value = std::str::from_utf8(value).ok()?;
    httpdate::parse_http_date(value).ok()
}

fn if_none_match_matches(values: &[&[u8]], current_etag: Option<&str>) -> bool {
    if values.len() == 1 && trim_ows(values[0]) == b"*" {
        return true;
    }
    let Some(current_etag) = current_etag.and_then(parse_single_entity_tag) else {
        return false;
    };
    values
        .iter()
        .any(|value| entity_tag_list_matches(value, current_etag))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_single_entity_tag(value: &str) -> Option<&[u8]> {
    let bytes = trim_ows(value.as_bytes());
    let (opaque, next) = parse_entity_tag(bytes, 0)?;
    (next == bytes.len()).then_some(opaque)
}

fn parse_entity_tag(value: &[u8], mut cursor: usize) -> Option<(&[u8], usize)> {
    if value.get(cursor..cursor.saturating_add(2)) == Some(b"W/") {
        cursor += 2;
    }
    if value.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    let opaque_start = cursor;
    while let Some(&byte) = value.get(cursor) {
        if byte == b'"' {
            return Some((&value[opaque_start..cursor], cursor + 1));
        }
        if !(byte == 0x21 || (0x23..=0x7e).contains(&byte) || byte >= 0x80) {
            return None;
        }
        cursor += 1;
    }
    None
}

fn entity_tag_list_matches(value: &[u8], current_opaque: &[u8]) -> bool {
    let mut cursor = 0usize;
    let mut matched = false;
    loop {
        while value
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b','))
        {
            cursor += 1;
        }
        if cursor == value.len() {
            return matched;
        }
        let Some((candidate, next)) = parse_entity_tag(value, cursor) else {
            return false;
        };
        matched |= candidate == current_opaque;
        cursor = next;
        while value
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            cursor += 1;
        }
        match value.get(cursor) {
            Some(b',') => cursor += 1,
            None => return matched,
            Some(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in origin fingerprint for tests that are not themselves
    /// about config identity.
    const FP: &str = "00112233445566ff";

    // --- compute_cache_key tests ---

    /// Two nodes running different cache-relevant config must not read
    /// each other's entries out of a shared store (WOR-2407).
    ///
    /// Without the fingerprint segment every node on a rolling config
    /// change shares one flat key space, so whichever writes first
    /// decides what the whole fleet serves until the TTL expires.
    #[test]
    fn a_different_config_fingerprint_partitions_the_key() {
        let key = |fp: &str| {
            compute_cache_key(
                "",
                "example.com",
                "GET",
                "/api/v1",
                None,
                &QueryMode::Sort,
                &[],
                fp,
            )
        };
        assert_ne!(
            key("0f1e2d3c4b5a6978"),
            key("69780f1e2d3c4b5a"),
            "an origin whose cache-relevant config changed must not share entries with the old one"
        );
    }

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
            FP,
        );
        // Trailing empty segments (`::`) reflect "no query, no vary";
        // the config fingerprint is the last segment.
        assert_eq!(key, ":example.com:GET:/api/v1:::00112233445566ff");
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
            FP,
        );
        let b = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/search",
            Some("a=1&b=2"),
            &QueryMode::Sort,
            &[],
            FP,
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
            FP,
        );
        let without_q = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::IgnoreAll,
            &[],
            FP,
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
            FP,
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
            FP,
        );
        let key_br = compute_cache_key(
            "",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::Sort,
            &br,
            FP,
        );
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
            FP,
        );
        let b = compute_cache_key(
            "ws-2",
            "example.com",
            "GET",
            "/x",
            None,
            &QueryMode::Sort,
            &[],
            FP,
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
            FP,
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

    // --- cached conditional requests ---

    fn validator_headers(etag: Option<&str>, last_modified: Option<&str>) -> Vec<(String, String)> {
        let mut headers = vec![
            (
                "cache-control".to_string(),
                "public, max-age=60".to_string(),
            ),
            ("content-location".to_string(), "/objects/42".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
            ),
            (
                "expires".to_string(),
                "Sun, 06 Nov 1994 08:50:37 GMT".to_string(),
            ),
            ("vary".to_string(), "accept-encoding".to_string()),
            ("content-length".to_string(), "12".to_string()),
        ];
        if let Some(etag) = etag {
            headers.push(("etag".to_string(), etag.to_string()));
        }
        if let Some(last_modified) = last_modified {
            headers.push(("last-modified".to_string(), last_modified.to_string()));
        }
        headers
    }

    #[test]
    fn if_none_match_uses_weak_comparison_across_a_list() {
        let headers = validator_headers(Some(r#"W/"opaque,tag""#), None);

        assert_eq!(
            evaluate_cached_preconditions(
                "GET",
                200,
                &headers,
                &[br#""other", "opaque,tag""#],
                None,
            ),
            CachedPrecondition::NotModified
        );
    }

    #[test]
    fn if_none_match_wildcard_matches_a_cached_representation_without_an_etag() {
        let headers = validator_headers(None, None);

        assert_eq!(
            evaluate_cached_preconditions("HEAD", 200, &headers, &[b"*"], None),
            CachedPrecondition::NotModified
        );
    }

    #[test]
    fn nonmatching_if_none_match_returns_the_full_cached_response() {
        let headers = validator_headers(Some(r#""current""#), None);

        assert_eq!(
            evaluate_cached_preconditions(
                "GET",
                200,
                &headers,
                &[br#""previous", W/"other""#],
                None,
            ),
            CachedPrecondition::ServeRepresentation
        );
    }

    #[test]
    fn if_none_match_presence_suppresses_if_modified_since_fallback() {
        let modified = "Sun, 06 Nov 1994 08:49:37 GMT";
        let headers = validator_headers(Some(r#""current""#), Some(modified));

        assert_eq!(
            evaluate_cached_preconditions(
                "GET",
                200,
                &headers,
                &[br#""different""#],
                Some(modified.as_bytes()),
            ),
            CachedPrecondition::ServeRepresentation
        );
    }

    #[test]
    fn if_modified_since_falls_back_when_etag_condition_is_absent() {
        let headers = validator_headers(None, Some("Sun, 06 Nov 1994 08:49:37 GMT"));

        assert_eq!(
            evaluate_cached_preconditions(
                "GET",
                200,
                &headers,
                &[],
                Some(b"Sun, 06 Nov 1994 08:50:00 GMT"),
            ),
            CachedPrecondition::NotModified
        );
        assert_eq!(
            evaluate_cached_preconditions(
                "GET",
                200,
                &headers,
                &[],
                Some(b"Sun, 06 Nov 1994 08:00:00 GMT"),
            ),
            CachedPrecondition::ServeRepresentation
        );
    }

    #[test]
    fn malformed_or_inapplicable_dates_do_not_hide_the_representation() {
        let headers = validator_headers(None, Some("Sun, 06 Nov 1994 08:49:37 GMT"));

        assert_eq!(
            evaluate_cached_preconditions("GET", 200, &headers, &[], Some(b"not-a-date")),
            CachedPrecondition::ServeRepresentation
        );
        assert_eq!(
            evaluate_cached_preconditions(
                "POST",
                200,
                &headers,
                &[],
                Some(b"Sun, 06 Nov 1994 08:50:00 GMT"),
            ),
            CachedPrecondition::ServeRepresentation
        );
    }

    #[test]
    fn matching_if_none_match_on_an_unsafe_method_is_a_precondition_failure() {
        let headers = validator_headers(Some(r#""current""#), None);

        assert_eq!(
            evaluate_cached_preconditions("POST", 200, &headers, &[br#"W/"current""#], None,),
            CachedPrecondition::PreconditionFailed
        );
    }

    #[test]
    fn cache_only_evaluates_preconditions_for_a_stored_ok_response() {
        let headers = validator_headers(Some(r#""missing""#), None);

        assert_eq!(
            evaluate_cached_preconditions("GET", 404, &headers, &[b"*"], None),
            CachedPrecondition::ServeRepresentation
        );
    }

    #[test]
    fn not_modified_headers_keep_cache_metadata_and_drop_representation_fields() {
        let headers =
            validator_headers(Some(r#""current""#), Some("Sun, 06 Nov 1994 08:49:37 GMT"));

        assert_eq!(
            headers_for_not_modified(&headers),
            vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=60".to_string()
                ),
                ("content-location".to_string(), "/objects/42".to_string()),
                (
                    "date".to_string(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".to_string()
                ),
                (
                    "expires".to_string(),
                    "Sun, 06 Nov 1994 08:50:37 GMT".to_string()
                ),
                ("vary".to_string(), "accept-encoding".to_string()),
                ("etag".to_string(), r#""current""#.to_string()),
                (
                    "last-modified".to_string(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
                ),
            ]
        );
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
            generation: 0,
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now,
            ttl_secs: 300,
            config_fp: String::new(),
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
            generation: 0,
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now.saturating_sub(500),
            ttl_secs: 100,
            config_fp: String::new(),
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
