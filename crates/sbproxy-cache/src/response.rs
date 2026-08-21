//! Response cache logic: key computation, cacheability checks, and configuration.
//!
//! This module is the canonical home for the cache-key wire format
//! shared by both the runtime cache lookup path (in `sbproxy-core`) and
//! the unit tests below. The key format is:
//!
//! `v2:<workspace>:<tenant>:<hostname>:<method>:<path>:<identity>:<query-canonical>:<vary-fingerprint>:<config-fingerprint>`
//!
//! Every field after the `v2` tag is written by `push_field`, which
//! percent-escapes `%` and `:`. That escaping is what makes the colon a
//! delimiter rather than a suggestion, and it is the fix WOR-2607
//! landed. Without it the fields are merely concatenated and the client
//! moves the boundary itself: `GET /victim:foo?bar` and
//! `GET /victim?foo:bar` both rendered `::GET:/victim:foo:bar=::<fp>`,
//! so whoever could reach one path seeded the other's entry. The same
//! escaping is what makes [`path_invalidation_prefix`] mean what it
//! says. The old unescaped `::GET:/victim:` was a string prefix of
//! every `/victim:foo` key as well, so one mutation purged unrelated
//! paths.
//!
//! The `v2` tag is the rollout namespace. An entry written under the
//! old unversioned format can no longer be read as a new one, so a
//! fleet mid-deploy runs two disjoint key spaces and the old entries
//! age out on their TTLs instead of being reinterpreted.
//!
//! ## Three tiers, and only one of them can widen a key
//!
//! * **Host-stamped**: workspace, tenant, hostname, method, path,
//!   identity, canonical query, and the config fingerprint. No operator
//!   config and no policy can drop one of these or change what it
//!   resolves to.
//! * **Operator-declared**: `response_cache.vary`, a list of request
//!   header names, hashed into the vary fingerprint.
//! * **Policy-added**: a `cache.key` event's dimensions, hashed into
//!   the same fingerprint. The event can only add.
//!
//! So a policy narrows a key and can never widen one past its own
//! tenant, which is the property `cache_event` is built around.
//!
//! `identity` is the caller: a 16-hex digest over the resolved
//! principal and the ambient credentials the request presented, or the
//! empty string when it presented none. Two callers holding different
//! credentials cannot share an entry, and anonymous traffic keys
//! exactly as it did before. RFC 9111 section 3.5 would have a shared
//! cache refuse to store a credentialed response at all; partitioning
//! is more permissive than that and still safe, because the partition
//! is drawn by the host rather than by the response.
//!
//! The `config-fingerprint` names the origin config that produced the
//! entry. A shared store (Redis, memcached, a file store on a shared
//! volume) is one flat key space across every node, so without this
//! field a fleet mid-rolling-change serves entries written under a
//! config that no longer applies. See
//! `sbproxy_config::cache_identity` for what feeds it.
//!
//! ## The key is stable across restarts and across a fleet
//!
//! Every field is a pure function of the request and the compiled
//! config. Nothing is salted per process, seeded from a random value,
//! or read off the clock: the two digests here are unkeyed SHA-256, the
//! principal's key id is an unsalted digest of the credential
//! (`sbproxy_modules::auth::derive_key_fingerprint`), and the config
//! fingerprint is computed from the config text. So two proxies sharing
//! a Redis hit each other's entries, and a restart reads back what the
//! process before it wrote. `a_known_key_is_byte_stable` pins that; it
//! fails the moment anything per-process leaks into a field.
//!
//! Two nodes running *different* config do not share entries, by
//! design: the config fingerprint partitions them.
//!
//! ## What is deliberately not in the key
//!
//! A key that is too narrow costs hit rate. A key that is too wide
//! serves one caller's response to another, so each entry below says
//! which of the two its absence risks.
//!
//! * **The request body.** Absent. Config compile refuses any
//!   `cacheable_methods` entry other than `GET` and `HEAD`, so no
//!   method whose body carries the request can reach the cache at all.
//!   Caching a completion is the semantic cache's job. Too wide if that
//!   refusal is ever relaxed without the body joining the key.
//! * **Scheme and port.** Absent. Origin resolution reads the hostname
//!   with the port stripped, so both listeners reach one origin and one
//!   upstream URL, and that URL is config, already covered by the
//!   config fingerprint. Safe while routing ignores them.
//! * **`Range`.** Absent. Only `200` is in the default
//!   `cacheable_status`, and a stored whole entity answers any range.
//!   An operator who adds `206` stores a partial body as if it were
//!   whole: too wide, and the remedy is a config-compile refusal rather
//!   than a key field.
//! * **The upstream's own `Vary:` response header.** Not a key field,
//!   and it cannot be one: the key is fixed before the request goes
//!   upstream and the `Vary` arrives with the response. Handled on the
//!   write side instead, where `uncovered_vary_dimension` in
//!   `sbproxy_core::server::proxy_http` refuses to store a response
//!   whose `Vary` names a dimension this key does not carry. Refusing
//!   costs a store; admitting would be too wide.
//! * **The content coding the proxy applied.** In the key as a
//!   negotiated-capability bucket, but deliberately *not* in the stored
//!   entry: the body is captured before the compression step and a hit
//!   never runs that step, so the entry holds the representation and
//!   `strip_proxy_added_content_coding` keeps the label off it. The two
//!   have to agree or every hit ships a body no client can decode.
//! * **Which forward rule the request took.** Absent. Forward rules are
//!   evaluated after `request_filter`, so a header that only a rule
//!   matches on can send two identically-keyed requests to two
//!   upstreams: too wide. List that header in `vary:` until the
//!   evaluation order changes.
//! * **What a request modifier rewrote.** Absent, and it cannot be
//!   here: modifiers run in `upstream_request_filter`, after the key is
//!   built. A modifier that is a deterministic function of fields
//!   already in the key is safe. A script modifier reading an unlisted
//!   header is too wide, on the same terms as a forward rule.
//! * **Transform output.** Not a field, but covered: the config
//!   fingerprint includes `transforms`, and an origin with transforms
//!   stores the chain's output rather than the upstream bytes. A
//!   transform whose output depends on an unlisted request header is
//!   too wide, again on the same terms.

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

/// Tag opening every key this module renders.
///
/// Bumping it retires the whole key space at once: no entry written
/// under an older format can be read back under a newer one, which is
/// what a change to the field list or the escaping needs, since the
/// alternative is reinterpreting an old string as a new one.
const KEY_FORMAT_VERSION: &str = "v2";

/// Append one field to a key, escaping the delimiter out of it.
///
/// `%` becomes `%25` and `:` becomes `%3A`, in that order of
/// precedence, which makes the mapping injective: `%3A` and a literal
/// `:` are distinguishable in the output because a literal `%` was
/// already doubled. Two different field lists therefore cannot render
/// the same key.
///
/// Escaping rather than hashing is deliberate. A digest would also be
/// injective, and it would destroy both of the things that read these
/// keys as text: [`path_invalidation_prefix`], which relies on the
/// rendering of a shorter field list being a byte prefix of the longer
/// one, and `POST /admin/cache/purge`, where an operator types a
/// prefix.
fn push_field(out: &mut String, field: &str) {
    let mut rest = field;
    while let Some(idx) = rest.find(['%', ':']) {
        out.push_str(&rest[..idx]);
        // `find` matched one of two ASCII bytes, so `idx` is on a
        // character boundary and the byte there is one of the two.
        out.push_str(if rest.as_bytes()[idx] == b'%' {
            "%25"
        } else {
            "%3A"
        });
        rest = &rest[idx + 1..];
    }
    out.push_str(rest);
}

/// Render the version tag followed by each field, delimiter-escaped.
///
/// Both the key and its invalidation prefix go through here so the
/// prefix relationship holds by construction rather than because two
/// format strings happen to agree. A field added to
/// [`compute_cache_key`] and forgotten in
/// [`path_invalidation_prefix`] can only ever shorten the prefix, never
/// desynchronize the escaping.
fn render_fields<'a>(out: &mut String, fields: impl IntoIterator<Item = &'a str>) {
    out.push_str(KEY_FORMAT_VERSION);
    for field in fields {
        out.push(':');
        push_field(out, field);
    }
}

/// Compute a cache key from request attributes.
///
/// The key format is:
/// `v2:<workspace>:<tenant>:<hostname>:<method>:<path>:<identity>:<query-canonical>:<vary-fingerprint>:<config-fingerprint>`
///
/// `workspace` may be empty for the OSS single-tenant path. `tenant` is
/// the origin's resolved tenant (`__default__` in a single-tenant
/// deployment). `identity` is the caller digest from
/// [`caller_identity`], empty for an uncredentialed request. `query` is
/// canonicalized per `QueryMode` (sort by name, drop entirely, or
/// allowlist a subset). `vary_headers` is a slice of `(name, value)`
/// pairs the caller already canonicalized; the fingerprint is a stable
/// SHA-256 prefix so the key length stays bounded.
///
/// `tenant` and `identity` are both stamped here rather than folded
/// into `vary_headers` by the call site. Folding would have worked and
/// would have been fewer lines, and it would also have put the two
/// dimensions that separate one customer from another in the one part
/// of the key an operator's config and a `cache.key` policy can reach.
/// A field a policy cannot address is the whole guarantee.
///
/// `config_fp` identifies the origin config that produced the entry, so
/// two nodes running different cache-relevant config cannot read each
/// other's entries out of a shared store (WOR-2407). It is computed
/// once per origin at compile time by
/// `sbproxy_config::cache_identity::origin_cache_fingerprint`, never
/// per request. It is the **last** field on purpose:
/// [`path_invalidation_prefix`] stops after the path, so a mutation
/// still evicts every cached variant of a path whatever config, caller,
/// or query wrote it.
// The parameter list is the key format, field by field, in the order
// `render_fields` below writes them. Bundling it into a struct to get
// under the seven-argument threshold would put the field list somewhere
// other than the code that renders it, which is the one place a reader
// checks when they need to know what a key contains.
#[allow(clippy::too_many_arguments)]
pub fn compute_cache_key(
    workspace: &str,
    tenant: &str,
    hostname: &str,
    method: &str,
    path: &str,
    identity: &str,
    query: Option<&str>,
    query_mode: &QueryMode,
    vary_headers: &[(String, String)],
    config_fp: &str,
) -> String {
    let canonical_query = canonicalize_query(query, query_mode);
    let vary_fp = vary_fingerprint(vary_headers);
    let mut key = String::with_capacity(
        workspace.len()
            + tenant.len()
            + hostname.len()
            + method.len()
            + path.len()
            + identity.len()
            + canonical_query.len()
            + config_fp.len()
            + 32,
    );
    render_fields(
        &mut key,
        [
            workspace,
            tenant,
            hostname,
            method,
            path,
            identity,
            canonical_query.as_str(),
            vary_fp.as_str(),
            config_fp,
        ],
    );
    key
}

/// Compute the path-only key prefix used for `POST` invalidation.
///
/// The mutation-handler walks every cache entry sharing this prefix and
/// drops them. The prefix is the leading fields of
/// [`compute_cache_key`] up to and including the path, so a
/// `POST /users/42` invalidates every `GET /users/42?...` variant
/// whatever its query string, caller, or Vary fingerprint.
///
/// Widening a delete is safe in a way that widening a read is not:
/// dropping an entry that did not need dropping costs one upstream
/// round trip, so this prefix deliberately crosses the caller identity
/// the key otherwise separates.
///
/// It does **not** cross the method: `HEAD` entries survive a mutation
/// and age out on their TTL. That is a staleness gap rather than a
/// leak, and it only exists for an origin that put `HEAD` in
/// `cacheable_methods`.
pub fn path_invalidation_prefix(
    workspace: &str,
    tenant: &str,
    hostname: &str,
    path: &str,
) -> String {
    let mut prefix =
        String::with_capacity(workspace.len() + tenant.len() + hostname.len() + path.len() + 16);
    render_fields(&mut prefix, [workspace, tenant, hostname, "GET", path]);
    // The trailing delimiter is what stops `/users/4` from prefixing
    // `/users/42`. It is only load bearing because `push_field` escaped
    // every `:` the path itself carried.
    prefix.push(':');
    prefix
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
///
/// Each part is length-delimited rather than joined by a separator, for
/// the reason the key itself is escaped: a `name=value\n` join lets one
/// pair impersonate two. `("a", "b=c")` and `("a=b", "c")` both hashed
/// `a=b=c\n` before WOR-2607. No HTTP header name can carry `=` so
/// nothing on the request path could reach that, but this function is
/// public and the ambiguity is not worth keeping for the four bytes it
/// saves.
pub fn vary_fingerprint(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (name, value) in headers {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    // 16-hex-char prefix is plenty for collision avoidance per origin
    // and keeps cache keys short. The full digest would bloat every
    // key for no practical gain.
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Digest the caller so two credentials cannot share a cache entry.
///
/// `credential` is the safe credential identity the request resolved
/// to: an API key id, a principal source plus subject, or a digest of
/// the authorization value. The caller passes the empty string for a
/// request that resolved to no credential, rather than a sentinel
/// spelling of "anonymous", so this function never has to recognize a
/// constant that lives in another crate. `cookie` is the raw `Cookie`
/// header when the request carried one.
///
/// Returns the empty string when both are absent, so anonymous traffic
/// keys exactly as it did before this existed, and a 16-hex digest
/// otherwise. Empty and 16 hex characters cannot be confused, so the
/// two cases stay distinguishable.
///
/// The digest is what lands in the key, never the inputs. A key travels
/// into Redis and memcached as a key name, into an operator's
/// `POST /admin/cache/purge` request, and into the response that echoes
/// the prefix back; a subject or a session cookie has no business in
/// any of those.
///
/// The cookie is in here because an upstream that personalizes on a
/// session sbproxy did not issue is invisible to the principal: no auth
/// provider ran, so every caller would look anonymous and share one
/// entry. Including it costs hit rate on an origin whose clients carry
/// any cookie at all, including one no upstream reads. That is the
/// trade this takes deliberately: a cold cache is a bill, and one
/// caller's page served to another is an incident.
pub fn caller_identity(credential: &str, cookie: Option<&str>) -> String {
    let cookie = cookie.filter(|value| !value.is_empty());
    if credential.is_empty() && cookie.is_none() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Domain label plus length-delimited fields, so a credential ending
    // in what looks like a cookie cannot render the same digest as the
    // pair that really is one.
    hasher.update(b"sbproxy-response-cache-identity-v2\0");
    hasher.update((credential.len() as u64).to_be_bytes());
    hasher.update(credential.as_bytes());
    let cookie = cookie.unwrap_or_default();
    hasher.update((cookie.len() as u64).to_be_bytes());
    hasher.update(cookie.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Bucket an `Accept-Encoding` value down to the codings the client
/// will actually take.
///
/// The proxy forwards `Accept-Encoding` upstream, so an upstream that
/// compresses returns different bytes, under a different
/// `Content-Encoding`, to two clients that ask differently. Nothing
/// made that a cache dimension: the entry a `gzip` client seeded was
/// replayed verbatim to a client that had asked for `identity`.
///
/// Bucketing rather than keying on the raw header is what keeps this
/// from being a cardinality bomb. Browsers send half a dozen spellings
/// of the same capability set, and the upstream picks from the set, not
/// from the spelling: `gzip, deflate, br` and `br;q=1.0, gzip;q=0.8`
/// both bucket to `br,gzip` and share an entry, correctly. The result
/// is one of at most 32 values.
///
/// A coding at `q=0` is a refusal and is dropped. A header that leaves
/// nothing acceptable buckets as `identity`, which is deliberately
/// **not** the empty string a missing header buckets as: RFC 9110
/// reads an absent `Accept-Encoding` as "anything goes" and a present
/// one as an exhaustive list, so an upstream may compress for the first
/// and may not for the second. Folding them together would be the one
/// bucketing that could serve a coding the client refused.
pub fn negotiated_encoding_bucket(accept_encoding: Option<&str>) -> String {
    const KNOWN: [&str; 5] = ["*", "br", "deflate", "gzip", "zstd"];
    let Some(raw) = accept_encoding else {
        return String::new();
    };
    let mut accepted: Vec<&str> = Vec::new();
    for part in raw.split(',') {
        let mut params = part.split(';');
        let coding = params.next().unwrap_or_default().trim();
        let refused = params.any(|param| match param.trim().split_once('=') {
            Some((name, value)) => {
                name.eq_ignore_ascii_case("q")
                    && value.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
            }
            None => false,
        });
        if refused {
            continue;
        }
        if let Some(known) = KNOWN
            .iter()
            .copied()
            .find(|candidate| candidate.eq_ignore_ascii_case(coding))
        {
            accepted.push(known);
        }
    }
    accepted.sort_unstable();
    accepted.dedup();
    if accepted.is_empty() {
        return "identity".to_owned();
    }
    accepted.join(",")
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

    /// Every test below that is not about one particular field goes
    /// through this, so a new field added to the key does not need a
    /// hundred call sites edited before the suite compiles again.
    fn key(hostname: &str, method: &str, path: &str, query: Option<&str>) -> String {
        compute_cache_key(
            "",
            "__default__",
            hostname,
            method,
            path,
            "",
            query,
            &QueryMode::Sort,
            &[],
            FP,
        )
    }

    /// The WOR-2607 defect: a client that can reach one path must not
    /// be able to render another request's key.
    ///
    /// Path `/victim:foo` with query `bar` and path `/victim` with
    /// query `foo:bar` both rendered `::GET:/victim:foo:bar=::<fp>`
    /// before the fields were escaped, because the colon that separates
    /// them is a legal `pchar` and nothing removed it. Whoever could
    /// request the first seeded the entry the second reads.
    #[test]
    fn delimiter_injection_in_path_and_query_cannot_collide() {
        let injected_path = key("h", "GET", "/victim:foo", Some("bar"));
        let injected_query = key("h", "GET", "/victim", Some("foo:bar"));
        assert_ne!(
            injected_path, injected_query,
            "a colon in a path or a query must not move the field boundary"
        );
        assert!(
            injected_path.contains("/victim%3Afoo"),
            "the path's colon must be escaped, got: {injected_path}"
        );
    }

    /// The escape character itself is not an escape hatch.
    ///
    /// A guard on the fix rather than a second reproduction of the bug:
    /// the shipped format escaped nothing, so these two already
    /// differed. Escaping `:` and not `%` would be the tempting
    /// simplification, and it would make a path containing a literal
    /// `%3A` render exactly like one containing `:`.
    #[test]
    fn a_literal_percent_escape_in_a_path_cannot_spell_a_delimiter() {
        assert_ne!(
            key("h", "GET", "/a%3Ab", None),
            key("h", "GET", "/a:b", None),
            "a literal `%3A` and a literal `:` must render differently"
        );
    }

    /// Field boundaries hold in every direction, not only the two the
    /// ticket named. Each pair below differs by which field a colon
    /// landed in and nothing else.
    #[test]
    fn no_two_field_lists_render_the_same_key() {
        let collisions = [
            (
                key("host:GET", "x", "/p", None),
                key("host", "GET:x", "/p", None),
            ),
            (
                key("h", "GET", "/a", Some("b=1")),
                key("h", "GET", "/a:b=1", None),
            ),
        ];
        for (left, right) in collisions {
            assert_ne!(left, right, "two field lists rendered one key");
        }
    }

    /// A caller's credentials partition the cache.
    ///
    /// Without this, an origin with `authentication` and
    /// `response_cache` on serves the first caller's `GET /me` to every
    /// later caller, as a cache hit, with nothing anywhere saying so.
    #[test]
    fn two_callers_do_not_share_an_entry() {
        let for_identity = |identity: &str| {
            compute_cache_key(
                "",
                "__default__",
                "api.local",
                "GET",
                "/me",
                identity,
                None,
                &QueryMode::Sort,
                &[],
                FP,
            )
        };
        let alice = caller_identity("principal:jwt:alice", None);
        let bob = caller_identity("principal:jwt:bob", None);
        let anonymous = caller_identity("", None);

        assert_ne!(for_identity(&alice), for_identity(&bob));
        assert_ne!(for_identity(&alice), for_identity(&anonymous));
        assert_eq!(
            anonymous, "",
            "an uncredentialed request keys as it did before the identity field existed"
        );
    }

    /// A session the proxy did not issue is still a credential.
    ///
    /// No auth provider runs for an upstream-managed session, so every
    /// caller resolves to the same anonymous principal. The cookie is
    /// the only thing that tells them apart.
    #[test]
    fn two_session_cookies_do_not_share_an_entry() {
        let alice = caller_identity("", Some("sid=alice"));
        let bob = caller_identity("", Some("sid=bob"));
        assert_ne!(alice, bob, "two sessions must not share an entry");
        assert_ne!(alice, "", "a cookie-bearing request is not anonymous");
        assert_eq!(
            caller_identity("", Some("")),
            "",
            "an empty cookie header is not a credential"
        );
    }

    /// The identity digest is domain separated and length delimited, so
    /// a credential cannot borrow the cookie's bytes to impersonate a
    /// different pair.
    #[test]
    fn the_identity_digest_cannot_be_reassociated_across_its_fields() {
        assert_ne!(
            caller_identity("principal:jwt:ab", Some("c")),
            caller_identity("principal:jwt:a", Some("bc")),
        );
    }

    /// Two nodes running different cache-relevant config must not read
    /// each other's entries out of a shared store (WOR-2407).
    ///
    /// Without the fingerprint field every node on a rolling config
    /// change shares one flat key space, so whichever writes first
    /// decides what the whole fleet serves until the TTL expires.
    #[test]
    fn a_different_config_fingerprint_partitions_the_key() {
        let key = |fp: &str| {
            compute_cache_key(
                "",
                "__default__",
                "example.com",
                "GET",
                "/api/v1",
                "",
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

    /// One tenant's entries are not readable as another's.
    ///
    /// Today the hostname already separates them, because an origin is
    /// resolved by hostname and carries exactly one tenant. This field
    /// says so structurally instead, so the separation does not quietly
    /// depend on routing never gaining a second dimension.
    #[test]
    fn a_different_tenant_partitions_the_key() {
        let key = |tenant: &str| {
            compute_cache_key(
                "",
                tenant,
                "example.com",
                "GET",
                "/api/v1",
                "",
                None,
                &QueryMode::Sort,
                &[],
                FP,
            )
        };
        assert_ne!(key("acme"), key("globex"));
    }

    #[test]
    fn test_basic_cache_key() {
        // Trailing empty fields reflect "no identity, no query, no
        // vary"; the config fingerprint is the last one.
        assert_eq!(
            key("example.com", "GET", "/api/v1", None),
            "v2::__default__:example.com:GET:/api/v1::::00112233445566ff"
        );
    }

    /// Nothing per-process, random, or clock-derived may reach a key.
    ///
    /// A shared Redis is one key space for the whole fleet, and a
    /// restart re-reads what the process before it wrote, so a salt
    /// anywhere in here would turn every lookup into a miss and nothing
    /// would report it: the hit-rate panel would just read zero.
    #[test]
    fn a_known_key_is_byte_stable() {
        let vary = vec![("accept-language".to_string(), "en".to_string())];
        let rendered = compute_cache_key(
            "ws-1",
            "acme",
            "api.local",
            "GET",
            "/v1/thing",
            &caller_identity("api_key_id:kid-7", Some("sid=abc")),
            Some("b=2&a=1"),
            &QueryMode::Sort,
            &vary,
            FP,
        );
        assert_eq!(
            rendered,
            "v2:ws-1:acme:api.local:GET:/v1/thing:26fe413a4e3df262:a=1&b=2:\
             68a80533e583b68a:00112233445566ff"
        );
    }

    #[test]
    fn test_cache_key_with_query_sort() {
        let a = key("example.com", "GET", "/search", Some("b=2&a=1"));
        let b = key("example.com", "GET", "/search", Some("a=1&b=2"));
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
            "__default__",
            "example.com",
            "GET",
            "/x",
            "",
            Some("a=1&b=2"),
            &QueryMode::IgnoreAll,
            &[],
            FP,
        );
        let without_q = compute_cache_key(
            "",
            "__default__",
            "example.com",
            "GET",
            "/x",
            "",
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
            "__default__",
            "example.com",
            "GET",
            "/x",
            "",
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
        let vary_key = |value: &str| {
            compute_cache_key(
                "",
                "__default__",
                "example.com",
                "GET",
                "/x",
                "",
                None,
                &QueryMode::Sort,
                &[("accept-encoding".to_string(), value.to_string())],
                FP,
            )
        };
        assert_ne!(
            vary_key("gzip"),
            vary_key("br"),
            "different Accept-Encoding values must produce different cache keys"
        );
    }

    #[test]
    fn test_cache_key_workspace_segments_keys() {
        let workspace_key = |workspace: &str| {
            compute_cache_key(
                workspace,
                "__default__",
                "example.com",
                "GET",
                "/x",
                "",
                None,
                &QueryMode::Sort,
                &[],
                FP,
            )
        };
        assert_ne!(
            workspace_key("ws-1"),
            workspace_key("ws-2"),
            "different workspaces must not collide"
        );
    }

    /// A vary pair cannot impersonate two, and two cannot impersonate
    /// one. The old `name=value\n` join hashed `("a", "b=c")` and
    /// `("a=b", "c")` to the same digest.
    #[test]
    fn a_vary_pair_cannot_be_reassociated_across_its_separator() {
        let pair =
            |name: &str, value: &str| vary_fingerprint(&[(name.to_string(), value.to_string())]);
        assert_ne!(pair("a", "b=c"), pair("a=b", "c"));
        assert_eq!(
            vary_fingerprint(&[]),
            "",
            "no vary headers is the empty fingerprint"
        );
    }

    /// The upstream picks a coding from the set the client offered, so
    /// two spellings of one set must share an entry and two different
    /// sets must not.
    #[test]
    fn accept_encoding_buckets_by_capability_not_by_spelling() {
        assert_eq!(
            negotiated_encoding_bucket(Some("gzip, deflate, br")),
            negotiated_encoding_bucket(Some("br;q=1.0, GZIP;q=0.8 , deflate")),
        );
        assert_ne!(
            negotiated_encoding_bucket(Some("gzip")),
            negotiated_encoding_bucket(Some("br")),
        );
        assert_eq!(
            negotiated_encoding_bucket(Some("gzip;q=0")),
            "identity",
            "a refused coding leaves only identity acceptable"
        );
        assert_eq!(
            negotiated_encoding_bucket(Some("identity, x-made-up")),
            "identity",
            "an unrecognized coding cannot enlarge the bucket set"
        );
        assert_ne!(
            negotiated_encoding_bucket(None),
            negotiated_encoding_bucket(Some("identity")),
            "an absent header permits any coding; a present one is exhaustive"
        );
    }

    #[test]
    fn test_path_invalidation_prefix() {
        let prefix = path_invalidation_prefix("", "__default__", "example.com", "/users/42");
        let get_key = compute_cache_key(
            "",
            "__default__",
            "example.com",
            "GET",
            "/users/42",
            &caller_identity("principal:jwt:alice", None),
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

    /// The other half of the WOR-2607 defect: the prefix must not reach
    /// past the path it names.
    ///
    /// `::GET:/victim:` was a string prefix of every `/victim:foo` key,
    /// so a `POST /victim` purged a path the caller may not even have
    /// been able to reach. The same goes for the ordinary case of one
    /// path being a textual prefix of another.
    #[test]
    fn an_invalidation_prefix_stops_at_the_path_it_names() {
        let prefix = path_invalidation_prefix("", "__default__", "example.com", "/victim");
        for unrelated in ["/victim:foo", "/victim2", "/victimised"] {
            assert!(
                !key("example.com", "GET", unrelated, None).starts_with(&prefix),
                "a POST /victim must not purge {unrelated}"
            );
        }
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
            swr_secs: None,
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
            swr_secs: None,
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
