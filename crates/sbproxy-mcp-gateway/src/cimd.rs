// Client ID Metadata Documents (CIMD).
//
// CIMD is the client-side analogue of RFC 9728 (resource metadata): a
// `client_id` is itself an https URL that resolves to a JSON document
// describing the client's `redirect_uris`, `scope`,
// `token_endpoint_auth_method`, and the rest of the RFC 7591 metadata
// fields. The Authorization Server fetches the document at /authorize
// time, validates the requested `redirect_uri` against it, and treats
// control of the URL as the trust anchor (anyone who can publish the
// document is the client).
//
// This module implements:
//
//   * `ClientIdMetadataDocument`: the document model. Mirrors RFC 7591
//     plus the `client_id` self-identification field the parecki draft
//     adds.
//   * `fetch`: validates the URL is https, blocks SSRF against private
//     and loopback addresses, caps the response body, and verifies the
//     document's `client_id` field matches the URL exactly.
//   * `CimdCache` trait + `InMemoryCimdCache`: TTL + ETag cache. A 304
//     response keeps the cached entry alive; the response's
//     `Cache-Control: max-age` header overrides the configured TTL.
//
// The trust model is intentionally narrow: the client's identity is
// "the entity in control of `https://<host>/<path>`". The broker
// MUST refuse documents fetched over plain http (no integrity), MUST
// refuse SSRF targets (no impersonation by network position), and
// MUST refuse documents whose embedded `client_id` does not match the
// URL (no host-based bait-and-switch).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use reqwest::Client;
use sbproxy_security::ssrf::validate_dialable_addrs;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// --- Document model ---

/// Client ID Metadata Document. Mirrors RFC 7591 client metadata plus
/// the `client_id` self-identification field added by the parecki
/// CIMD draft. Unknown JSON fields are ignored on the wire.
///
/// The exact field set is curated to match what the broker actually
/// reads at /authorize and /token time. Extending this struct does not
/// require touching the cache or the SSRF guard.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientIdMetadataDocument {
    /// Self-identification. MUST equal the URL the document was
    /// fetched from. Without this anchor a malicious host could
    /// impersonate any other CIMD client by serving its document.
    pub client_id: String,

    /// Human-readable name displayed on consent screens.
    #[serde(default)]
    pub client_name: Option<String>,

    /// Allowed redirect URIs. RFC 6749 mandates exact match at
    /// authorize time; CIMD does the same.
    #[serde(default)]
    pub redirect_uris: Vec<String>,

    /// Grant types the client intends to use. Public-client CIMD only
    /// makes sense with `authorization_code` (+ optional
    /// `refresh_token`); password and implicit are forbidden.
    #[serde(default)]
    pub grant_types: Vec<String>,

    /// Response types the client requests. OAuth 2.1 only allows
    /// `code`.
    #[serde(default)]
    pub response_types: Vec<String>,

    /// Space-separated scope string the client is allowed to ask for.
    /// /authorize-time scope is validated as a subset of this.
    #[serde(default)]
    pub scope: Option<String>,

    /// Token-endpoint client authentication method. CIMD clients are
    /// public; only `none` is accepted at /token time. Anything else
    /// is recorded but rejected when the broker decides whether to
    /// accept the inbound /token request.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,

    /// JWKS URL for clients that ship `private_key_jwt`. Held for
    /// future use; Wave 4C only consumes `none`-method CIMD clients.
    #[serde(default)]
    pub jwks_uri: Option<String>,

    /// Inline JWKS for clients that prefer not to host a separate
    /// document. Stored as raw JSON for forward compatibility.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,

    /// URL of the client's home page. Surfaced on consent screens.
    #[serde(default)]
    pub client_uri: Option<String>,

    /// URL of the client's logo. Surfaced on consent screens.
    #[serde(default)]
    pub logo_uri: Option<String>,

    /// URL of the client's terms of service.
    #[serde(default)]
    pub tos_uri: Option<String>,

    /// URL of the client's privacy policy.
    #[serde(default)]
    pub policy_uri: Option<String>,

    /// Software identifier (RFC 7591 §2). Opaque string the client
    /// chooses; stable across instances.
    #[serde(default)]
    pub software_id: Option<String>,

    /// Software version (RFC 7591 §2). Opaque string.
    #[serde(default)]
    pub software_version: Option<String>,
}

impl ClientIdMetadataDocument {
    /// Returns the document's `scope` field tokenised on whitespace.
    /// An absent or empty `scope` returns an empty vector.
    pub fn scope_tokens(&self) -> Vec<&str> {
        match self.scope.as_deref() {
            Some(s) => s.split_whitespace().collect(),
            None => Vec::new(),
        }
    }

    /// Returns true when every token in `requested` appears in the
    /// document's declared scope. An empty `requested` is always
    /// allowed; a document with no `scope` accepts any request because
    /// the AS will further constrain.
    pub fn allows_scope(&self, requested: &str) -> bool {
        let req: Vec<&str> = requested.split_whitespace().collect();
        if req.is_empty() {
            return true;
        }
        let allowed = self.scope_tokens();
        if allowed.is_empty() {
            return true;
        }
        req.iter().all(|t| allowed.contains(t))
    }

    /// Returns true when `redirect_uri` exact-matches an entry in
    /// the document. RFC 6749 §3.1.2.4 mandates exact matching.
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|r| r == redirect_uri)
    }
}

// --- SSRF guard ---

/// Returns true when `host` resolves to or literally is a private,
/// loopback, or link-local address. The check refuses to fetch CIMD
/// documents from such addresses to prevent the broker becoming an
/// SSRF oracle.
///
/// We intentionally do NOT perform DNS resolution here: the URL crate
/// already gave us the host string, and a DNS-based bypass (TOCTOU)
/// is mitigated by the same check happening inside `reqwest` only
/// when the deployer plumbs a custom resolver. For the inline check,
/// we cover IP literals and the most common bypass hostnames.
fn is_disallowed_host(host: &str) -> bool {
    // Match common loopback hostnames literally. Deployers who really
    // want to host CIMD on `localhost` can run the broker without the
    // SSRF guard or override the http client.
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    ) {
        return true;
    }

    // Strip surrounding brackets for IPv6 literals like `[::1]`.
    let trimmed = lower.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return is_disallowed_ip(ip);
    }

    false
}

/// Returns true when `ip` must not be dialed by the CIMD fetcher.
///
/// This is one line on purpose. The shared
/// [`sbproxy_security::ssrf::validate_dialable_addrs`] is the workspace's
/// dial-time range check: it canonicalizes IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) before testing, so the v6-shaped spelling of an
/// RFC 1918 or link-local address cannot walk past the block, and it
/// covers the private ranges plus multicast, `0.0.0.0/8`, `240.0.0.0/4`,
/// and the deprecated `::a.b.c.d` form. A hand-rolled copy here is how
/// the mapped-address hole got in.
///
/// The port is irrelevant to a range test, so a placeholder is used.
fn is_disallowed_ip(ip: IpAddr) -> bool {
    validate_dialable_addrs(&[SocketAddr::new(ip, 0)]).is_err()
}

// --- DNS resolution + dialer pinning ---

/// Maximum time we wait for the hostname to resolve before giving up.
/// CIMD discovery happens at /authorize time so a slow DNS server is
/// effectively a denial of service against the broker.
const CIMD_DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum time the hardened HTTP client will spend on a single
/// request (connect + TLS + headers + body). Bounded so a slow CIMD
/// host cannot pin a broker worker indefinitely.
const CIMD_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve `host`:`port` via the system resolver, validate every
/// returned address, and return the validated set. The returned
/// vector is non-empty on success; an empty result is reported as
/// an error so callers do not silently fall through to the system
/// resolver inside reqwest.
///
/// `host` must already be lowercased and stripped of any IPv6
/// brackets. If `host` is itself an IP literal it is validated and
/// returned as a single-element vector (no DNS lookup is performed).
///
/// `allow_loopback` is the crate's own test exemption, described on
/// [`enforce_fetch_envelope`]. It permits a loopback destination and
/// nothing else; every other range is refused with it set.
async fn resolve_and_validate(
    host: &str,
    port: u16,
    allow_loopback: bool,
) -> Result<Vec<SocketAddr>> {
    // IP literal fast path. Mirrors the inline check in
    // `is_disallowed_host` but is centralised here so the dialer
    // code does not have to special-case literals.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !(allow_loopback && sbproxy_security::ssrf::canonical_ip(ip).is_loopback())
            && is_disallowed_ip(ip)
        {
            bail!(
                "CIMD host {host:?} resolves to address {ip} which is in a blocked range (SSRF guard)"
            );
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let lookup = tokio::time::timeout(CIMD_DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| {
            anyhow!(
                "CIMD DNS lookup for {host:?} timed out after {:?}",
                CIMD_DNS_TIMEOUT
            )
        })?
        .map_err(|e| anyhow!("CIMD DNS lookup for {host:?} failed: {e}"))?;

    let mut addrs: Vec<SocketAddr> = lookup.collect();
    if addrs.is_empty() {
        bail!("CIMD DNS lookup for {host:?} returned no addresses");
    }

    // Validate every resolved address. If ANY address is in a
    // blocked range we refuse the whole hostname; we cannot let
    // happy-eyeballs randomly pick the bad one. This is the
    // canonical fix for the DNS-rebind / metadata SSRF described
    // in WOR-44.
    for sa in &addrs {
        if allow_loopback && sbproxy_security::ssrf::canonical_ip(sa.ip()).is_loopback() {
            continue;
        }
        if is_disallowed_ip(sa.ip()) {
            bail!(
                "CIMD host {host:?} resolves to address {} which is in a blocked range (SSRF guard)",
                sa.ip()
            );
        }
    }

    // Force the requested port. `lookup_host` does fill in the port
    // we passed, but we override defensively in case a future tokio
    // change relaxes that.
    for sa in &mut addrs {
        sa.set_port(port);
    }
    Ok(addrs)
}

/// Custom `reqwest::dns::Resolve` implementation that hands back a
/// fixed set of pre-validated addresses for exactly one hostname
/// and refuses all other lookups. Pinning the dialed addresses is
/// the second half of the SSRF guard: even if a malicious host
/// races DNS responses (returning a public IP at validation time
/// and a private IP at dial time), the dialer never re-queries
/// DNS and so cannot be tricked.
struct PinnedResolver {
    /// Hostname this resolver answers for. Lowercased, no brackets.
    host: String,
    /// Pre-validated socket addresses. The connector iterates
    /// these in order; happy-eyeballs is fine because every entry
    /// has already passed `is_disallowed_ip`.
    addrs: Vec<SocketAddr>,
}

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let queried = name.as_str().to_ascii_lowercase();
        if queried == self.host {
            let addrs: reqwest::dns::Addrs = Box::new(self.addrs.clone().into_iter());
            Box::pin(std::future::ready(Ok(addrs)))
        } else {
            // Any other hostname (e.g. one introduced by a
            // redirect) is refused. Combined with
            // `redirect::Policy::none()` this is belt-and-braces.
            let err: Box<dyn std::error::Error + Send + Sync> = format!(
                "CIMD pinned resolver refuses lookup for {queried:?}; only {:?} is allowed",
                self.host
            )
            .into();
            Box::pin(std::future::ready(Err(err)))
        }
    }
}

/// Build a one-shot reqwest `Client` configured for fetching CIMD
/// documents safely:
///
///   * `dns_resolver` returns ONLY the validated addresses for the
///     CIMD URL's hostname; redirects to other hosts are rejected.
///   * `redirect::Policy::none()` disables follow-redirect entirely.
///     Redirects are a SSRF vector (the destination host can change
///     between validation and dial), so we make the caller decide
///     whether to re-fetch the new URL through this same code path.
///   * A hard request timeout caps the broker worker hold time.
///
/// The returned client is intentionally a fresh instance per call. A
/// CIMD URL is the `client_id` on an unauthenticated `/authorize`, so
/// it is client-controlled, not operator-controlled: a shared client
/// would have to share one pinned resolver across every hostname a
/// caller can name, which is the same as not pinning at all. The cache
/// in front of the fetch (`CimdCache`) is what keeps the rate down.
async fn build_hardened_client(parsed: &url::Url, allow_loopback: bool) -> Result<Client> {
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("CIMD URL has no host"))?
        .to_ascii_lowercase();
    // Strip surrounding brackets for IPv6 literals so the resolver
    // hostname matches what hyper passes us at dial time.
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = resolve_and_validate(&host, port, allow_loopback).await?;
    let resolver = Arc::new(PinnedResolver {
        host: host.clone(),
        addrs,
    });
    // Built from the workspace's outbound builder so the connect
    // timeout, the pool bounds, and the sbproxy user agent are the same
    // as every other outbound client in this crate; only the resolver
    // and the request timeout are CIMD-specific.
    sbproxy_httpkit::OutboundClientBuilder::new()
        .no_redirects()
        .request_timeout(CIMD_REQUEST_TIMEOUT)
        .into_inner()
        .dns_resolver(resolver)
        .build()
        .map_err(|e| anyhow!("CIMD hardened client build failed: {e}"))
}

/// True when `host` names a loopback destination, in any of the
/// spellings a URL can carry it: the `localhost` name, an IPv4 literal
/// in `127.0.0.0/8`, `[::1]`, or the IPv4-mapped form of either.
fn host_is_loopback(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    ) {
        return true;
    }
    let trimmed = lower.trim_start_matches('[').trim_end_matches(']');
    trimmed
        .parse::<IpAddr>()
        .is_ok_and(|ip| sbproxy_security::ssrf::canonical_ip(ip).is_loopback())
}

/// Enforce the transport half of the CIMD fetch envelope and return the
/// pinned client for `parsed`.
///
/// The envelope is: https only, and a destination that is not private,
/// loopback, link-local, or otherwise reserved. Both halves are
/// unconditional. They used to sit behind `#[cfg(not(test))]`, which
/// meant the guard that shipped was the one no test in this crate could
/// run: `/authorize` reaches CIMD only through a `CimdCache`, and both
/// cache implementations skipped the guard under `cfg(test)`. Mutating
/// or deleting it changed nothing any test observed.
///
/// `allow_insecure_loopback` replaces that `cfg`. It is false in
/// production (no config key sets it, and no constructor outside this
/// crate's own tests can turn it on) and permits exactly one thing: a
/// loopback destination, over http or https, so the cache paths can be
/// driven against a local listener with the real guard compiled in and
/// running. A test that leaves it false sees the production refusal.
async fn enforce_fetch_envelope(
    parsed: &url::Url,
    allow_insecure_loopback: bool,
) -> Result<Client> {
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("CIMD client_id URL has no host"))?;
    let loopback_exempt = allow_insecure_loopback && host_is_loopback(host);
    if parsed.scheme() != "https" && !loopback_exempt {
        bail!(
            "CIMD client_id MUST use https scheme; got {:?}",
            parsed.scheme()
        );
    }
    if !loopback_exempt && is_disallowed_host(host) {
        bail!("CIMD client_id host {host:?} is not externally routable (SSRF guard)");
    }
    build_hardened_client(parsed, loopback_exempt).await
}

/// The three checks every fetched CIMD document must pass, whichever
/// path fetched it.
///
/// This is one function because it used to be three copies and one of
/// them was missing: `EphemeralKvCimdCache::get_or_fetch` parsed the
/// document and returned it without any of them, so a deployment on the
/// storage-backed cache would accept a document declaring
/// `redirect_uris: ["http://attacker.example/cb"]` and relay the
/// authorization result to it.
///
/// # Errors
///
/// Returns an error when the document does not self-identify with the
/// URL it was fetched from, declares no `redirect_uris`, or declares
/// one that OAuth 2.1 s1.5 does not permit.
fn validate_document(doc: &ClientIdMetadataDocument, client_id_url: &str) -> Result<()> {
    // The document MUST self-identify with the URL we fetched it from.
    // Compare strings exactly: clients can normalise their own URLs
    // however they like, but the AS decides which form is canonical.
    if doc.client_id != client_id_url {
        bail!(
            "CIMD document client_id {:?} does not match fetch URL {:?}",
            doc.client_id,
            client_id_url
        );
    }
    if doc.redirect_uris.is_empty() {
        bail!("CIMD document MUST declare at least one redirect_uri");
    }
    for uri in &doc.redirect_uris {
        validate_redirect_uri(uri)?;
    }
    Ok(())
}

// --- Fetch ---

/// Fetches a CIMD document at `client_id_url`, enforcing the security
/// envelope the broker requires. `allow_insecure_loopback` is the
/// crate-internal test exemption described on [`enforce_fetch_envelope`];
/// production callers pass `false`.
///
/// The envelope:
///
///   * URL scheme MUST be `https`.
///   * URL host MUST NOT resolve to a loopback / private / link-local
///     address (SSRF guard).
///   * Response body MUST be no larger than `max_doc_bytes`.
///   * Document MUST contain a `client_id` field matching `client_id_url`
///     exactly.
///   * `redirect_uris` MUST be non-empty and every entry MUST be
///     either `https://` or a `http://localhost` / `http://127.0.0.1`
///     URL (the carve-out OAuth 2.1 §1.5 allows for native clients
///     binding to localhost during development).
pub async fn fetch(
    client_id_url: &str,
    max_doc_bytes: usize,
    allow_insecure_loopback: bool,
) -> Result<FetchedCimd> {
    let parsed = url::Url::parse(client_id_url)
        .map_err(|e| anyhow!("client_id_url is not a valid URL: {e}"))?;

    // The envelope check builds a per-fetch client whose DNS resolver
    // returns ONLY the pre-validated addresses for the host, and which
    // refuses to follow redirects. A shared client cannot pin its DNS
    // resolver to a single hostname and so cannot defend against the
    // rebind vector described in WOR-44.
    let http = enforce_fetch_envelope(&parsed, allow_insecure_loopback).await?;

    let resp = http
        .get(parsed.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| anyhow!("CIMD fetch failed: {e}"))?;

    if !resp.status().is_success() {
        bail!("CIMD fetch returned status {}", resp.status());
    }

    // Parse the Cache-Control max-age and ETag before consuming the body.
    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let max_age = parse_max_age(
        resp.headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );

    // Enforce the size cap by reading the body with `take`. We avoid
    // `Content-Length` because servers may omit it or lie.
    let body_bytes = crate::remote_body::bounded_response_body(resp, max_doc_bytes, "CIMD").await?;

    let doc: ClientIdMetadataDocument = serde_json::from_slice(&body_bytes)
        .map_err(|e| anyhow!("CIMD document parse failed: {e}"))?;
    validate_document(&doc, client_id_url)?;

    Ok(FetchedCimd { doc, etag, max_age })
}

/// Carrier for a freshly-fetched CIMD document along with the cache
/// metadata pulled out of the HTTP response.
#[derive(Clone, Debug)]
pub struct FetchedCimd {
    /// The parsed document.
    pub doc: ClientIdMetadataDocument,
    /// The response's ETag, if any. Cached and replayed on the next
    /// refresh as `If-None-Match`.
    pub etag: Option<String>,
    /// Cache lifetime as parsed from `Cache-Control: max-age=N`. None
    /// means the cache should fall back to its configured TTL.
    pub max_age: Option<Duration>,
}

/// Parse a `Cache-Control` header looking for a `max-age=N` directive.
/// Returns `None` for headers without that directive or for invalid
/// values.
fn parse_max_age(header: Option<&str>) -> Option<Duration> {
    let header = header?;
    for part in header.split(',') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("max-age=") {
            if let Ok(n) = rest.parse::<u64>() {
                return Some(Duration::from_secs(n));
            }
        }
    }
    None
}

/// Validates a single `redirect_uri` per OAuth 2.1 §1.5: https only,
/// with a localhost carve-out for native development clients.
fn validate_redirect_uri(uri: &str) -> Result<()> {
    let parsed = url::Url::parse(uri).map_err(|e| anyhow!("redirect_uri {uri:?} invalid: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                Ok(())
            } else {
                bail!("redirect_uri {uri:?} must be https or http://localhost")
            }
        }
        other => bail!("redirect_uri {uri:?} uses unsupported scheme {other:?}"),
    }
}

// --- Cache ---

/// Cache entry held inside the in-memory CIMD cache.
#[derive(Clone, Debug)]
struct CachedDoc {
    doc: Arc<ClientIdMetadataDocument>,
    etag: Option<String>,
    /// Wall-clock time the entry was written. Compared against the
    /// configured TTL (or the response's max-age, whichever is
    /// shorter) to decide when to refresh.
    fetched_at: Instant,
    /// Effective TTL for this entry. Either the configured default
    /// or `Cache-Control: max-age` from the response, whichever is
    /// smaller.
    ttl: Duration,
}

/// Trait for CIMD caches. Production deployments use the in-memory
/// implementation; the trait exists so a future Redis-backed cache can
/// drop in without changing /authorize.
#[async_trait]
pub trait CimdCache: Send + Sync {
    /// Return a cached document for `client_id_url` if it is younger
    /// than the configured TTL; otherwise re-fetch (replaying the
    /// stored ETag) and update the cache.
    async fn get_or_fetch(
        &self,
        client_id_url: &str,
        max_doc_bytes: usize,
    ) -> Result<Arc<ClientIdMetadataDocument>>;
}

/// In-memory `CimdCache` implementation. Entries are keyed by the full
/// CIMD URL. Cloning is intentionally not derived; share via `Arc`.
pub struct InMemoryCimdCache {
    entries: Mutex<HashMap<String, CachedDoc>>,
    default_ttl: Duration,
    capacity: usize,
    /// See [`enforce_fetch_envelope`]. False on every path an operator
    /// can reach; only this crate's own tests set it.
    allow_insecure_loopback: bool,
}

const DEFAULT_CIMD_CACHE_CAPACITY: usize = 1_024;

/// Floor [`InMemoryCimdCache::new`] applies to a zero TTL.
///
/// A zero would evict every document before the `/authorize` call that
/// fetched it could reuse it, turning the cache into a fetch per
/// request against a client-controlled URL. `McpGatewayConfig` refuses
/// it at startup; this floor is what keeps the constructor total for
/// the callers that build a cache by hand.
const MIN_CIMD_CACHE_TTL: Duration = Duration::from_secs(1);

impl InMemoryCimdCache {
    /// Build a fresh, empty cache with the given default TTL applied
    /// to documents whose response has no `Cache-Control: max-age`.
    ///
    /// A zero `default_ttl` is the one thing [`Self::with_capacity`]
    /// refuses, and it is a caller mistake: every document would be
    /// evicted before the `/authorize` call that fetched it could
    /// reuse it. [`crate::config::validate_startup`] refuses it
    /// outright when CIMD is enabled, so a configured deployment never
    /// reaches the floor below. A caller building a cache by hand gets
    /// `MIN_CIMD_CACHE_TTL` and a `debug_assert`, rather than a panic
    /// that would take a running broker down for one bad argument.
    pub fn new(default_ttl: Duration) -> Self {
        debug_assert!(
            !default_ttl.is_zero(),
            "CIMD cache TTL must be greater than zero"
        );
        Self {
            entries: Mutex::new(HashMap::new()),
            default_ttl: if default_ttl.is_zero() {
                MIN_CIMD_CACHE_TTL
            } else {
                default_ttl
            },
            capacity: DEFAULT_CIMD_CACHE_CAPACITY,
            allow_insecure_loopback: false,
        }
    }

    /// Build a cache that permits a loopback CIMD host over plain http.
    ///
    /// Test-only, and the reason the fetch envelope no longer hides
    /// behind `#[cfg(not(test))]`: a test that wants a local listener
    /// asks for the exemption here, and every other test in this module
    /// runs the production guard.
    #[cfg(test)]
    fn with_loopback_exemption(default_ttl: Duration) -> Self {
        Self {
            allow_insecure_loopback: true,
            ..Self::new(default_ttl)
        }
    }

    /// Build a cache with an explicit entry cap. On insertion at
    /// capacity the oldest live entry is evicted after expired entries
    /// have been reclaimed.
    pub fn with_capacity(default_ttl: Duration, capacity: usize) -> Result<Self> {
        if default_ttl.is_zero() || capacity == 0 {
            bail!("CIMD cache TTL and capacity must be greater than zero");
        }
        Ok(Self {
            entries: Mutex::new(HashMap::new()),
            default_ttl,
            capacity,
            allow_insecure_loopback: false,
        })
    }

    /// Return the cache wrapped in an `Arc` for handler injection.
    pub fn arc(default_ttl: Duration) -> Arc<dyn CimdCache> {
        Arc::new(Self::new(default_ttl))
    }

    /// Fetch with conditional-request semantics. On 304, refresh the
    /// stored `fetched_at` so the entry stays alive for another TTL.
    async fn refresh(
        &self,
        client_id_url: &str,
        max_doc_bytes: usize,
        cached_etag: Option<String>,
    ) -> Result<FetchedCimd> {
        // The plain `fetch` helper does not know about ETags. For
        // conditional refresh we issue the GET ourselves so we can
        // attach `If-None-Match` and treat 304 as "reuse cache". The
        // envelope, the SSRF guard, and the DNS pin are the same ones
        // `fetch` uses, and they run here unconditionally.
        let parsed = url::Url::parse(client_id_url)
            .map_err(|e| anyhow!("client_id_url is not a valid URL: {e}"))?;
        let http = enforce_fetch_envelope(&parsed, self.allow_insecure_loopback).await?;

        let mut req = http
            .get(parsed.as_str())
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(etag) = cached_etag.as_deref() {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("CIMD refresh failed: {e}"))?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            // Caller decides what to do; signal with a sentinel error.
            bail!("__cimd_not_modified__");
        }
        if !resp.status().is_success() {
            bail!("CIMD refresh returned status {}", resp.status());
        }

        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let max_age = parse_max_age(
            resp.headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
        );
        let body_bytes =
            crate::remote_body::bounded_response_body(resp, max_doc_bytes, "CIMD").await?;
        let doc: ClientIdMetadataDocument = serde_json::from_slice(&body_bytes)
            .map_err(|e| anyhow!("CIMD document parse failed: {e}"))?;
        validate_document(&doc, client_id_url)?;
        Ok(FetchedCimd { doc, etag, max_age })
    }

    /// Seed an entry for tests. Lets the unit suite exercise the
    /// hit / TTL / 304 paths without the network.
    #[cfg(test)]
    async fn seed(
        &self,
        client_id_url: &str,
        doc: ClientIdMetadataDocument,
        etag: Option<String>,
        fetched_at: Instant,
        ttl: Duration,
    ) {
        let mut guard = self.entries.lock().await;
        Self::reclaim_and_make_room(&mut guard, client_id_url, self.capacity, Instant::now());
        guard.insert(
            client_id_url.to_string(),
            CachedDoc {
                doc: Arc::new(doc),
                etag,
                fetched_at,
                ttl,
            },
        );
    }

    fn reclaim_and_make_room(
        entries: &mut HashMap<String, CachedDoc>,
        incoming_key: &str,
        capacity: usize,
        now: Instant,
    ) {
        entries.retain(|_, entry| now.duration_since(entry.fetched_at) < entry.ttl);
        if !entries.contains_key(incoming_key) && entries.len() >= capacity {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
    }
}

#[async_trait]
impl CimdCache for InMemoryCimdCache {
    async fn get_or_fetch(
        &self,
        client_id_url: &str,
        max_doc_bytes: usize,
    ) -> Result<Arc<ClientIdMetadataDocument>> {
        let now = Instant::now();
        // Fast path: cached and inside its TTL.
        let cached_etag = {
            let mut guard = self.entries.lock().await;
            guard.retain(|key, entry| {
                key == client_id_url || now.duration_since(entry.fetched_at) < entry.ttl
            });
            if let Some(entry) = guard.get(client_id_url) {
                if now.duration_since(entry.fetched_at) < entry.ttl {
                    return Ok(entry.doc.clone());
                }
                entry.etag.clone()
            } else {
                None
            }
        };

        // Slow path: refresh. We hold no lock during the network call.
        match self
            .refresh(client_id_url, max_doc_bytes, cached_etag.clone())
            .await
        {
            Ok(FetchedCimd { doc, etag, max_age }) => {
                let ttl = match max_age {
                    Some(m) if m < self.default_ttl => m,
                    Some(_) => self.default_ttl,
                    None => self.default_ttl,
                };
                let arc = Arc::new(doc);
                let mut guard = self.entries.lock().await;
                Self::reclaim_and_make_room(
                    &mut guard,
                    client_id_url,
                    self.capacity,
                    Instant::now(),
                );
                guard.insert(
                    client_id_url.to_string(),
                    CachedDoc {
                        doc: arc.clone(),
                        etag,
                        fetched_at: Instant::now(),
                        ttl,
                    },
                );
                Ok(arc)
            }
            Err(e) if e.to_string().contains("__cimd_not_modified__") => {
                // 304: bump the cache entry's fetched_at so it stays
                // alive for another TTL, then return the existing doc.
                let mut guard = self.entries.lock().await;
                if let Some(entry) = guard.get_mut(client_id_url) {
                    entry.fetched_at = Instant::now();
                    return Ok(entry.doc.clone());
                }
                Err(anyhow!("CIMD 304 with no cached entry"))
            }
            Err(e) => Err(e),
        }
    }
}

// --- EphemeralKv-backed cache ---

/// `CimdCache` implementation backed by [`sbproxy_storage::EphemeralKv`].
/// Lets multi-replica deployments share cache state across pods (e.g.
/// via the Redis-backed EphemeralKv) so a freshly-spawned replica
/// does not have to re-fetch every CIMD doc on first traffic.
///
/// ## Tradeoff vs `InMemoryCimdCache`
///
/// The TTL is enforced by the storage backend, so we do NOT keep an
/// etag on the cached entry. When the storage TTL expires, the entry
/// is gone and the next request triggers a plain (non-conditional)
/// GET. The in-memory cache still uses `If-None-Match` and accepts
/// 304 to avoid the transfer; this implementation trades that
/// optimization for shared state across replicas. CIMD docs are
/// small JSON, fetched at TTL boundaries; the cost is rounding error
/// for typical workloads.
///
/// ## Key layout
///
/// `cimd:doc:{client_id_url}`. The URL is used verbatim. It is
/// client-controlled (the `client_id` on an unauthenticated
/// `/authorize`), and no guard bounds its length, so the caller is
/// responsible for the bound: `/authorize` refuses a `client_id`
/// longer than [`crate::config::MAX_CIMD_CLIENT_ID_LEN`] before it
/// reaches the cache.
pub struct EphemeralKvCimdCache {
    store: std::sync::Arc<dyn sbproxy_storage::EphemeralKv>,
    default_ttl: Duration,
    /// See [`enforce_fetch_envelope`]. False on every path an operator
    /// can reach; only this crate's own tests set it.
    allow_insecure_loopback: bool,
}

impl EphemeralKvCimdCache {
    /// Build a cache backed by `store` with the given default TTL
    /// applied when the response carries no `Cache-Control: max-age`.
    pub fn new(
        store: std::sync::Arc<dyn sbproxy_storage::EphemeralKv>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            store,
            default_ttl,
            allow_insecure_loopback: false,
        }
    }

    /// Build a cache that permits a loopback CIMD host over plain http.
    /// Test-only; see [`InMemoryCimdCache::with_loopback_exemption`].
    #[cfg(test)]
    fn with_loopback_exemption(
        store: std::sync::Arc<dyn sbproxy_storage::EphemeralKv>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            allow_insecure_loopback: true,
            ..Self::new(store, default_ttl)
        }
    }

    /// Construct and return as `Arc<dyn CimdCache>` for handler
    /// injection.
    pub fn arc(
        store: std::sync::Arc<dyn sbproxy_storage::EphemeralKv>,
        default_ttl: Duration,
    ) -> Arc<dyn CimdCache> {
        Arc::new(Self::new(store, default_ttl))
    }

    fn cache_key(client_id_url: &str) -> String {
        format!("cimd:doc:{client_id_url}")
    }
}

#[async_trait]
impl CimdCache for EphemeralKvCimdCache {
    async fn get_or_fetch(
        &self,
        client_id_url: &str,
        max_doc_bytes: usize,
    ) -> Result<Arc<ClientIdMetadataDocument>> {
        let key = Self::cache_key(client_id_url);

        // Fast path: cached and inside its TTL (TTL is enforced by
        // the storage backend; a returned `Some` is by definition
        // still valid).
        if let Some(bytes) = self
            .store
            .get(&key)
            .await
            .map_err(|e| anyhow!("CIMD cache get failed: {e}"))?
        {
            if let Ok(doc) = serde_json::from_slice::<ClientIdMetadataDocument>(&bytes) {
                return Ok(Arc::new(doc));
            }
            // Stored bytes that fail to deserialize are treated as a
            // miss; the next put overwrites them. This protects
            // against schema drift across deploys.
        }

        // Slow path: fetch fresh. We do not have an etag (the
        // storage backend evicted it with the doc on TTL expiry), so
        // this is always a plain GET. The slight bandwidth cost is
        // the price of multi-replica sharing.
        let parsed = url::Url::parse(client_id_url)
            .map_err(|e| anyhow!("client_id_url is not a valid URL: {e}"))?;
        let http = enforce_fetch_envelope(&parsed, self.allow_insecure_loopback).await?;
        let resp = http
            .get(parsed.as_str())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("CIMD fetch failed: {e}"))?;
        if !resp.status().is_success() {
            bail!("CIMD fetch returned status {}", resp.status());
        }
        let max_age = parse_max_age(
            resp.headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
        );
        let body = crate::remote_body::bounded_response_body(resp, max_doc_bytes, "CIMD").await?;
        let doc: ClientIdMetadataDocument =
            serde_json::from_slice(&body).map_err(|e| anyhow!("CIMD JSON parse failed: {e}"))?;
        // The same three checks the other two fetch paths make. This
        // implementation used to skip all of them.
        validate_document(&doc, client_id_url)?;

        // Effective TTL: the smaller of the configured default and
        // the response's max-age, when present. Mirrors the
        // in-memory cache's policy.
        let ttl = match max_age {
            Some(m) if m < self.default_ttl => m,
            _ => self.default_ttl,
        };

        // Serialize and cache. A serialization failure is logged but
        // does not fail the request: the caller still gets the
        // freshly-fetched doc; we just lose the cache opportunity.
        if let Ok(bytes) = serde_json::to_vec(&doc) {
            if let Err(e) = self.store.put(&key, bytes::Bytes::from(bytes), ttl).await {
                tracing::warn!(
                    target: "mcp_gateway::cimd",
                    error = %e,
                    url = %sbproxy_security::url_redact::redacted_url(client_id_url),
                    "EphemeralKv put failed; CIMD doc returned uncached"
                );
            }
        }

        Ok(Arc::new(doc))
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn fixture_doc(client_id: &str) -> ClientIdMetadataDocument {
        ClientIdMetadataDocument {
            client_id: client_id.to_string(),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://client.example/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: Some("none".to_string()),
            ..Default::default()
        }
    }

    // --- Pure-function tests ---

    #[tokio::test]
    async fn in_memory_cache_reclaims_expired_unique_keys_and_evicts_oldest() {
        let cache = InMemoryCimdCache::with_capacity(Duration::from_secs(60), 1).unwrap();
        let first_url = "https://first.example/cimd";
        cache
            .seed(
                first_url,
                fixture_doc(first_url),
                None,
                Instant::now() - Duration::from_secs(2),
                Duration::from_secs(1),
            )
            .await;
        let second_url = "https://second.example/cimd";
        cache
            .seed(
                second_url,
                fixture_doc(second_url),
                None,
                Instant::now(),
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(cache.entries.lock().await.len(), 1);
        assert!(cache.entries.lock().await.contains_key(second_url));

        let third_url = "https://third.example/cimd";
        cache
            .seed(
                third_url,
                fixture_doc(third_url),
                None,
                Instant::now(),
                Duration::from_secs(60),
            )
            .await;
        assert_eq!(cache.entries.lock().await.len(), 1);
        assert!(cache.entries.lock().await.contains_key(third_url));
    }

    #[test]
    fn parse_max_age_extracts_first_directive() {
        assert_eq!(
            parse_max_age(Some("max-age=120, public")),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_max_age(Some("public, max-age=60")),
            Some(Duration::from_secs(60))
        );
        assert_eq!(parse_max_age(Some("no-store")), None);
        assert_eq!(parse_max_age(None), None);
    }

    #[test]
    fn allows_scope_subset() {
        let mut doc = fixture_doc("https://client.example/.well-known/cimd");
        doc.scope = Some("read write admin".to_string());
        assert!(doc.allows_scope("read"));
        assert!(doc.allows_scope("read write"));
        assert!(!doc.allows_scope("read delete"));
        assert!(doc.allows_scope("")); // empty request always allowed
    }

    #[test]
    fn allows_scope_when_doc_has_none() {
        let mut doc = fixture_doc("https://client.example/.well-known/cimd");
        doc.scope = None;
        // No declared scope means we delegate the decision to the AS.
        assert!(doc.allows_scope("anything"));
    }

    #[test]
    fn allows_redirect_uri_exact_match_only() {
        let doc = fixture_doc("https://client.example/.well-known/cimd");
        assert!(doc.allows_redirect_uri("https://client.example/cb"));
        assert!(!doc.allows_redirect_uri("https://client.example/cb/"));
        assert!(!doc.allows_redirect_uri("https://evil.example/cb"));
    }

    #[test]
    fn ssrf_guard_blocks_loopback_and_private() {
        assert!(is_disallowed_host("127.0.0.1"));
        assert!(is_disallowed_host("localhost"));
        assert!(is_disallowed_host("[::1]"));
        assert!(is_disallowed_host("10.0.0.1"));
        assert!(is_disallowed_host("192.168.1.1"));
        assert!(is_disallowed_host("169.254.169.254"));
        assert!(!is_disallowed_host("example.com"));
        assert!(!is_disallowed_host("8.8.8.8"));
    }

    #[test]
    fn ssrf_guard_blocks_the_ipv4_mapped_ipv6_spelling() {
        // A dual-stack socket dials `::ffff:10.0.4.7` as the IPv4
        // address 10.0.4.7, so the v6-shaped spelling has to be
        // canonicalized before any range test. The literal fast path in
        // `resolve_and_validate` sees the same string through
        // `is_disallowed_host`, which is what /authorize reaches.
        for mapped in [
            "[::ffff:10.0.4.7]",
            "[::ffff:127.0.0.1]",
            "[::ffff:169.254.169.254]",
            "[::ffff:192.168.1.1]",
            "[::ffff:100.64.0.1]",
        ] {
            assert!(is_disallowed_host(mapped), "{mapped} must not be fetchable");
        }
        // The deprecated IPv4-compatible form is reserved space too.
        assert!(is_disallowed_host("[::10.0.4.7]"));
        // A public address in the same spelling still resolves.
        assert!(!is_disallowed_host("[::ffff:8.8.8.8]"));
    }

    #[tokio::test]
    async fn resolve_and_validate_refuses_a_mapped_private_literal() {
        let refused = resolve_and_validate("::ffff:10.0.4.7", 443, false).await;
        assert!(
            refused.is_err(),
            "the pinned dialer must not be handed a mapped private address"
        );
    }

    #[test]
    fn ssrf_guard_blocks_extended_ranges() {
        // 0.0.0.0/8 (this network).
        assert!(is_disallowed_ip("0.0.0.0".parse().unwrap()));
        assert!(is_disallowed_ip("0.1.2.3".parse().unwrap()));
        // 100.64.0.0/10 (CGNAT).
        assert!(is_disallowed_ip("100.64.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("100.127.255.254".parse().unwrap()));
        // 224.0.0.0/4 (multicast).
        assert!(is_disallowed_ip("224.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("239.255.255.255".parse().unwrap()));
        // 169.254.169.254 (cloud metadata) covered by link-local.
        assert!(is_disallowed_ip("169.254.169.254".parse().unwrap()));
        // 172.16.0.0/12 (private).
        assert!(is_disallowed_ip("172.16.0.1".parse().unwrap()));
        assert!(is_disallowed_ip("172.31.255.255".parse().unwrap()));
        // IPv6 ULA fc00::/7 covers cloud metadata at fd00:ec2::254.
        assert!(is_disallowed_ip("fd00:ec2::254".parse().unwrap()));
        assert!(is_disallowed_ip("fc00::1".parse().unwrap()));
        // IPv6 multicast ff00::/8.
        assert!(is_disallowed_ip("ff02::1".parse().unwrap()));
        // IPv6 link-local fe80::/10.
        assert!(is_disallowed_ip("fe80::1".parse().unwrap()));
        // Public addresses should pass.
        assert!(!is_disallowed_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_disallowed_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolve_and_validate_rejects_metadata_literal() {
        // The cloud metadata literal is the canonical target of the
        // DNS-rebind SSRF this fix defends against. Even if a
        // hostname resolves here, we must refuse before dialing.
        let err = resolve_and_validate("169.254.169.254", 443, false)
            .await
            .expect_err("metadata literal must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("blocked range"),
            "expected blocked-range error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_and_validate_rejects_when_dns_returns_private() {
        // Many systems resolve `localhost` to 127.0.0.1 (and ::1).
        // If a CIMD attacker controls a public-looking hostname
        // whose DNS A record points at 127/8 or 169.254/16 the
        // resolver will hand us those addresses; we must reject
        // every one before the dialer ever sees them.
        let err = resolve_and_validate("localhost", 443, false)
            .await
            .expect_err("localhost DNS result must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("blocked range") || msg.contains("SSRF"),
            "expected SSRF rejection, got: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_and_validate_accepts_public_literal() {
        // IP-literal fast path: a public address skips DNS and is
        // returned verbatim with the requested port pinned.
        let addrs = resolve_and_validate("1.1.1.1", 443, false)
            .await
            .expect("public literal must succeed");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip().to_string(), "1.1.1.1");
        assert_eq!(addrs[0].port(), 443);
    }

    #[tokio::test]
    async fn pinned_resolver_refuses_other_hostnames() {
        // The pinned resolver is the second half of the SSRF guard:
        // a redirect that switches Host header MUST NOT trigger
        // a fresh system-resolver lookup. The resolver replies with
        // an explicit error for any name other than the pinned one.
        use reqwest::dns::Resolve;
        use std::str::FromStr;
        let pinned = PinnedResolver {
            host: "client.example".to_string(),
            addrs: vec![SocketAddr::from(([1, 1, 1, 1], 443))],
        };
        let bad = reqwest::dns::Name::from_str("attacker.example").unwrap();
        let res = pinned.resolve(bad).await;
        assert!(
            res.is_err(),
            "pinned resolver must refuse non-pinned hostnames"
        );
    }

    #[tokio::test]
    async fn hardened_client_does_not_follow_redirects() {
        // Build a redirect-disabled client the same way the
        // production path does (we cannot use build_hardened_client
        // directly because its DNS resolver refuses 127.0.0.1, so
        // we replicate its redirect + timeout policy with a default
        // resolver and aim at a local test server). The test
        // server returns 302 -> /elsewhere; the client must surface
        // the 302 to the caller instead of following it. That is
        // the production guarantee that defends against
        // redirect-based SSRF described in WOR-44.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/cimd.json\r\nContent-Length: 0\r\n\r\n";
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://{}/cimd.json", addr))
            .send()
            .await
            .expect("request must complete without following redirect");
        assert_eq!(
            resp.status().as_u16(),
            302,
            "hardened client must surface the 3xx instead of following it"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_metadata_dns_target() {
        // A public-looking hostname like `metadata.local` may
        // resolve to 169.254.169.254 in test environments where
        // /etc/hosts is configured for it; the production fetch
        // must refuse before dialing. We exercise the same code
        // path by passing the metadata literal as the URL host:
        // resolve_and_validate's IP-literal fast path catches it.
        let err = fetch("https://169.254.169.254/cimd.json", 16 * 1024, false)
            .await
            .expect_err("metadata target must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF") || msg.contains("blocked range"),
            "expected SSRF rejection, got: {msg}"
        );
    }

    #[test]
    fn validate_redirect_uri_accepts_https_and_localhost() {
        assert!(validate_redirect_uri("https://client.example/cb").is_ok());
        assert!(validate_redirect_uri("http://localhost:1234/cb").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1/cb").is_ok());
        assert!(validate_redirect_uri("http://example.com/cb").is_err());
        assert!(validate_redirect_uri("ftp://client.example/cb").is_err());
        assert!(validate_redirect_uri("not-a-url").is_err());
    }

    // --- Server-backed tests ---
    //
    // Stand up a tiny in-process HTTP/1.1 server we can serve canned
    // responses from, so these tests exercise the cache logic without
    // a real network dependency.

    struct TestServer {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
    }

    impl TestServer {
        async fn spawn(responses: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_clone = hits.clone();
            tokio::spawn(async move {
                let mut idx = 0usize;
                loop {
                    let (mut sock, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let mut buf = vec![0u8; 8192];
                    let _ = sock.read(&mut buf).await;
                    let body = if idx < responses.len() {
                        responses[idx].clone()
                    } else {
                        responses.last().cloned().unwrap_or_else(canned_404)
                    };
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                    hits_clone.fetch_add(1, Ordering::SeqCst);
                    idx += 1;
                }
            });
            Self { addr, hits }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
        }
    }

    fn canned_200(body: &str, headers: &[(&str, &str)]) -> String {
        let mut header_block = String::new();
        for (k, v) in headers {
            header_block.push_str(&format!("{k}: {v}\r\n"));
        }
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}",
            body.len(),
            header_block,
            body
        )
    }

    fn canned_304(headers: &[(&str, &str)]) -> String {
        let mut header_block = String::new();
        for (k, v) in headers {
            header_block.push_str(&format!("{k}: {v}\r\n"));
        }
        format!("HTTP/1.1 304 Not Modified\r\n{header_block}\r\n")
    }

    fn canned_404() -> String {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
    }

    #[tokio::test]
    async fn fetch_rejects_http_scheme() {
        let err = fetch("http://client.example/cimd.json", 16 * 1024, false)
            .await
            .expect_err("must reject http");
        let msg = err.to_string();
        assert!(msg.contains("https"), "got error: {msg}");
    }

    #[tokio::test]
    async fn fetch_rejects_loopback_url() {
        let err = fetch("https://127.0.0.1/cimd.json", 16 * 1024, false)
            .await
            .expect_err("must reject loopback");
        let msg = err.to_string();
        assert!(msg.contains("SSRF"), "got error: {msg}");
    }

    #[tokio::test]
    async fn fetch_rejects_private_ip_url() {
        let err = fetch("https://10.0.0.1/cimd.json", 16 * 1024, false)
            .await
            .expect_err("must reject private ip");
        let msg = err.to_string();
        assert!(msg.contains("SSRF"), "got error: {msg}");
    }

    #[tokio::test]
    async fn fetch_rejects_self_id_mismatch() {
        // The document advertises a different client_id than the URL.
        let server = TestServer::spawn(vec![canned_200(
            r#"{"client_id":"https://client.example/other","redirect_uris":["https://client.example/cb"]}"#,
            &[],
        )])
        .await;
        let url = server.url("/cimd.json");
        let err = fetch(&url, 16 * 1024, true)
            .await
            .expect_err("self-id mismatch must fail");
        let msg = err.to_string();
        assert!(msg.contains("does not match fetch URL"), "got error: {msg}");
    }

    #[tokio::test]
    async fn fetch_enforces_size_cap() {
        // Pad the body well above the 256-byte cap.
        let big_body = format!(
            r#"{{"client_id":"X","redirect_uris":["https://client.example/cb"],"client_name":"{}"}}"#,
            "A".repeat(512)
        );
        let server = TestServer::spawn(vec![canned_200(&big_body, &[])]).await;
        let url = server.url("/cimd.json");
        let err = fetch(&url, 256, true)
            .await
            .expect_err("size cap must fail");
        let msg = err.to_string();
        assert!(msg.contains("byte limit"), "got error: {msg}");
    }

    /// Reserve an ephemeral port, build a server listening on it,
    /// and return both the URL and the server. Lets us bake the URL
    /// into the response body before spawning so the document's
    /// `client_id` self-identification check passes.
    async fn spawn_with_known_url(
        path: &str,
        responses_for_url: impl FnOnce(&str) -> Vec<String>,
    ) -> (String, TestServer) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let url = format!("http://{}{}", addr, path);
        let responses = responses_for_url(&url);
        let listener = TcpListener::bind(addr).await.unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let body = if idx < responses.len() {
                    responses[idx].clone()
                } else {
                    responses.last().cloned().unwrap_or_else(canned_404)
                };
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
                hits_clone.fetch_add(1, Ordering::SeqCst);
                idx += 1;
            }
        });
        (url, TestServer { addr, hits })
    }

    #[tokio::test]
    async fn fetch_rejects_empty_redirect_uris() {
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":[]}}"#),
                &[],
            )]
        })
        .await;
        let err = fetch(&url, 16 * 1024, true)
            .await
            .expect_err("empty redirect_uris must fail");
        assert!(err.to_string().contains("redirect_uri"), "got: {err}");
        let _ = server.hits.load(Ordering::SeqCst);
    }

    #[tokio::test]
    async fn fetch_rejects_non_https_redirect_uri() {
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":["http://evil.example/cb"]}}"#),
                &[],
            )]
        })
        .await;
        let err = fetch(&url, 16 * 1024, true)
            .await
            .expect_err("non-https redirect_uri must fail");
        assert!(
            err.to_string().contains("https") || err.to_string().contains("localhost"),
            "got: {err}"
        );
        let _ = server.hits.load(Ordering::SeqCst);
    }

    #[tokio::test]
    async fn cache_hit_within_ttl_skips_network() {
        let cache = InMemoryCimdCache::with_loopback_exemption(Duration::from_secs(60));
        let url = "https://client.example/.well-known/cimd";
        let doc = fixture_doc(url);
        cache
            .seed(
                url,
                doc.clone(),
                Some("\"v1\"".to_string()),
                Instant::now(),
                Duration::from_secs(60),
            )
            .await;
        // Use an unroutable URL to prove we never hit the network.
        let got = cache.get_or_fetch(url, 16 * 1024).await.expect("cache hit");
        assert_eq!(got.client_id, url);
        assert_eq!(got.client_name.as_deref(), Some("Test Client"));
    }

    #[tokio::test]
    async fn cache_ttl_expiry_triggers_refetch_via_etag_304() {
        // Server replies 304 Not Modified to the conditional request.
        let server = TestServer::spawn(vec![canned_304(&[("ETag", "\"v1\"")])]).await;
        let url = server.url("/cimd.json");
        let doc = fixture_doc(&url);
        let cache = InMemoryCimdCache::with_loopback_exemption(Duration::from_secs(60));
        // Seed with fetched_at well in the past so the entry is stale.
        let stale_at = Instant::now() - Duration::from_secs(120);
        cache
            .seed(
                &url,
                doc.clone(),
                Some("\"v1\"".to_string()),
                stale_at,
                Duration::from_secs(30),
            )
            .await;
        let got = cache
            .get_or_fetch(&url, 16 * 1024)
            .await
            .expect("304 keeps entry");
        assert_eq!(got.client_id, url);
        assert!(
            server.hits.load(Ordering::SeqCst) >= 1,
            "server saw request"
        );
    }

    #[tokio::test]
    async fn cache_respects_response_cache_control_max_age() {
        // We need the body's client_id to match the server URL, so we
        // reserve a port first by binding-then-dropping a listener,
        // then construct the responses with that URL, then spawn.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let url = format!("http://{}/cimd.json", addr);
        let body1 = format!(
            r#"{{"client_id":"{}","redirect_uris":["https://client.example/cb"],"client_name":"v1"}}"#,
            url
        );
        let body2 = format!(
            r#"{{"client_id":"{}","redirect_uris":["https://client.example/cb"],"client_name":"v2"}}"#,
            url
        );
        // Spawn explicitly on the reserved address so the URL matches.
        let listener = TcpListener::bind(addr).await.unwrap();
        let responses = [
            canned_200(&body1, &[("Cache-Control", "max-age=1")]),
            canned_200(&body2, &[("Cache-Control", "max-age=60")]),
        ];
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let body = if idx < responses.len() {
                    responses[idx].clone()
                } else {
                    responses.last().cloned().unwrap_or_else(canned_404)
                };
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
                idx += 1;
            }
        });
        let cache = InMemoryCimdCache::with_loopback_exemption(Duration::from_secs(3600));
        let first = cache
            .get_or_fetch(&url, 16 * 1024)
            .await
            .expect("first fetch");
        assert_eq!(first.client_name.as_deref(), Some("v1"));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let second = cache
            .get_or_fetch(&url, 16 * 1024)
            .await
            .expect("second fetch");
        assert_eq!(second.client_name.as_deref(), Some("v2"));
    }

    // --- EphemeralKv-backed cache tests ---

    fn ephemeral_kv() -> std::sync::Arc<dyn sbproxy_storage::EphemeralKv> {
        std::sync::Arc::new(crate::local_store::LocalStore::new())
    }

    // --- The guard on the path /authorize actually runs ---

    #[tokio::test]
    async fn the_in_memory_cache_refuses_a_loopback_document_without_the_exemption() {
        // /authorize never calls `fetch`; it goes through a
        // `CimdCache`. This is the same local listener the tests above
        // use, against a cache built the production way, so the
        // refusal being asserted is the one that ships.
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":["https://client.example/cb"]}}"#),
                &[],
            )]
        })
        .await;
        let cache = InMemoryCimdCache::new(Duration::from_secs(60));
        let refused = cache.get_or_fetch(&url, 16 * 1024).await;
        assert!(
            refused.is_err(),
            "the cache refresh path must run the SSRF guard"
        );
        assert_eq!(
            server.hits.load(Ordering::SeqCst),
            0,
            "the refusal must happen before the dial"
        );
    }

    #[tokio::test]
    async fn the_storage_backed_cache_refuses_a_loopback_document_without_the_exemption() {
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":["https://client.example/cb"]}}"#),
                &[],
            )]
        })
        .await;
        let cache = EphemeralKvCimdCache::new(ephemeral_kv(), Duration::from_secs(60));
        let refused = cache.get_or_fetch(&url, 16 * 1024).await;
        assert!(
            refused.is_err(),
            "the cache fetch path must run the SSRF guard"
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_storage_backed_cache_validates_the_document_it_returns() {
        // A plaintext redirect_uri is exactly what `validate_redirect_uri`
        // exists to refuse, and /authorize's only check for a CIMD
        // client is `doc.allows_redirect_uri`. This implementation used
        // to return the document unvalidated.
        let (url, _server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":["http://attacker.example/cb"]}}"#),
                &[],
            )]
        })
        .await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));
        let refused = cache.get_or_fetch(&url, 16 * 1024).await;
        let message = refused
            .expect_err("plaintext redirect_uri must be refused")
            .to_string();
        assert!(
            message.contains("redirect_uri"),
            "the refusal must name the field: {message}"
        );
    }

    #[tokio::test]
    async fn the_storage_backed_cache_refuses_a_document_naming_another_client_id() {
        let (url, _server) = spawn_with_known_url("/cimd.json", |_u| {
            vec![canned_200(
                r#"{"client_id":"https://other.example/cimd","redirect_uris":["https://client.example/cb"]}"#,
                &[],
            )]
        })
        .await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));
        let refused = cache.get_or_fetch(&url, 16 * 1024).await;
        let message = refused
            .expect_err("a document that names a different client_id must be refused")
            .to_string();
        assert!(
            message.contains("does not match fetch URL"),
            "got: {message}"
        );
    }

    #[tokio::test]
    async fn the_storage_backed_cache_refuses_a_document_with_no_redirect_uris() {
        let (url, _server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(r#"{{"client_id":"{u}","redirect_uris":[]}}"#),
                &[],
            )]
        })
        .await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));
        assert!(cache.get_or_fetch(&url, 16 * 1024).await.is_err());
    }

    #[tokio::test]
    async fn ephemeral_kv_cache_first_fetch_populates_store() {
        let body_doc = |url: &str| {
            format!(
                r#"{{"client_id":"{url}","redirect_uris":["https://client.example/cb"],"client_name":"populate"}}"#
            )
        };
        let (url, server) =
            spawn_with_known_url("/cimd.json", |u| vec![canned_200(&body_doc(u), &[])]).await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));

        let doc = cache
            .get_or_fetch(&url, 16 * 1024)
            .await
            .expect("first fetch");
        assert_eq!(doc.client_name.as_deref(), Some("populate"));
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ephemeral_kv_cache_hit_skips_network() {
        // Single response: if the cache is doing its job, the second
        // call must not hit the upstream and the canned 200 list will
        // not be consulted again.
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(
                    r#"{{"client_id":"{u}","redirect_uris":["https://client.example/cb"],"client_name":"cached"}}"#
                ),
                &[],
            )]
        })
        .await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));

        let _first = cache.get_or_fetch(&url, 16 * 1024).await.unwrap();
        let second = cache.get_or_fetch(&url, 16 * 1024).await.unwrap();

        assert_eq!(second.client_name.as_deref(), Some("cached"));
        assert_eq!(
            server.hits.load(Ordering::SeqCst),
            1,
            "second call must hit the cache, not the network"
        );
    }

    #[tokio::test]
    async fn ephemeral_kv_cache_respects_response_max_age_when_smaller() {
        // Configured default TTL is 60 s but the response says
        // max-age=1. The effective TTL is the smaller of the two.
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            // Two responses: one for the populate, one for the
            // post-expiry refresh.
            let body = format!(
                r#"{{"client_id":"{u}","redirect_uris":["https://client.example/cb"],"client_name":"shortlived"}}"#
            );
            vec![
                canned_200(&body, &[("Cache-Control", "max-age=1")]),
                canned_200(&body, &[("Cache-Control", "max-age=1")]),
            ]
        })
        .await;
        let cache =
            EphemeralKvCimdCache::with_loopback_exemption(ephemeral_kv(), Duration::from_secs(60));

        let _ = cache.get_or_fetch(&url, 16 * 1024).await.unwrap();
        // After 1.2s the entry should be evicted; the next call
        // re-fetches.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = cache.get_or_fetch(&url, 16 * 1024).await.unwrap();

        assert_eq!(
            server.hits.load(Ordering::SeqCst),
            2,
            "TTL expiry must trigger a re-fetch"
        );
    }

    #[tokio::test]
    async fn ephemeral_kv_cache_corrupt_stored_bytes_falls_back_to_fetch() {
        // Pre-seed the storage with garbage at the cache key. Next
        // get_or_fetch must treat it as a miss (the deserialize
        // fallback path) rather than panicking or returning a bad
        // doc. Defends against schema drift across deploys.
        let kv = ephemeral_kv();
        let (url, server) = spawn_with_known_url("/cimd.json", |u| {
            vec![canned_200(
                &format!(
                    r#"{{"client_id":"{u}","redirect_uris":["https://client.example/cb"],"client_name":"recovered"}}"#
                ),
                &[],
            )]
        })
        .await;
        kv.put(
            &EphemeralKvCimdCache::cache_key(&url),
            bytes::Bytes::from_static(b"not valid json"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let cache = EphemeralKvCimdCache::with_loopback_exemption(kv, Duration::from_secs(60));

        let doc = cache.get_or_fetch(&url, 16 * 1024).await.unwrap();
        assert_eq!(doc.client_name.as_deref(), Some("recovered"));
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }
}
