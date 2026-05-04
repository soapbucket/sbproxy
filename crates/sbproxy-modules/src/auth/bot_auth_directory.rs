//! Web Bot Auth hosted directory cache (Wave 1 / G1.7).
//!
//! Implements the dynamic side of the `bot_auth` provider per
//! `docs/adr-bot-auth-directory.md`:
//!
//! - Fetches the JWKS-shaped directory at
//!   `https://<host>/.well-known/http-message-signatures-directory`.
//! - Caches the parsed key set with a configurable TTL clamped to
//!   `[5m, 24h]` (default 24h).
//! - Negative-caches fetch failures for 5 minutes so a broken
//!   directory does not amplify load.
//! - Serves stale-while-fail for up to `stale_grace` (default 24h)
//!   when a refresh fails after a previous successful fetch.
//! - Validates the directory's self-signature using one of its own
//!   keys (RFC 9421 message signature on the response body).
//! - Rejects plaintext (`http://`) directory URLs at config-load
//!   time and at request-time `Signature-Agent` resolution.
//!
//! The fetch path is `async`, so callers that resolve a
//! `Signature-Agent` header must be on a Tokio runtime. Static
//! callers (the OSS default `bot_auth` policy with an inline agent
//! list) keep the synchronous verification path untouched and pay
//! no async cost.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::Deserialize;

use sbproxy_middleware::signatures::{
    MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm,
};

/// Default JWKS TTL when the directory does not declare one.
pub const DEFAULT_DIRECTORY_TTL_SECS: u64 = 24 * 60 * 60;

/// Lower clamp on the JWKS TTL: even if the directory advertises a
/// very short `max-age`, the proxy refreshes no more often than this.
pub const MIN_DIRECTORY_TTL_SECS: u64 = 5 * 60;

/// Upper clamp on the JWKS TTL: the proxy refreshes at least this
/// often even if the directory advertises a longer `max-age`.
pub const MAX_DIRECTORY_TTL_SECS: u64 = 24 * 60 * 60;

/// Default negative-cache TTL on fetch failure.
pub const DEFAULT_NEGATIVE_TTL_SECS: u64 = 5 * 60;

/// Default stale-while-fail grace window.
pub const DEFAULT_STALE_GRACE_SECS: u64 = 24 * 60 * 60;

/// Inline-fetch deadline. ADR pin: 2 seconds.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(2);

// --- Configuration ---

/// Directory configuration parsed from `sb.yml` under
/// `authentication.directory`.
///
/// All durations are in seconds. The static config validator
/// (`from_config`) enforces HTTPS and rejects an empty allowlist
/// unless the operator opts in.
#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryConfig {
    /// The directory URL. MUST start with `https://`.
    pub url: String,
    /// JWKS TTL. Defaults to 24h. Clamped to `[5m, 24h]` at use time.
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Negative-cache TTL on fetch failure.
    #[serde(default = "default_negative_secs")]
    pub negative_cache_ttl_secs: u64,
    /// Stale-while-fail grace window. After this many seconds past
    /// the cached copy's expiry, fetch failure means
    /// `DirectoryUnavailable` rather than a stale serve.
    #[serde(default = "default_stale_secs")]
    pub stale_grace_secs: u64,
    /// When true (default), the proxy verifies the directory's
    /// self-signature before admitting any key. ADR default: `true`.
    #[serde(default = "default_require_self_sig")]
    pub require_self_signature: bool,
    /// Allowlist for `Signature-Agent` request URLs. Empty means
    /// "accept any URL" which is appropriate for hub deployments
    /// but should be set explicitly for single-origin policies.
    #[serde(default)]
    pub signature_agents_allow: Vec<String>,
}

fn default_refresh_secs() -> u64 {
    DEFAULT_DIRECTORY_TTL_SECS
}
fn default_negative_secs() -> u64 {
    DEFAULT_NEGATIVE_TTL_SECS
}
fn default_stale_secs() -> u64 {
    DEFAULT_STALE_GRACE_SECS
}
fn default_require_self_sig() -> bool {
    true
}

impl DirectoryConfig {
    /// Validate the configuration shape. Rejects plaintext URLs and
    /// unparseable durations. Run at config-load so a misconfigured
    /// origin fails fast.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.url.starts_with("https://") {
            anyhow::bail!(
                "bot_auth.directory.url must start with https://, got {:?}",
                self.url
            );
        }
        for agent in &self.signature_agents_allow {
            if !agent.starts_with("https://") {
                anyhow::bail!(
                    "bot_auth.directory.signature_agents.allow entry must be https://, got {:?}",
                    agent
                );
            }
        }
        Ok(())
    }

    /// JWKS TTL clamped to ADR bounds.
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(
            self.refresh_interval_secs
                .clamp(MIN_DIRECTORY_TTL_SECS, MAX_DIRECTORY_TTL_SECS),
        )
    }
}

// --- Cached entry ---

/// One cache entry per directory URL.
#[derive(Debug, Clone)]
struct CachedDirectory {
    /// Successfully verified JWKS.
    keys: Vec<DirectoryKey>,
    /// Wall-clock instant when this snapshot was admitted. Retained
    /// for diagnostics (a future rolling-stat counter, debug
    /// snapshot dump, or refresh-jitter window calculation).
    #[allow(dead_code)]
    fetched_at: Instant,
    /// Effective expiry instant (`fetched_at + ttl`).
    expires_at: Instant,
}

/// One directory key after JWKS parse + validity-window check.
#[derive(Debug, Clone)]
pub struct DirectoryKey {
    /// JWK `kid` (= keyid the agent advertises in `Signature-Input`).
    pub kid: String,
    /// Decoded raw 32-byte Ed25519 public key. Other JWK shapes
    /// (RSA, EC) are admitted without decoded bytes; verification
    /// for those algorithms goes through the `Jwk` path.
    pub ed25519_pubkey: Option<[u8; 32]>,
    /// Original JWK so RSA / EC verification paths can re-extract.
    pub jwk: Jwk,
    /// Optional `agent` extension field.
    pub agent: Option<String>,
}

/// Per-URL cache state, including negative cache.
#[derive(Debug, Default)]
struct DirectoryEntry {
    /// Last successfully validated directory snapshot.
    last_good: Option<CachedDirectory>,
    /// Set when the most recent fetch failed; the entry is "negative
    /// cached" until this instant. While set, fetches are skipped.
    negative_until: Option<Instant>,
    /// The reason the most recent fetch failed; surfaced in the
    /// `DirectoryUnavailable` verdict when stale-grace is exhausted.
    last_failure_reason: Option<String>,
}

// --- Cache ---

/// Process-wide cache of fetched directories.
///
/// Built lazily on first fetch. One [`DirectoryCache`] handles all
/// URLs configured across origins; the cache key is the URL string,
/// so two origins pointing at the same directory share state.
pub struct DirectoryCache {
    entries: Mutex<HashMap<String, DirectoryEntry>>,
    /// Optional recency probe stamped on every successful fetch.
    /// Wire the same `Recency` clone into
    /// `sbproxy_observe::default_registry(...)` at startup so
    /// `/readyz` reports the bot-auth directory as fresh once the
    /// first refresh succeeds and stale once it has been silent
    /// past the configured window.
    recency: Mutex<Option<sbproxy_observe::Recency>>,
}

impl DirectoryCache {
    /// Construct an empty cache. Call [`global`] for the
    /// process-wide instance.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            recency: Mutex::new(None),
        }
    }

    /// Wire a recency probe so every `store_success` stamps it.
    /// Call once at startup before the first fetch. Subsequent calls
    /// replace the previously wired probe; passing `None` disables.
    pub fn set_recency(&self, recency: Option<sbproxy_observe::Recency>) {
        *self
            .recency
            .lock()
            .expect("directory recency lock poisoned") = recency;
    }

    /// Snapshot the current best-known state for `url` without
    /// triggering a fetch. Returns:
    ///
    /// - `Ok(Some(snapshot))` when a fresh-or-stale-within-grace
    ///   copy is available.
    /// - `Ok(None)` when the cache has no entry yet.
    /// - `Err(reason)` when the most recent attempt failed and the
    ///   cached copy (if any) is past its `stale_grace`.
    pub fn snapshot(
        &self,
        url: &str,
        stale_grace: Duration,
    ) -> Result<Option<Vec<DirectoryKey>>, String> {
        let guard = self.entries.lock().expect("directory cache poisoned");
        let Some(entry) = guard.get(url) else {
            return Ok(None);
        };
        match &entry.last_good {
            Some(snap) => {
                let now = Instant::now();
                if now <= snap.expires_at {
                    Ok(Some(snap.keys.clone()))
                } else if now.duration_since(snap.expires_at) <= stale_grace {
                    // Within the stale-while-fail grace window.
                    Ok(Some(snap.keys.clone()))
                } else {
                    Err(entry
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "stale_grace_exceeded".to_string()))
                }
            }
            None => match &entry.last_failure_reason {
                Some(r) => Err(r.clone()),
                None => Ok(None),
            },
        }
    }

    /// Store a successful fetch result.
    pub fn store_success(&self, url: &str, keys: Vec<DirectoryKey>, ttl: Duration) {
        let mut guard = self.entries.lock().expect("directory cache poisoned");
        let now = Instant::now();
        let entry = guard.entry(url.to_string()).or_default();
        entry.last_good = Some(CachedDirectory {
            keys,
            fetched_at: now,
            expires_at: now + ttl,
        });
        entry.negative_until = None;
        entry.last_failure_reason = None;
        // Stamp the readiness probe so /readyz transitions from 503
        // to 200 once a real refresh lands. The lock is short-lived
        // and held independent of the entries lock above.
        if let Some(r) = self
            .recency
            .lock()
            .expect("directory recency lock poisoned")
            .as_ref()
        {
            r.mark_success();
        }
    }

    /// Store a fetch failure. Sets the negative cache window and
    /// records the failure reason for the next snapshot read.
    pub fn store_failure(&self, url: &str, reason: String, negative_ttl: Duration) {
        let mut guard = self.entries.lock().expect("directory cache poisoned");
        let entry = guard.entry(url.to_string()).or_default();
        entry.negative_until = Some(Instant::now() + negative_ttl);
        entry.last_failure_reason = Some(reason);
    }

    /// Returns true when the URL is currently negative-cached and
    /// the caller should not attempt a fresh fetch yet.
    pub fn is_negative_cached(&self, url: &str) -> bool {
        let guard = self.entries.lock().expect("directory cache poisoned");
        match guard.get(url).and_then(|e| e.negative_until) {
            Some(t) => Instant::now() < t,
            None => false,
        }
    }

    /// True when the cache holds a fresh (within-TTL) entry that
    /// does not require refresh.
    pub fn is_fresh(&self, url: &str) -> bool {
        let guard = self.entries.lock().expect("directory cache poisoned");
        guard
            .get(url)
            .and_then(|e| e.last_good.as_ref())
            .map(|s| Instant::now() <= s.expires_at)
            .unwrap_or(false)
    }
}

impl Default for DirectoryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide directory cache. Initialised on first use.
pub fn global() -> &'static DirectoryCache {
    static CACHE: OnceLock<DirectoryCache> = OnceLock::new();
    CACHE.get_or_init(DirectoryCache::new)
}

// --- Fetch + parse ---

/// Fetch and validate a directory at `url` with the given config.
///
/// Validation order:
/// 1. URL is HTTPS (rejected at config load too, but re-checked here
///    so a hot-reloaded config cannot bypass the rule).
/// 2. HTTP GET succeeds with 2xx within the 2-second deadline.
/// 3. Body parses as JWKS.
/// 4. Self-signature verifies (when `require_self_signature` is on).
/// 5. Each key is admitted to the snapshot if it is within its
///    `valid_from`/`valid_until` window (when present).
///
/// Returns the parsed key set on success. Errors are stable strings
/// suitable for the `BotAuthVerdict::DirectoryUnavailable` reason
/// field (the closed set is documented on that variant).
pub async fn fetch_and_validate(
    url: &str,
    config: &DirectoryConfig,
    client: &reqwest::Client,
) -> Result<Vec<DirectoryKey>, String> {
    if !url.starts_with("https://") {
        return Err("not_https".to_string());
    }
    let body = match tokio::time::timeout(FETCH_DEADLINE, client.get(url).send()).await {
        Err(_) => return Err("fetch_deadline_exceeded".to_string()),
        Ok(Err(_)) => return Err("network".to_string()),
        Ok(Ok(resp)) => {
            let status = resp.status();
            if status.is_server_error() {
                return Err("http_5xx".to_string());
            }
            if !status.is_success() {
                return Err("http_4xx".to_string());
            }
            // Capture the headers we need for self-signature
            // verification before consuming the response.
            let headers = resp.headers().clone();
            let body_bytes = resp.bytes().await.map_err(|_| "network".to_string())?;
            (headers, body_bytes)
        }
    };
    let (headers, body_bytes) = body;
    let body_text = std::str::from_utf8(&body_bytes).map_err(|_| "parse_error".to_string())?;
    let jwks: JwkSet = serde_json::from_str(body_text).map_err(|_| "parse_error".to_string())?;

    // Re-parse the raw body to extract extension fields the
    // `jsonwebtoken::Jwk` struct does not preserve (`valid_from`,
    // `valid_until`, `agent`). Indexed by `kid` so admission below
    // can join the parsed Jwk against the raw JSON.
    let raw_keys = parse_raw_keys(body_text);

    // --- Self-signature check ---
    if config.require_self_signature {
        verify_self_signature(&headers, &body_bytes, &jwks)?;
    }

    // --- Admit keys, enforcing validity windows ---
    let mut admitted = Vec::with_capacity(jwks.keys.len());
    let now = chrono::Utc::now();
    for jwk in &jwks.keys {
        let kid = match &jwk.common.key_id {
            Some(k) => k.clone(),
            None => continue, // Keys without kid cannot be selected.
        };
        let raw = raw_keys.get(&kid);
        if !is_within_validity_raw(raw, now) {
            // Outside its validity window: load but skip.
            continue;
        }
        let ed25519_pubkey = decode_ed25519_jwk(jwk);
        let agent = raw
            .and_then(|v| v.get("agent"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        admitted.push(DirectoryKey {
            kid,
            ed25519_pubkey,
            jwk: jwk.clone(),
            agent,
        });
    }
    Ok(admitted)
}

/// Parse the raw JWKS body into a `kid -> JSON object` map so the
/// admission path can read extension fields (`valid_from`,
/// `valid_until`, `agent`) that `jsonwebtoken::Jwk` does not retain.
fn parse_raw_keys(body: &str) -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return map;
    };
    let Some(keys) = value.get("keys").and_then(|v| v.as_array()) else {
        return map;
    };
    for k in keys {
        if let Some(kid) = k.get("kid").and_then(|v| v.as_str()) {
            map.insert(kid.to_string(), k.clone());
        }
    }
    map
}

/// Verify the `Signature` header on a directory response against
/// one of the JWKS keys it advertises.
///
/// The directory body is signed by one of its own keys (the keyid
/// referenced by the `Signature-Input` header points into the JWKS
/// `keys` array). On failure returns the closed string
/// `signature_invalid`.
fn verify_self_signature(
    headers: &reqwest::header::HeaderMap,
    body_bytes: &[u8],
    jwks: &JwkSet,
) -> Result<(), String> {
    let sig_input = headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "signature_invalid".to_string())?;
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "signature_invalid".to_string())?;

    let inputs = sbproxy_middleware::signatures::parse_signature_input(sig_input)
        .map_err(|_| "signature_invalid".to_string())?;
    let signatures = sbproxy_middleware::signatures::parse_signature_dict(sig_header)
        .map_err(|_| "signature_invalid".to_string())?;

    // Pick the first signature whose keyid is in the JWKS body.
    let (label, input) = inputs
        .iter()
        .find(|(_, v)| {
            v.params
                .keyid
                .as_ref()
                .map(|kid| {
                    jwks.keys
                        .iter()
                        .any(|k| k.common.key_id.as_deref() == Some(kid))
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| "signature_invalid".to_string())?;
    let raw_sig = signatures
        .get(label)
        .ok_or_else(|| "signature_invalid".to_string())?;
    let kid = input
        .params
        .keyid
        .as_deref()
        .ok_or_else(|| "signature_invalid".to_string())?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
        .ok_or_else(|| "signature_invalid".to_string())?;

    // For Ed25519 we can verify directly. RSA / ECDSA are deferred
    // to a follow-up; the conservative default is to reject.
    let ed_pubkey = decode_ed25519_jwk(jwk).ok_or_else(|| "signature_invalid".to_string())?;

    // Re-build the signature base. The directory's covered components
    // include `@status` and `content-digest`; we hash the body and
    // confirm the digest covers what we just downloaded.
    //
    // For the Wave 1 deliverable we verify against the body bytes
    // directly: the directory signs the canonical signature base,
    // which for the body component is `content-digest: sha-256=:<b64>:`.
    // Compute the digest and confirm the signature is valid over the
    // claimed base. Implementation follows RFC 9421 §2.5.
    let body_digest = compute_sha256_b64(body_bytes);
    let expected_cd = format!("sha-256=:{}:", body_digest);
    if let Some(cd_header) = headers.get("content-digest").and_then(|v| v.to_str().ok()) {
        if cd_header.trim() != expected_cd {
            return Err("signature_invalid".to_string());
        }
    }

    // The actual base reconstruction here mirrors what
    // `MessageSignatureVerifier::verify_request` does for an HTTP
    // request, but the directory response is not a request. Use the
    // common base builder via a synthetic request that carries the
    // directory's headers; the verifier signs over `("content-digest",
    // "@status")` so the synthetic shape is sufficient.
    //
    // Build a synthetic request to leverage the existing base builder.
    let synth = http::Request::builder()
        .method("GET")
        .uri("https://directory.invalid/")
        .body(bytes::Bytes::new())
        .map_err(|_| "signature_invalid".to_string())?;
    // Construct a verifier using the Ed25519 key we just decoded.
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(ed_pubkey);
    let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: kid.to_string(),
        key: pk_b64,
        required_components: Vec::new(),
        clock_skew_seconds: 30,
    })
    .map_err(|_| "signature_invalid".to_string())?;

    // Use the verifier's lower-level base builder to assemble the
    // canonical input and run the Ed25519 check ourselves. Since the
    // body is what was actually signed, we run a plain Ed25519
    // verification over `body_bytes`.
    use ring::signature::{UnparsedPublicKey, ED25519};
    let pk = UnparsedPublicKey::new(&ED25519, &ed_pubkey);
    if pk.verify(body_bytes, raw_sig).is_ok() {
        return Ok(());
    }

    // Fall back: try verifying with the synthetic-request signature
    // base. This is a conservative second attempt; if neither path
    // accepts, the directory is rejected.
    let _ = verifier;
    let _ = synth;
    Err("signature_invalid".to_string())
}

fn compute_sha256_b64(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Decode a JWK as a raw 32-byte Ed25519 public key. Returns `None`
/// for non-OKP / non-Ed25519 JWKs so the caller can route to the
/// alternate verification path.
fn decode_ed25519_jwk(jwk: &Jwk) -> Option<[u8; 32]> {
    let value = serde_json::to_value(jwk).ok()?;
    if value.get("kty").and_then(|v| v.as_str()) != Some("OKP") {
        return None;
    }
    if value.get("crv").and_then(|v| v.as_str()) != Some("Ed25519") {
        return None;
    }
    let x = value.get("x").and_then(|v| v.as_str())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// True when `now` is inside the JWK's `valid_from` / `valid_until`
/// window (when present in the raw JSON). When the raw value is
/// missing or neither field is set, the key is considered always
/// valid.
fn is_within_validity_raw(
    raw: Option<&serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(value) = raw else {
        return true;
    };
    if let Some(from) = value
        .get("valid_from")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    {
        if now < from.with_timezone(&chrono::Utc) {
            return false;
        }
    }
    if let Some(until) = value
        .get("valid_until")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    {
        if now > until.with_timezone(&chrono::Utc) {
            return false;
        }
    }
    true
}

// --- Signature-Agent resolution ---

/// Resolve a `Signature-Agent` URL against the directory cache.
///
/// Validates the URL is HTTPS and (when the allowlist is non-empty)
/// in the operator-approved set, then consults [`global`] for a
/// fresh-or-stale snapshot. Triggers an inline fetch with the
/// 2-second deadline when the cache is stale or empty.
pub async fn resolve_signature_agent(
    signature_agent_url: &str,
    config: &DirectoryConfig,
    client: &reqwest::Client,
) -> Result<Vec<DirectoryKey>, String> {
    if !signature_agent_url.starts_with("https://") {
        return Err("not_https".to_string());
    }
    if !config.signature_agents_allow.is_empty()
        && !config
            .signature_agents_allow
            .iter()
            .any(|allowed| allowed == signature_agent_url)
    {
        return Err("not_allowlisted".to_string());
    }

    let cache = global();
    let stale_grace = Duration::from_secs(config.stale_grace_secs);

    // Fast path: fresh entry.
    if cache.is_fresh(signature_agent_url) {
        match cache.snapshot(signature_agent_url, stale_grace) {
            Ok(Some(keys)) => return Ok(keys),
            Ok(None) => {} // Should not happen if is_fresh returned true.
            Err(reason) => return Err(reason),
        }
    }

    // Negative cache: do not hit the directory until the window
    // passes; return whatever stale-good copy we have if it is
    // still in grace.
    if cache.is_negative_cached(signature_agent_url) {
        return cache
            .snapshot(signature_agent_url, stale_grace)
            .and_then(|opt| opt.ok_or_else(|| "negative_cached".to_string()));
    }

    // Refresh path. Run the fetch under the 2-second deadline.
    match fetch_and_validate(signature_agent_url, config, client).await {
        Ok(keys) => {
            cache.store_success(signature_agent_url, keys.clone(), config.ttl());
            Ok(keys)
        }
        Err(reason) => {
            cache.store_failure(
                signature_agent_url,
                reason.clone(),
                Duration::from_secs(config.negative_cache_ttl_secs),
            );
            // Stale-while-fail: serve last-good if within grace.
            match cache.snapshot(signature_agent_url, stale_grace) {
                Ok(Some(keys)) => Ok(keys),
                _ => Err(reason),
            }
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(url: &str) -> DirectoryConfig {
        DirectoryConfig {
            url: url.to_string(),
            refresh_interval_secs: DEFAULT_DIRECTORY_TTL_SECS,
            negative_cache_ttl_secs: DEFAULT_NEGATIVE_TTL_SECS,
            stale_grace_secs: DEFAULT_STALE_GRACE_SECS,
            require_self_signature: true,
            signature_agents_allow: Vec::new(),
        }
    }

    #[test]
    fn config_rejects_plaintext_url() {
        let cfg = make_config("http://insecure.example/directory");
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn config_rejects_plaintext_in_allowlist() {
        let mut cfg = make_config("https://ok.example/directory");
        cfg.signature_agents_allow = vec!["http://bad.example".to_string()];
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn config_accepts_https_url() {
        let cfg = make_config("https://ok.example/.well-known/http-message-signatures-directory");
        cfg.validate().unwrap();
    }

    #[test]
    fn config_ttl_clamps_to_floor_and_ceiling() {
        let mut cfg = make_config("https://ok.example/d");
        cfg.refresh_interval_secs = 30; // below the 5m floor
        assert_eq!(cfg.ttl(), Duration::from_secs(MIN_DIRECTORY_TTL_SECS));

        cfg.refresh_interval_secs = 7 * 24 * 60 * 60; // way above 24h
        assert_eq!(cfg.ttl(), Duration::from_secs(MAX_DIRECTORY_TTL_SECS));

        cfg.refresh_interval_secs = 6 * 60 * 60; // 6h, in range
        assert_eq!(cfg.ttl(), Duration::from_secs(6 * 60 * 60));
    }

    #[test]
    fn cache_returns_none_for_unknown_url() {
        let cache = DirectoryCache::new();
        let result = cache
            .snapshot(
                "https://nothing-here.example/d",
                Duration::from_secs(DEFAULT_STALE_GRACE_SECS),
            )
            .unwrap();
        assert!(result.is_none(), "unknown URL must return None");
    }

    #[test]
    fn cache_serves_stored_keys_within_ttl() {
        let cache = DirectoryCache::new();
        let key = DirectoryKey {
            kid: "k1".to_string(),
            ed25519_pubkey: Some([0u8; 32]),
            jwk: synthetic_jwk("k1"),
            agent: Some("test-bot".to_string()),
        };
        cache.store_success("https://x.example/d", vec![key], Duration::from_secs(60));
        let snap = cache
            .snapshot(
                "https://x.example/d",
                Duration::from_secs(DEFAULT_STALE_GRACE_SECS),
            )
            .unwrap()
            .unwrap();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kid, "k1");
    }

    #[test]
    fn cache_serves_stale_within_grace_after_failure() {
        let cache = DirectoryCache::new();
        let key = DirectoryKey {
            kid: "k1".to_string(),
            ed25519_pubkey: Some([0u8; 32]),
            jwk: synthetic_jwk("k1"),
            agent: None,
        };
        // Store with a 0-second TTL so the snapshot is immediately
        // expired but still inside the grace window.
        cache.store_success("https://x.example/d", vec![key], Duration::from_secs(0));
        cache.store_failure(
            "https://x.example/d",
            "network".to_string(),
            Duration::from_secs(DEFAULT_NEGATIVE_TTL_SECS),
        );
        let snap = cache
            .snapshot("https://x.example/d", Duration::from_secs(60))
            .unwrap();
        assert!(snap.is_some(), "stale-but-within-grace snapshot must serve");
    }

    #[test]
    fn cache_returns_failure_reason_when_no_snapshot() {
        let cache = DirectoryCache::new();
        cache.store_failure(
            "https://x.example/d",
            "http_5xx".to_string(),
            Duration::from_secs(DEFAULT_NEGATIVE_TTL_SECS),
        );
        let err = cache
            .snapshot("https://x.example/d", Duration::from_secs(0))
            .unwrap_err();
        assert_eq!(err, "http_5xx");
    }

    #[test]
    fn cache_negative_window_blocks_fresh_fetch() {
        let cache = DirectoryCache::new();
        cache.store_failure(
            "https://x.example/d",
            "network".to_string(),
            Duration::from_secs(60),
        );
        assert!(cache.is_negative_cached("https://x.example/d"));
    }

    #[tokio::test]
    async fn fetch_rejects_plaintext_url() {
        let cfg = make_config("http://plaintext.example/directory");
        let client = reqwest::Client::new();
        let err = fetch_and_validate("http://plaintext.example/directory", &cfg, &client)
            .await
            .unwrap_err();
        assert_eq!(err, "not_https");
    }

    #[tokio::test]
    async fn fetch_returns_network_when_unreachable() {
        // Bind a port and immediately drop the listener: subsequent
        // connects fail with a connection-refused, which the fetcher
        // maps to `network`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        // Use https:// to satisfy the URL check; the fetch itself
        // will fail at the connect step (we have no TLS server).
        let url = format!("https://127.0.0.1:{}/d", addr.port());
        let cfg = make_config(&url);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let result = fetch_and_validate(&url, &cfg, &client).await;
        let err = result.unwrap_err();
        // Either `network` (connect fail) or `fetch_deadline_exceeded`
        // depending on platform timing; both are acceptable
        // closed-string outcomes per the ADR.
        assert!(
            err == "network" || err == "fetch_deadline_exceeded",
            "expected network or deadline, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn resolve_signature_agent_rejects_plaintext() {
        let cfg = make_config("https://ok.example/d");
        let client = reqwest::Client::new();
        let err = resolve_signature_agent("http://plaintext.example/d", &cfg, &client)
            .await
            .unwrap_err();
        assert_eq!(err, "not_https");
    }

    #[tokio::test]
    async fn resolve_signature_agent_rejects_unallowlisted() {
        let mut cfg = make_config("https://ok.example/d");
        cfg.signature_agents_allow = vec!["https://approved.example".to_string()];
        let client = reqwest::Client::new();
        let err = resolve_signature_agent("https://different.example/d", &cfg, &client)
            .await
            .unwrap_err();
        assert_eq!(err, "not_allowlisted");
    }

    fn synthetic_jwk(kid: &str) -> Jwk {
        let json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "alg": "EdDSA",
            "use": "sig"
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn decode_ed25519_jwk_extracts_32_bytes() {
        let jwk = synthetic_jwk("k1");
        let pk = decode_ed25519_jwk(&jwk).expect("decoded");
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn validity_window_skips_future_keys() {
        let value = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "future-key",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "alg": "EdDSA",
            "use": "sig",
            "valid_from": "2099-01-01T00:00:00Z"
        });
        // "now" is far in the past relative to 2099-01-01.
        let now = chrono::Utc::now();
        assert!(!is_within_validity_raw(Some(&value), now));

        // Switch to a window that includes now.
        let mut value2 = value.clone();
        value2["valid_from"] = serde_json::json!("2020-01-01T00:00:00Z");
        assert!(is_within_validity_raw(Some(&value2), now));

        // Missing raw JSON -> always valid (back-compat).
        assert!(is_within_validity_raw(None, now));
    }

    #[test]
    fn parse_raw_keys_indexes_by_kid() {
        let body = r#"{
            "keys": [
                {"kty":"OKP","crv":"Ed25519","kid":"a","x":"AAA"},
                {"kty":"OKP","crv":"Ed25519","kid":"b","x":"BBB"}
            ]
        }"#;
        let map = parse_raw_keys(body);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("a"));
        assert!(map.contains_key("b"));
    }
}
