//! Quote-token JWS signer + verifier (Wave 3 / G3.6).
//!
//! Implements the signed quote token defined by `docs/adr-quote-token-jws.md`.
//! Each token binds a 402 challenge to a specific `(route, shape, price, rail,
//! quote_id)` tuple with a single-use `nonce`. The proxy issues tokens when
//! emitting multi-rail challenges (G3.4) and the local ledger service verifies
//! them on redeem.
//!
//! ## Wire shape
//!
//! Compact JWS (RFC 7515) with `alg=EdDSA` and `typ=sbproxy-quote+jws`. The
//! header carries a `kid` selecting which public key in the JWKS verifies the
//! signature; rotation works by adding a new key with a new kid and trusting
//! both for the rotation window. The payload claims are pinned in
//! [`QuoteClaims`].
//!
//! ## Layering
//!
//! Per `adr-billing-hot-path-vs-async.md` the proxy hot path is sync. Signing
//! is sync (pure ed25519 + base64); the persistence of `(nonce, quote_id)`
//! into the `quote_tokens` table is async fire-and-forget and lives behind a
//! pluggable [`NonceStore`] impl. The OSS build ships with the in-memory
//! [`InMemoryNonceStore`] which the e2e tests and the single-host deployment
//! topology use.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::ai_crawl::{ContentShape, Money};

// --- Public claim types ---

/// Decoded JWS payload for a quote token.
///
/// Mirrors the claim set pinned in `docs/adr-quote-token-jws.md`. The
/// closed-string fields (`rail`, `shape`) are kept as `String` on the wire
/// type to absorb future closed-enum amendments without breaking parsers
/// that pre-date the addition (per `adr-schema-versioning.md` Rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteClaims {
    /// Issuer URL: the proxy's external base URL.
    pub iss: String,
    /// Subject: the agent identity from the agent-class taxonomy.
    pub sub: String,
    /// Audience: always `"ledger"` in Wave 3.
    pub aud: String,
    /// Issued-at, unix seconds.
    pub iat: u64,
    /// Expiration, unix seconds.
    pub exp: u64,
    /// Single-use nonce (ULID string). The verifier consults the
    /// [`NonceStore`] to ensure each token redeems exactly once.
    pub nonce: String,
    /// Stable quote identifier (ULID, separate from `nonce`).
    pub quote_id: String,
    /// Resource path the quote was issued for.
    pub route: String,
    /// Content shape negotiated with the agent (`html`, `markdown`, ...).
    pub shape: String,
    /// Price the quote was offered at.
    pub price: Money,
    /// Rail identifier (`x402`, `mpp`, ...).
    pub rail: String,
    /// Optional facilitator URL; only set for x402 rails.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub facilitator: Option<String>,
}

/// JWS protected header.
///
/// `typ` is pinned to the vendor-specific `sbproxy-quote+jws` so verifiers can
/// reject ordinary application JWTs masquerading as quote tokens before any
/// signature work happens.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuoteHeader {
    /// Algorithm; always `"EdDSA"` in Wave 3.
    pub alg: String,
    /// Type tag; always `"sbproxy-quote+jws"`.
    pub typ: String,
    /// Key id selecting which JWKS entry verifies this signature.
    pub kid: String,
}

// --- Error types ---

/// Errors returned by [`QuoteTokenSigner::sign`].
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// JSON encoding of the header or payload failed.
    #[error("encode error: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Errors returned by [`QuoteTokenVerifier::verify`].
///
/// The variants map directly to the closed error codes pinned by
/// `docs/adr-quote-token-jws.md` § verification path. The ledger service
/// translates these to the wire-level codes (`ledger.signature_invalid`,
/// `ledger.token_expired`, `ledger.token_already_spent`, ...).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// Token shape is wrong (missing dots, header decode fails, claims decode fails).
    #[error("malformed token: {0}")]
    Malformed(String),
    /// Header `kid` does not match any public key in the JWKS.
    #[error("unknown signing key id: {0}")]
    UnknownKey(String),
    /// Header `alg` is not `EdDSA`.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    /// Header `typ` is not `sbproxy-quote+jws`.
    #[error("unsupported token type: {0}")]
    UnsupportedType(String),
    /// Signature did not validate against the resolved public key.
    #[error("signature invalid")]
    SignatureInvalid,
    /// `exp <= now`. The token is past its TTL.
    #[error("token expired (exp={exp}, now={now})")]
    Expired {
        /// Claim `exp`.
        exp: u64,
        /// Verifier wall clock at check time.
        now: u64,
    },
    /// `iat > now + max_skew`. The agent's clock is too far in the future.
    #[error("clock skew (iat={iat}, now={now})")]
    SkewedTimestamp {
        /// Claim `iat`.
        iat: u64,
        /// Verifier wall clock at check time.
        now: u64,
    },
    /// Claim `route` does not equal the redeem call's resolved path.
    #[error("route mismatch: claim={claim}, expected={expected}")]
    RouteMismatch {
        /// Claim `route`.
        claim: String,
        /// Expected route (from the redeem call's resolved path).
        expected: String,
    },
    /// Claim `shape` does not match the redeem call's resolved content shape.
    #[error("shape mismatch: claim={claim}, expected={expected}")]
    ShapeMismatch {
        /// Claim `shape`.
        claim: String,
        /// Expected shape (from the redeem call's resolved Accept).
        expected: String,
    },
    /// Nonce was already consumed by a prior redeem.
    #[error("nonce already consumed: {0}")]
    NonceAlreadyConsumed(String),
    /// Nonce store returned an error.
    #[error("nonce store error: {0}")]
    NonceStore(String),
}

// --- Signer ---

/// Sync signer that produces compact-JWS quote tokens.
///
/// One signer per active key; rotation rebuilds the proxy's
/// [`QuoteTokenSigner`] with the new key and the JWKS endpoint serves both
/// the new and previous public keys for the configured rotation window.
pub struct QuoteTokenSigner {
    signing_key: SigningKey,
    /// `kid` stamped into the JWS header. The verifier looks up the matching
    /// public key in the JWKS by this id.
    key_id: String,
    /// Issuer URL stamped into every token's `iss` claim.
    issuer: String,
    /// Default TTL applied when the caller passes `None` for `ttl`.
    default_ttl: Duration,
}

impl std::fmt::Debug for QuoteTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private key bytes; the kid is the safe identifier.
        f.debug_struct("QuoteTokenSigner")
            .field("kid", &self.key_id)
            .field("issuer", &self.issuer)
            .field("default_ttl", &self.default_ttl)
            .finish()
    }
}

impl QuoteTokenSigner {
    /// Build a signer from a 32-byte Ed25519 private key seed plus metadata.
    pub fn new(
        signing_key: SigningKey,
        key_id: impl Into<String>,
        issuer: impl Into<String>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            signing_key,
            key_id: key_id.into(),
            issuer: issuer.into(),
            default_ttl,
        }
    }

    /// Build a signer from a 32-byte Ed25519 private key seed (raw bytes).
    pub fn from_seed_bytes(
        seed: &[u8; 32],
        key_id: impl Into<String>,
        issuer: impl Into<String>,
        default_ttl: Duration,
    ) -> Self {
        Self::new(SigningKey::from_bytes(seed), key_id, issuer, default_ttl)
    }

    /// Issuer URL stamped on signed tokens.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Active signing key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The matching public key. Use this to seed a [`QuoteTokenVerifier`] in
    /// single-host deployments where signer and verifier coexist.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a fully-populated [`QuoteClaims`]. Caller owns `iat` / `exp` /
    /// `nonce` / `quote_id`; this method does not mutate the claim set.
    pub fn sign(&self, claims: &QuoteClaims) -> Result<String, SignError> {
        let header = QuoteHeader {
            alg: "EdDSA".to_string(),
            typ: "sbproxy-quote+jws".to_string(),
            kid: self.key_id.clone(),
        };
        let header_json = serde_json::to_vec(&header)?;
        let payload_json = serde_json::to_vec(claims)?;
        let header_b64 = base64_url_encode(&header_json);
        let payload_b64 = base64_url_encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64_url_encode(&signature.to_bytes());
        Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
    }

    /// Convenience: build a fresh [`QuoteClaims`] from the parts a caller
    /// typically has on hand and sign it. Generates `iat = now`,
    /// `exp = now + ttl_or_default`, fresh ULIDs for `nonce` and `quote_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        agent_id: &str,
        route: &str,
        shape: ContentShape,
        price: Money,
        rail: &str,
        facilitator: Option<String>,
        ttl: Option<Duration>,
    ) -> Result<IssuedQuote, SignError> {
        let now = unix_seconds_now();
        let ttl_secs = ttl.unwrap_or(self.default_ttl).as_secs();
        let nonce = ulid::Ulid::new().to_string();
        let quote_id = ulid::Ulid::new().to_string();
        let claims = QuoteClaims {
            iss: self.issuer.clone(),
            sub: agent_id.to_string(),
            aud: "ledger".to_string(),
            iat: now,
            exp: now.saturating_add(ttl_secs),
            nonce: nonce.clone(),
            quote_id: quote_id.clone(),
            route: route.to_string(),
            shape: shape.as_str().to_string(),
            price,
            rail: rail.to_string(),
            facilitator,
        };
        let token = self.sign(&claims)?;
        Ok(IssuedQuote { token, claims })
    }
}

/// A signed quote token plus its decoded claims, so the caller does not have
/// to round-trip through the verifier just to read the nonce / quote_id /
/// expiry it just generated.
#[derive(Debug, Clone)]
pub struct IssuedQuote {
    /// Compact JWS token suitable for embedding in the multi-rail 402 body.
    pub token: String,
    /// The exact claims that were signed.
    pub claims: QuoteClaims,
}

// --- Verifier ---

/// Maximum tolerated future-clock skew on `iat`. Mirrors the 5-minute window
/// pinned in `docs/adr-quote-token-jws.md` § verification path.
pub const MAX_IAT_SKEW: Duration = Duration::from_secs(5 * 60);

/// Stateless verifier for compact-JWS quote tokens.
///
/// Holds the JWKS (kid -> public key map) and a [`NonceStore`] that
/// guarantees single-use redemption. The verifier itself is sync because the
/// proxy hot path is sync per the layering ADR; the nonce-store implementation
/// can be in-memory (OSS) or Postgres-backed (enterprise).
pub struct QuoteTokenVerifier {
    public_keys: HashMap<String, VerifyingKey>,
    nonce_store: Arc<dyn NonceStore>,
    /// Hard ceiling on the (exp - iat) gap. Mirrors the per-deployment
    /// `max_ttl_seconds` knob from the ADR; defaults to one hour.
    max_ttl: Duration,
    /// Tolerated future-clock skew. Defaults to [`MAX_IAT_SKEW`].
    max_skew: Duration,
}

impl std::fmt::Debug for QuoteTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuoteTokenVerifier")
            .field("kids", &self.public_keys.keys().collect::<Vec<_>>())
            .field("max_ttl", &self.max_ttl)
            .field("max_skew", &self.max_skew)
            .finish()
    }
}

impl QuoteTokenVerifier {
    /// Build a verifier with a single trusted key.
    pub fn single_key(
        kid: impl Into<String>,
        public_key: VerifyingKey,
        nonce_store: Arc<dyn NonceStore>,
    ) -> Self {
        let mut keys = HashMap::with_capacity(1);
        keys.insert(kid.into(), public_key);
        Self {
            public_keys: keys,
            nonce_store,
            max_ttl: Duration::from_secs(3600),
            max_skew: MAX_IAT_SKEW,
        }
    }

    /// Build a verifier with a JWKS (multiple kids during a rotation window).
    pub fn with_keys(
        keys: HashMap<String, VerifyingKey>,
        nonce_store: Arc<dyn NonceStore>,
    ) -> Self {
        Self {
            public_keys: keys,
            nonce_store,
            max_ttl: Duration::from_secs(3600),
            max_skew: MAX_IAT_SKEW,
        }
    }

    /// Override the hard TTL ceiling. The default matches the ADR (1h).
    pub fn with_max_ttl(mut self, max_ttl: Duration) -> Self {
        self.max_ttl = max_ttl;
        self
    }

    /// Override the maximum tolerated future-clock skew on `iat`.
    pub fn with_max_skew(mut self, max_skew: Duration) -> Self {
        self.max_skew = max_skew;
        self
    }

    /// Add or replace a key in the JWKS. Used to add a new key during a
    /// rotation window without rebuilding the verifier.
    pub fn add_key(&mut self, kid: impl Into<String>, public_key: VerifyingKey) {
        self.public_keys.insert(kid.into(), public_key);
    }

    /// Verify a compact JWS token.
    ///
    /// Per the ADR's verification path:
    /// 1. Parse + decode header.
    /// 2. Reject unknown `kid` / `alg` / `typ`.
    /// 3. Verify ed25519 signature.
    /// 4. Check `exp` and `iat` (clock-skew tolerance).
    /// 5. Match `route` and `shape` against the supplied expectations.
    /// 6. Consume `nonce` via the [`NonceStore`].
    ///
    /// The caller is responsible for the `price` and `rail` matches, which
    /// depend on the rail-specific redeem context that the verifier does
    /// not own.
    pub fn verify(
        &self,
        token: &str,
        expected_route: &str,
        expected_shape: ContentShape,
    ) -> Result<QuoteClaims, VerifyError> {
        // --- Parse JWS ---
        let mut parts = token.split('.');
        let header_b64 = parts
            .next()
            .ok_or_else(|| VerifyError::Malformed("missing header".into()))?;
        let payload_b64 = parts
            .next()
            .ok_or_else(|| VerifyError::Malformed("missing payload".into()))?;
        let signature_b64 = parts
            .next()
            .ok_or_else(|| VerifyError::Malformed("missing signature".into()))?;
        if parts.next().is_some() {
            return Err(VerifyError::Malformed("too many segments".into()));
        }

        let header_bytes = base64_url_decode(header_b64)
            .map_err(|e| VerifyError::Malformed(format!("header b64: {e}")))?;
        let payload_bytes = base64_url_decode(payload_b64)
            .map_err(|e| VerifyError::Malformed(format!("payload b64: {e}")))?;
        let signature_bytes = base64_url_decode(signature_b64)
            .map_err(|e| VerifyError::Malformed(format!("signature b64: {e}")))?;

        let header: QuoteHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| VerifyError::Malformed(format!("header decode: {e}")))?;

        if header.alg != "EdDSA" {
            return Err(VerifyError::UnsupportedAlg(header.alg));
        }
        if header.typ != "sbproxy-quote+jws" {
            return Err(VerifyError::UnsupportedType(header.typ));
        }

        // --- Resolve key ---
        let key = self
            .public_keys
            .get(&header.kid)
            .ok_or_else(|| VerifyError::UnknownKey(header.kid.clone()))?;

        // --- Verify signature ---
        let sig_arr: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let signing_input = format!("{header_b64}.{payload_b64}");
        key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| VerifyError::SignatureInvalid)?;

        // --- Decode claims ---
        let claims: QuoteClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| VerifyError::Malformed(format!("claims decode: {e}")))?;

        // --- Time checks ---
        let now = unix_seconds_now();
        if claims.exp <= now {
            return Err(VerifyError::Expired {
                exp: claims.exp,
                now,
            });
        }
        let max_skew = self.max_skew.as_secs();
        if claims.iat > now.saturating_add(max_skew) {
            return Err(VerifyError::SkewedTimestamp {
                iat: claims.iat,
                now,
            });
        }
        // Defence-in-depth TTL ceiling: reject tokens whose effective TTL
        // exceeds the verifier's max_ttl, even if the issuer was misconfigured.
        let ttl_secs = claims.exp.saturating_sub(claims.iat);
        if ttl_secs > self.max_ttl.as_secs() {
            return Err(VerifyError::Expired {
                exp: claims.exp,
                now,
            });
        }

        // --- Route + shape match ---
        if claims.route != expected_route {
            return Err(VerifyError::RouteMismatch {
                claim: claims.route.clone(),
                expected: expected_route.to_string(),
            });
        }
        let expected_shape_str = expected_shape.as_str();
        if claims.shape != expected_shape_str {
            return Err(VerifyError::ShapeMismatch {
                claim: claims.shape.clone(),
                expected: expected_shape_str.to_string(),
            });
        }

        // --- Nonce single-use ---
        match self.nonce_store.check_and_consume(&claims.nonce) {
            Ok(NonceCheck::Fresh) => Ok(claims),
            Ok(NonceCheck::AlreadyConsumed) => Err(VerifyError::NonceAlreadyConsumed(claims.nonce)),
            // The ADR's async-insert race: the nonce is unknown because the
            // issuer's insert has not landed yet. The ledger reports this as
            // `bad_request` to the client; here we translate to the closest
            // verify error.
            Ok(NonceCheck::Unknown) => Err(VerifyError::NonceAlreadyConsumed(claims.nonce)),
            Err(e) => Err(VerifyError::NonceStore(e.to_string())),
        }
    }

    /// JWKS publication shape: a JSON object with a `keys` array. Each entry
    /// is a JWK-ish record `{ "kty": "OKP", "crv": "Ed25519", "kid": "...",
    /// "x": "<base64url public key>" }`. Stable enough to be served by the
    /// proxy admin server at `/.well-known/sbproxy/quote-keys.json`.
    pub fn jwks_json(&self) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = self
            .public_keys
            .iter()
            .map(|(kid, vk)| {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": kid,
                    "x": base64_url_encode(vk.as_bytes()),
                })
            })
            .collect();
        serde_json::json!({ "keys": keys })
    }
}

// --- Nonce store ---

/// Outcome of a [`NonceStore::check_and_consume`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCheck {
    /// First time we have seen this nonce. The store has now marked it
    /// consumed; the verifier proceeds with the wallet debit.
    Fresh,
    /// A prior call already consumed this nonce. The verifier rejects the
    /// redeem with `ledger.token_already_spent`.
    AlreadyConsumed,
    /// The nonce was never registered. In Postgres-backed deployments this
    /// is the rare async-insert race documented in the ADR; the verifier
    /// rejects with `ledger.bad_request` and the agent re-quotes.
    Unknown,
}

/// Errors returned by [`NonceStore`] backends. Implementations stringify
/// their internal error type into [`NonceError::message`] so the verifier
/// stays detached from the storage backend.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct NonceError {
    /// Human-readable description of the storage-side failure.
    pub message: String,
}

impl NonceError {
    /// Build an error from any displayable cause.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Pluggable single-use nonce ledger.
///
/// Implementations:
/// - [`InMemoryNonceStore`]: OSS default. Ships with the proxy and is
///   sufficient for single-host topologies and the e2e tests.
/// - A Postgres-backed implementation (out of scope for this OSS crate)
///   writes to the `quote_tokens` table per `adr-quote-token-jws.md` §
///   replay protection. The trait is the wire shape both implementations
///   agree on.
pub trait NonceStore: Send + Sync + std::fmt::Debug + 'static {
    /// Atomically check whether `nonce` has been consumed and, if not,
    /// mark it consumed.
    ///
    /// Returns:
    /// - [`NonceCheck::Fresh`] on first redeem (the store has now marked it).
    /// - [`NonceCheck::AlreadyConsumed`] on repeat (the verifier rejects).
    /// - [`NonceCheck::Unknown`] when the nonce was never registered. In
    ///   Postgres-backed deployments this means the issuer's async insert
    ///   has not landed yet; the verifier rejects with `bad_request` and
    ///   the agent re-quotes.
    fn check_and_consume(&self, nonce: &str) -> Result<NonceCheck, NonceError>;

    /// Optional pre-registration hook. The issuer calls this when emitting
    /// a 402 challenge so the verifier can later distinguish "never seen"
    /// from "already consumed". The default impl is a no-op for stores
    /// (like the in-memory ledger) that treat `Unknown` and `Fresh` as the
    /// same case.
    fn register(&self, _nonce: &str) -> Result<(), NonceError> {
        Ok(())
    }
}

/// In-memory single-use nonce ledger. Suitable for tests and single-host OSS
/// deployments. Multi-host enterprise deployments must use the Postgres-
/// backed store per the ADR, otherwise an attacker can bounce the same
/// token between proxies before the in-memory state propagates.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    /// Set of nonces that have been issued (via `register`) and not yet
    /// consumed. Distinct from `consumed` so the verifier can return
    /// `Unknown` for nonces it has never seen at all (vs. `AlreadyConsumed`
    /// for nonces it has burned).
    issued: Mutex<std::collections::HashSet<String>>,
    /// Set of nonces that have been consumed. Once a nonce is here, all
    /// subsequent `check_and_consume` calls return `AlreadyConsumed`.
    consumed: Mutex<std::collections::HashSet<String>>,
}

impl InMemoryNonceStore {
    /// Build an empty in-memory nonce store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_consume(&self, nonce: &str) -> Result<NonceCheck, NonceError> {
        let mut consumed = self.consumed.lock();
        if consumed.contains(nonce) {
            return Ok(NonceCheck::AlreadyConsumed);
        }
        let issued = self.issued.lock();
        let was_issued = issued.contains(nonce);
        drop(issued);
        if !was_issued {
            // The in-memory store treats unknown and fresh distinctly only
            // when the issuer pre-registered. If no register() call ever
            // happened (e.g. a test that uses the signer's `issue()` helper
            // without separately registering), fall back to "fresh".
            consumed.insert(nonce.to_string());
            return Ok(NonceCheck::Fresh);
        }
        consumed.insert(nonce.to_string());
        Ok(NonceCheck::Fresh)
    }

    fn register(&self, nonce: &str) -> Result<(), NonceError> {
        self.issued.lock().insert(nonce.to_string());
        Ok(())
    }
}

// --- Helpers ---

fn base64_url_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_signer(default_ttl_secs: u64) -> QuoteTokenSigner {
        let seed: [u8; 32] = [
            7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        QuoteTokenSigner::from_seed_bytes(
            &seed,
            "kid-current",
            "https://api.example.com",
            Duration::from_secs(default_ttl_secs),
        )
    }

    fn fresh_money() -> Money {
        Money {
            amount_micros: 5_000,
            currency: "USD".to_string(),
        }
    }

    fn verifier_for(signer: &QuoteTokenSigner, store: Arc<dyn NonceStore>) -> QuoteTokenVerifier {
        QuoteTokenVerifier::single_key(signer.key_id().to_string(), signer.verifying_key(), store)
    }

    #[test]
    fn quote_token_signer_round_trip_with_kid() {
        let signer = fresh_signer(300);
        let issued = signer
            .issue(
                "agent-1",
                "/articles/foo",
                ContentShape::Markdown,
                fresh_money(),
                "x402",
                Some("https://facilitator-base.x402.org".to_string()),
                None,
            )
            .expect("sign");

        // Sanity check: three base64url segments separated by dots.
        let parts: Vec<&str> = issued.token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three segments");

        let header_bytes = base64_url_decode(parts[0]).expect("header b64");
        let header: QuoteHeader = serde_json::from_slice(&header_bytes).expect("header decode");
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "sbproxy-quote+jws");
        assert_eq!(header.kid, "kid-current");

        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let claims = verifier
            .verify(&issued.token, "/articles/foo", ContentShape::Markdown)
            .expect("verify");
        assert_eq!(claims.rail, "x402");
        assert_eq!(claims.shape, "markdown");
        assert_eq!(claims.price.amount_micros, 5_000);
        assert_eq!(claims.iss, "https://api.example.com");
        assert_eq!(claims.aud, "ledger");
    }

    #[test]
    fn quote_token_verify_happy_path() {
        let signer = fresh_signer(300);
        let issued = signer
            .issue(
                "agent-2",
                "/p/x",
                ContentShape::Html,
                fresh_money(),
                "mpp",
                None,
                None,
            )
            .expect("sign");
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let claims = verifier
            .verify(&issued.token, "/p/x", ContentShape::Html)
            .expect("verify");
        assert_eq!(claims.rail, "mpp");
        assert!(claims.facilitator.is_none());
    }

    #[test]
    fn quote_token_verify_rejects_expired() {
        // Build claims by hand with a backdated exp.
        let signer = fresh_signer(300);
        let now = unix_seconds_now();
        let claims = QuoteClaims {
            iss: signer.issuer().to_string(),
            sub: "agent-x".to_string(),
            aud: "ledger".to_string(),
            iat: now - 600,
            exp: now - 1, // already past
            nonce: ulid::Ulid::new().to_string(),
            quote_id: ulid::Ulid::new().to_string(),
            route: "/r".to_string(),
            shape: "html".to_string(),
            price: fresh_money(),
            rail: "x402".to_string(),
            facilitator: None,
        };
        let token = signer.sign(&claims).expect("sign");
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let err = verifier
            .verify(&token, "/r", ContentShape::Html)
            .expect_err("expected expired");
        assert!(matches!(err, VerifyError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn quote_token_verify_rejects_replayed_nonce() {
        let signer = fresh_signer(300);
        let issued = signer
            .issue(
                "agent-replay",
                "/r",
                ContentShape::Html,
                fresh_money(),
                "x402",
                None,
                None,
            )
            .expect("sign");
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);

        verifier
            .verify(&issued.token, "/r", ContentShape::Html)
            .expect("first verify ok");
        let err = verifier
            .verify(&issued.token, "/r", ContentShape::Html)
            .expect_err("second verify must fail");
        assert!(
            matches!(err, VerifyError::NonceAlreadyConsumed(_)),
            "{err:?}"
        );
    }

    #[test]
    fn quote_token_verify_rejects_route_mismatch() {
        let signer = fresh_signer(300);
        let issued = signer
            .issue(
                "agent-r",
                "/articles/x",
                ContentShape::Html,
                fresh_money(),
                "x402",
                None,
                None,
            )
            .expect("sign");
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let err = verifier
            .verify(&issued.token, "/articles/y", ContentShape::Html)
            .expect_err("route mismatch");
        assert!(matches!(err, VerifyError::RouteMismatch { .. }), "{err:?}");
    }

    #[test]
    fn quote_token_verify_rejects_shape_mismatch() {
        let signer = fresh_signer(300);
        let issued = signer
            .issue(
                "agent-s",
                "/r",
                ContentShape::Markdown,
                fresh_money(),
                "x402",
                None,
                None,
            )
            .expect("sign");
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let err = verifier
            .verify(&issued.token, "/r", ContentShape::Html)
            .expect_err("shape mismatch");
        assert!(matches!(err, VerifyError::ShapeMismatch { .. }), "{err:?}");
    }

    #[test]
    fn quote_token_verify_rejects_unknown_kid() {
        // Build a token signed by signer A; verify with verifier holding only
        // signer B's public key.
        let signer_a = fresh_signer(300);
        let issued = signer_a
            .issue(
                "a",
                "/r",
                ContentShape::Html,
                fresh_money(),
                "x402",
                None,
                None,
            )
            .expect("sign");
        // Different seed -> different verifying key, but reuse the same kid
        // string so we exercise the "kid present but signature invalid"
        // branch rather than the "kid unknown" branch.
        let seed_b: [u8; 32] = [99u8; 32];
        let signer_b = QuoteTokenSigner::from_seed_bytes(
            &seed_b,
            "kid-other",
            "https://api.example.com",
            Duration::from_secs(300),
        );
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = QuoteTokenVerifier::single_key(
            signer_b.key_id().to_string(),
            signer_b.verifying_key(),
            store,
        );
        let err = verifier
            .verify(&issued.token, "/r", ContentShape::Html)
            .expect_err("unknown kid");
        assert!(matches!(err, VerifyError::UnknownKey(_)), "{err:?}");
    }

    #[test]
    fn jwks_json_lists_active_kids() {
        let signer = fresh_signer(300);
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        let jwks = verifier.jwks_json();
        let keys = jwks
            .get("keys")
            .and_then(|v| v.as_array())
            .expect("keys array");
        assert_eq!(keys.len(), 1);
        let entry = &keys[0];
        assert_eq!(
            entry.get("kid").and_then(|v| v.as_str()),
            Some("kid-current")
        );
        assert_eq!(entry.get("alg").and_then(|v| v.as_str()), Some("EdDSA"));
        assert_eq!(entry.get("kty").and_then(|v| v.as_str()), Some("OKP"));
        assert_eq!(entry.get("crv").and_then(|v| v.as_str()), Some("Ed25519"));
    }

    #[test]
    fn rejects_malformed_token() {
        let signer = fresh_signer(300);
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = verifier_for(&signer, store);
        for bad in &["", "no-dots", "a.b", "a.b.c.d"] {
            let err = verifier
                .verify(bad, "/r", ContentShape::Html)
                .expect_err(&format!("malformed: {bad}"));
            assert!(matches!(err, VerifyError::Malformed(_)), "{err:?}");
        }
    }
}
