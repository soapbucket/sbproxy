//! RSL 1.0 Open License Protocol (OLP) license tokens (WOR-808).
//!
//! OLP is the RSL Collective's license-issuance protocol for the CAP
//! (Crawler Authorization Protocol) header. A crawler that hits a
//! `WWW-Authenticate: License` challenge follows the advertised
//! `token_url` to obtain a license token, then re-tries the request
//! with `Authorization: License <token>`. RSL 1.0 pins
//! `token_type: "License"` on the issued token; this module emits
//! that token as a compact JWS (RFC 7515) signed with Ed25519, plus a
//! JWK publication helper so external verifiers can validate without
//! contacting the issuer per-token.
//!
//! ## Wire shape
//!
//! Compact JWS with `alg=EdDSA`. Header:
//!
//! ```json
//! {"alg":"EdDSA","typ":"olp-license+jws","kid":"<key id>"}
//! ```
//!
//! Payload claims are pinned in [`OlpLicenseClaims`]: `iss` (issuer
//! URL), `sub` (the agent identity from the agent-class taxonomy or
//! the operator-issued opaque subject), `aud` (the protected origin's
//! hostname), `iat` / `exp` (unix seconds), `scope` (space-separated
//! token list per RFC 8693), `license_urn` (the URN of the RSL
//! `/licenses.xml` document the license operates under), and a stable
//! `jti` so an issuer that tracks revocation can identify the token
//! later.
//!
//! ## Key publication
//!
//! [`jwk_from_verifying_key`] turns an Ed25519 verifying key into the
//! `{kty: "OKP", crv: "Ed25519", x: <base64url>}` JWK shape per
//! RFC 8037 §2. The data-plane `GET /.well-known/olp/key` synthetic
//! endpoint serves it. Rotation works by adding a new key with a new
//! `kid` and trusting both for the rotation window; the JWK endpoint
//! emits the active key.
//!
//! ## Layering
//!
//! Sign and verify are sync and allocation-light (one base64-encode
//! per signing). Revocation / introspection requires a nonce or jti
//! store and is deferred to PR8.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Decoded JWS payload for an OLP license token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OlpLicenseClaims {
    /// Issuer URL (the proxy's external base URL, e.g.
    /// `https://api.example.com`).
    pub iss: String,
    /// Subject the license is issued to (agent_id, opaque opaque
    /// subject, or `anonymous` for public licenses).
    pub sub: String,
    /// Audience: the protected origin's hostname.
    pub aud: String,
    /// Issued-at, unix seconds.
    pub iat: u64,
    /// Expiration, unix seconds.
    pub exp: u64,
    /// Space-separated scope tokens per RFC 8693 §2.2.1. Pins which
    /// RSL usage tokens (`ai-train`, `ai-input`, `search`) the
    /// license grants.
    pub scope: String,
    /// URN of the RSL `/licenses.xml` document the license operates
    /// under (`urn:rsl:1.0:<hostname>:<config_version>`).
    pub license_urn: String,
    /// Stable JWT id; revocation stores (PR follow-up) key off this.
    /// Also used as the HKDF salt that derives the per-token EMS
    /// content key, so two tokens issued from the same content-key
    /// seed never share an EMS key.
    pub jti: String,
    /// WOR-808 PR8: RFC 7800 `cnf` confirmation claim carrying the
    /// EMS (Encrypted Media Standard) content key bound to this
    /// license. Present only when the operator declared a
    /// `content_key_seed` on the origin's OLP config; absent
    /// otherwise so existing clients that ignore `cnf` keep
    /// working.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cnf: Option<Confirmation>,
}

/// RFC 7800 `cnf` confirmation claim. Today only the symmetric-jwk
/// shape is emitted (the EMS content key); RFC 7800 also allows
/// `jkt` (key thumbprint) and `kid` references which are not used
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// Embedded JWK carrying the EMS content key.
    pub jwk: ConfirmationJwk,
}

/// Symmetric JWK (RFC 7518 §6.4) embedded in a `cnf.jwk` claim. The
/// content key is the `k` field, base64url-no-pad-encoded raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationJwk {
    /// `oct` per RFC 7518 §6.4 (symmetric key).
    pub kty: String,
    /// AEAD algorithm the content key is intended for; today fixed
    /// to `A256GCM` (AES-256-GCM) per the EMS profile sbproxy emits.
    pub alg: String,
    /// `enc` per RFC 7517 (key intended for content encryption).
    #[serde(rename = "use")]
    pub use_: String,
    /// Raw content key bytes, base64url no padding.
    pub k: String,
}

/// JWS protected header. `typ` is pinned to `olp-license+jws` per
/// RSL 1.0 so verifiers can reject ordinary JWTs that happen to land
/// on a CAP-protected origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OlpHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// `token_type` value RSL 1.0 mandates on the OLP token-issuance
/// response.
pub const OLP_TOKEN_TYPE: &str = "License";

/// JWS `typ` header value the signer stamps and the verifier
/// requires.
pub const OLP_JWS_TYP: &str = "olp-license+jws";

/// Default token TTL when the operator does not configure one.
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Stateless Ed25519 license-token signer.
#[derive(Debug)]
pub struct OlpTokenSigner {
    signing_key: SigningKey,
    /// Cached verifying key so callers can publish the JWK without
    /// re-deriving it on every request.
    verifying_key: VerifyingKey,
    kid: String,
}

impl OlpTokenSigner {
    /// Construct from the raw 32-byte seed of an Ed25519 key plus the
    /// key id the JWS header will advertise. The kid is opaque to the
    /// verifier; an operator can rotate by issuing under a new kid and
    /// trusting both for the overlap window.
    pub fn from_seed_bytes(seed: [u8; 32], kid: impl Into<String>) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            kid: kid.into(),
        }
    }

    /// The verifying half of the keypair. Publish via
    /// [`jwk_from_verifying_key`] for the `/.well-known/olp/key`
    /// endpoint, or hand to [`OlpTokenVerifier::new`] for in-process
    /// verify.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// JWS `kid` header the signer stamps.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Sign a claim set. Returns the compact JWS (three base64url
    /// segments separated by `.`).
    pub fn sign(&self, claims: &OlpLicenseClaims) -> Result<String, SignError> {
        let header = OlpHeader {
            alg: "EdDSA".to_string(),
            typ: OLP_JWS_TYP.to_string(),
            kid: self.kid.clone(),
        };
        let header_b64 =
            b64url(&serde_json::to_vec(&header).map_err(|e| SignError::Encode(e.to_string()))?);
        let payload_b64 =
            b64url(&serde_json::to_vec(claims).map_err(|e| SignError::Encode(e.to_string()))?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64url(&signature.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Stateless Ed25519 license-token verifier. One verifier per active
/// `kid`; on rotation the dispatcher tries each verifier in order.
#[derive(Debug)]
pub struct OlpTokenVerifier {
    verifying_key: VerifyingKey,
    expected_kid: String,
}

impl OlpTokenVerifier {
    /// Construct from a verifying key and the kid the issuer signed
    /// with. The verifier rejects any token whose JWS header lists a
    /// different kid (so a stolen key from one origin cannot impersonate
    /// another).
    pub fn new(verifying_key: VerifyingKey, expected_kid: impl Into<String>) -> Self {
        Self {
            verifying_key,
            expected_kid: expected_kid.into(),
        }
    }

    /// Verify a compact JWS and return the decoded claims. Returns
    /// [`VerifyError`] on any malformed segment, wrong typ/alg/kid,
    /// bad signature, or expired token. The `now_unix_secs` parameter
    /// is taken as input so tests can pin a clock and the production
    /// caller threads the wall-clock time.
    pub fn verify(&self, token: &str, now_unix_secs: u64) -> Result<OlpLicenseClaims, VerifyError> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(VerifyError::Malformed)?;
        let payload_b64 = parts.next().ok_or(VerifyError::Malformed)?;
        let sig_b64 = parts.next().ok_or(VerifyError::Malformed)?;
        if parts.next().is_some() {
            return Err(VerifyError::Malformed);
        }
        let header_bytes = b64url_decode(header_b64).ok_or(VerifyError::Malformed)?;
        let header: OlpHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| VerifyError::Malformed)?;
        if header.alg != "EdDSA" {
            return Err(VerifyError::WrongAlgorithm);
        }
        if header.typ != OLP_JWS_TYP {
            return Err(VerifyError::WrongTyp);
        }
        if header.kid != self.expected_kid {
            return Err(VerifyError::WrongKid);
        }
        let payload_bytes = b64url_decode(payload_b64).ok_or(VerifyError::Malformed)?;
        let sig_bytes = b64url_decode(sig_b64).ok_or(VerifyError::Malformed)?;
        if sig_bytes.len() != 64 {
            return Err(VerifyError::Malformed);
        }
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::Malformed)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let signing_input = format!("{header_b64}.{payload_b64}");
        self.verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| VerifyError::BadSignature)?;
        let claims: OlpLicenseClaims =
            serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::Malformed)?;
        if claims.exp <= now_unix_secs {
            return Err(VerifyError::Expired);
        }
        Ok(claims)
    }
}

/// Reason a token failed verification. Maps to the OLP `error` field
/// in the RFC 7662 introspection envelope and to the `WWW-Authenticate:
/// License error="..."` challenge code on a 401 / 403.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Could not parse the token (wrong segment count, bad base64,
    /// malformed JSON header / payload).
    Malformed,
    /// JWS header `alg` is not `EdDSA` (the only OLP-mandated alg in
    /// this build).
    WrongAlgorithm,
    /// JWS header `typ` is not `olp-license+jws`.
    WrongTyp,
    /// JWS header `kid` does not match the verifier's expected kid.
    WrongKid,
    /// Signature verification failed.
    BadSignature,
    /// Token has expired (`exp` <= now).
    Expired,
}

/// Reason a signer failed to produce a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// Claims or header failed JSON encoding (effectively unreachable
    /// for the pinned shapes but surfaced as a stable error rather
    /// than a panic).
    Encode(String),
}

/// RFC 8037 §2 JWK for an Ed25519 verifying key. Suitable for the
/// `GET /.well-known/olp/key` endpoint body. The `kid` field lets
/// rotating issuers serve multiple keys; the data-plane endpoint
/// today emits one JWK, but the helper accepts a `kid` so callers
/// can build a JWK Set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlpJwk {
    /// `OKP` per RFC 8037 §2.
    pub kty: String,
    /// `Ed25519` per RFC 8037 §3.1.
    pub crv: String,
    /// Public key bytes, base64url with no padding per RFC 7515 §2.
    pub x: String,
    /// Key id matching the JWS header `kid`.
    pub kid: String,
    /// `verify` only — the public-key JWK does not sign.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm the key is intended for.
    pub alg: String,
}

/// Build a JWK from an Ed25519 verifying key.
pub fn jwk_from_verifying_key(key: &VerifyingKey, kid: impl Into<String>) -> OlpJwk {
    OlpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: b64url(key.as_bytes()),
        kid: kid.into(),
        use_: "verify".to_string(),
        alg: "EdDSA".to_string(),
    }
}

/// JWK Set envelope per RFC 7517 §5. The well-known endpoint returns
/// this single-key set today; a multi-key build (rotation overlap)
/// would extend `keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlpJwkSet {
    /// The set of public keys verifiers should trust. Today the
    /// data-plane endpoint serves a single-entry set; rotation
    /// overlap would push two keys with different `kid` values so
    /// verifiers accept either during the cutover window.
    pub keys: Vec<OlpJwk>,
}

/// Inputs the token issuer needs to mint a license. The operator
/// configures `default_ttl_secs`, `default_scope`, and the issuer
/// URL; the call-site supplies the per-request subject and the
/// license URN this token operates under.
#[derive(Debug, Clone)]
pub struct IssueRequest<'a> {
    /// Subject the license is issued to.
    pub sub: &'a str,
    /// Audience: the protected origin's hostname.
    pub aud: &'a str,
    /// URN of the RSL `/licenses.xml` document the license is bound
    /// to. The issuer typically reads this from the
    /// `current_projections().rsl_urns` map on the hostname.
    pub license_urn: &'a str,
    /// Override the operator-configured default scope. `None` keeps
    /// the default.
    pub scope_override: Option<&'a str>,
    /// Override the operator-configured default TTL. `None` keeps
    /// the default.
    pub ttl_secs_override: Option<u64>,
    /// WOR-808 PR8: when set, derive a per-token EMS content key
    /// from this seed and the token's `jti` and attach it as an
    /// RFC 7800 `cnf.jwk` claim. The seed is the operator's
    /// `OlpConfig.content_key_seed`; absent here keeps the cnf
    /// claim off.
    pub content_key_seed: Option<&'a [u8]>,
}

/// Build a fresh [`OlpLicenseClaims`] from an issue request, the
/// issuer URL, and per-issuer defaults. Stamps `iat`/`exp` from the
/// current wall clock and a fresh `jti`; derives + attaches the
/// EMS `cnf.jwk` content key when `content_key_seed` is set.
pub fn build_claims(
    req: &IssueRequest<'_>,
    issuer: &str,
    default_scope: &str,
    default_ttl_secs: u64,
) -> OlpLicenseClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = req.ttl_secs_override.unwrap_or(default_ttl_secs);
    let scope = req.scope_override.unwrap_or(default_scope).to_string();
    let jti = fresh_jti();
    let cnf = req
        .content_key_seed
        .map(|seed| derive_ems_confirmation(seed, &jti));
    OlpLicenseClaims {
        iss: issuer.to_string(),
        sub: req.sub.to_string(),
        aud: req.aud.to_string(),
        iat: now,
        exp: now.saturating_add(ttl),
        scope,
        license_urn: req.license_urn.to_string(),
        jti,
        cnf,
    }
}

/// WOR-808 PR8: derive the per-token EMS content-key confirmation
/// claim from an operator-configured seed and the token's jti.
///
/// HKDF-SHA256 with `ikm = content_key_seed`, `salt = jti.as_bytes()`,
/// and the `EmsContentKey` purpose's versioned info string. Output
/// is 32 bytes (AES-256-GCM). Two tokens issued under the same seed
/// derive different keys (jti is per-token random), and the same
/// `(seed, jti)` always derives the same key so a decryptor that
/// retains the jti can recompute the key without storing the
/// material.
pub fn derive_ems_confirmation(content_key_seed: &[u8], jti: &str) -> Confirmation {
    let key_bytes = sbproxy_security::hkdf_derive_purpose(
        content_key_seed,
        jti.as_bytes(),
        sbproxy_security::HkdfPurpose::EmsContentKey,
        32,
    );
    Confirmation {
        jwk: ConfirmationJwk {
            kty: "oct".to_string(),
            alg: "A256GCM".to_string(),
            use_: "enc".to_string(),
            k: b64url(&key_bytes),
        },
    }
}

/// WOR-808 PR8: extract the raw EMS content key from a verified
/// license's `cnf.jwk.k` claim. Returns `None` when the token
/// carries no `cnf` claim (operator did not enable EMS for the
/// origin) or when the claim is shaped wrong (wrong kty, malformed
/// base64).
pub fn extract_ems_content_key(claims: &OlpLicenseClaims) -> Option<Vec<u8>> {
    let cnf = claims.cnf.as_ref()?;
    if cnf.jwk.kty != "oct" {
        return None;
    }
    b64url_decode(&cnf.jwk.k)
}

/// Generate a 128-bit random JTI as a 22-char base64url string (no
/// padding). Random source is `getrandom`, which OsRng wraps; we
/// avoid `ulid` to keep the dep set small (the jti only needs to be
/// per-issuer unique).
fn fresh_jti() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    b64url(&bytes)
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .ok()
}

// --- WOR-808 PR9: RFC 7662 / 7009 introspection + revocation ---

/// RFC 7662 §2.2 introspection response. Constructed by [`introspect`].
///
/// The `active` field is the only REQUIRED member. Every other field
/// is OPTIONAL and is omitted from the JSON when absent so a
/// well-formed `{"active": false}` response really is just that
/// (§2.2 forbids leaking why a token is inactive).
#[derive(Debug, Clone, Serialize)]
pub struct IntrospectResponse {
    /// RFC 7662 §2.2: REQUIRED. Whether the token is active right now.
    pub active: bool,
    /// RFC 7662 §2.2: issuer URL. Omitted when inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// RFC 7662 §2.2: subject the token authorizes. Omitted when inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// RFC 7662 §2.2: audience identifier. Omitted when inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// RFC 7662 §2.2: issued-at, unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// RFC 7662 §2.2: expiration, unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// RFC 7662 §2.2: space-separated scope list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 7662 §2.2: token id (matches the JWS `jti` claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// RSL 1.0 OLP extension: URN of the license document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_urn: Option<String>,
    /// RFC 7662 §2.2: client identifier. OLP today binds this to `sub`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// RFC 7662 §2.2: token type. RSL 1.0 OLP pins this to `License`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// RFC 7800 confirmation claim. Mirrored from the token when
    /// `mirror_cnf` is enabled; omitted on inactive tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

impl IntrospectResponse {
    /// The §2.2 "inactive" shape: just `{"active": false}`. Used for
    /// every token that fails to verify, has expired, or has been
    /// revoked; the operator's structured log can still emit the
    /// discriminator at `debug` level.
    pub fn inactive() -> Self {
        Self {
            active: false,
            iss: None,
            sub: None,
            aud: None,
            iat: None,
            exp: None,
            scope: None,
            jti: None,
            license_urn: None,
            client_id: None,
            token_type: None,
            cnf: None,
        }
    }
}

/// Revocation-list contract. Implementations write `jti` → "revoked"
/// with a TTL that matches the token's remaining lifetime so the
/// entry self-evicts once the token would expire anyway.
pub trait RevocationStore: Send + Sync + 'static {
    /// Return `true` when `jti` has been revoked. A storage error
    /// MUST propagate (the introspect endpoint translates it to a
    /// `503 temporarily_unavailable`); silently returning `false`
    /// would let an attacker fault-inject the store to bypass
    /// revocation.
    fn is_revoked(&self, jti: &str) -> anyhow::Result<bool>;

    /// Mark `jti` as revoked. `ttl_secs` is how long the entry
    /// should be retained; once the underlying token expires there
    /// is no value in keeping the revocation around since the
    /// verifier rejects it on `exp` anyway. `reason` is operator
    /// free text for audit / log purposes; backends MAY drop it
    /// when they only need the presence bit.
    fn revoke(&self, jti: &str, ttl_secs: u64, reason: &str) -> anyhow::Result<()>;
}

/// Wrap any [`sbproxy_platform::storage::KVStore`] as a
/// [`RevocationStore`]. Keys are scoped per-audience so the same
/// backing file or Redis instance can host revocations for multiple
/// origins without cross-origin enumeration.
pub struct KvRevocationStore {
    store: std::sync::Arc<dyn sbproxy_platform::storage::KVStore>,
    aud: String,
}

impl KvRevocationStore {
    /// Construct over a `KVStore` instance scoped to `aud`. The
    /// `aud` value lifts into the key prefix `olp/rev/<aud>/`.
    pub fn new(
        store: std::sync::Arc<dyn sbproxy_platform::storage::KVStore>,
        aud: impl Into<String>,
    ) -> Self {
        Self {
            store,
            aud: aud.into(),
        }
    }

    fn key(&self, jti: &str) -> String {
        format!("olp/rev/{}/{}", self.aud, jti)
    }
}

impl RevocationStore for KvRevocationStore {
    fn is_revoked(&self, jti: &str) -> anyhow::Result<bool> {
        let key = self.key(jti);
        Ok(self.store.get(key.as_bytes())?.is_some())
    }

    fn revoke(&self, jti: &str, ttl_secs: u64, reason: &str) -> anyhow::Result<()> {
        let key = self.key(jti);
        let payload = serde_json::json!({
            "revoked_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "reason": reason,
        })
        .to_string();
        // Backends that lack TTL support (in-memory) fall back to a
        // plain put — the entry will live for process lifetime, which
        // is fine for dev / CI use.
        match self
            .store
            .put_with_ttl(key.as_bytes(), payload.as_bytes(), ttl_secs)
        {
            Ok(()) => Ok(()),
            Err(_) => self.store.put(key.as_bytes(), payload.as_bytes()),
        }
    }
}

/// Decide whether `token` is currently active under `verifier` and
/// `revocation`, and build the RFC 7662 §2.2 response.
///
/// `now` is the current Unix time the caller wants the verifier to
/// use; production callers pass `SystemTime::now()`, tests pin a
/// fixed value. `mirror_cnf` controls whether an RFC 7800 `cnf`
/// claim on the token is propagated to the response (per the
/// `OlpIntrospectConfig` field of the same name).
///
/// Returns a response with `active: false` for every token that
/// fails to verify, has expired, or has been revoked. `active: true`
/// responses mirror every OLP claim per the agreed PR9 contract.
/// A storage error from the revocation store propagates so the
/// caller can surface it as a `503`.
pub fn introspect(
    verifier: &OlpTokenVerifier,
    revocation: &dyn RevocationStore,
    token: &str,
    now: u64,
    mirror_cnf: bool,
) -> anyhow::Result<IntrospectResponse> {
    let claims = match verifier.verify(token, now) {
        Ok(c) => c,
        Err(_) => return Ok(IntrospectResponse::inactive()),
    };
    if revocation.is_revoked(&claims.jti)? {
        return Ok(IntrospectResponse::inactive());
    }
    Ok(IntrospectResponse {
        active: true,
        iss: Some(claims.iss.clone()),
        sub: Some(claims.sub.clone()),
        aud: Some(claims.aud.clone()),
        iat: Some(claims.iat),
        exp: Some(claims.exp),
        scope: Some(claims.scope.clone()),
        jti: Some(claims.jti.clone()),
        license_urn: Some(claims.license_urn.clone()),
        // OLP today binds the OAuth `client_id` to the same value as
        // `sub` (the form-body `client_id` from `/token` becomes the
        // claim's `sub`); mirror it so RP libraries that key off
        // `client_id` see what they expect.
        client_id: Some(claims.sub.clone()),
        token_type: Some(OLP_TOKEN_TYPE.to_string()),
        cnf: if mirror_cnf { claims.cnf.clone() } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 32] {
        // Deterministic test seed; never use this in production.
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn signer() -> OlpTokenSigner {
        OlpTokenSigner::from_seed_bytes(fixed_seed(), "test-kid-1")
    }

    fn sample_claims() -> OlpLicenseClaims {
        OlpLicenseClaims {
            iss: "https://api.example.com".to_string(),
            sub: "agent:gptbot".to_string(),
            aud: "api.example.com".to_string(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            scope: "ai-train ai-input".to_string(),
            license_urn: "urn:rsl:1.0:api.example.com:42".to_string(),
            jti: "fixed-jti".to_string(),
            cnf: None,
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        let claims = sample_claims();
        let token = s.sign(&claims).expect("sign");
        let decoded = v.verify(&token, 1_700_000_500).expect("verify");
        assert_eq!(decoded, claims);
    }

    #[test]
    fn jws_typ_is_olp_license_jws() {
        let token = signer().sign(&sample_claims()).unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = b64url_decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "olp-license+jws");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "test-kid-1");
    }

    #[test]
    fn verify_rejects_wrong_kid() {
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), "different-kid");
        let token = s.sign(&sample_claims()).unwrap();
        assert_eq!(v.verify(&token, 1_700_000_500), Err(VerifyError::WrongKid));
    }

    #[test]
    fn verify_rejects_expired_token() {
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        let token = s.sign(&sample_claims()).unwrap();
        // sample_claims().exp == 1_700_003_600; check at one second
        // past that.
        assert_eq!(v.verify(&token, 1_700_003_601), Err(VerifyError::Expired));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        let token = s.sign(&sample_claims()).unwrap();
        // Flip one character in the payload segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        let mutated = parts[1]
            .chars()
            .map(|c| if c == 'a' { 'b' } else { c })
            .collect::<String>();
        parts[1] = &mutated;
        let bad = parts.join(".");
        let v_result = v.verify(&bad, 1_700_000_500);
        // Either the payload deserialises into nonsense (Malformed)
        // or the signature mismatches (BadSignature); both are
        // rejection outcomes. Assert on the rejection itself, not
        // the specific shape, because base64 substitution can land
        // in either error class.
        assert!(matches!(
            v_result,
            Err(VerifyError::BadSignature) | Err(VerifyError::Malformed)
        ));
    }

    #[test]
    fn verify_rejects_wrong_typ() {
        // Construct a JWS with a plain JWT typ instead of
        // `olp-license+jws`; verifier must reject before doing any
        // signature work.
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "test-kid-1"});
        let header_b64 = b64url(&serde_json::to_vec(&header).unwrap());
        let payload_b64 = b64url(&serde_json::to_vec(&sample_claims()).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = SigningKey::from_bytes(&fixed_seed()).sign(signing_input.as_bytes());
        let sig_b64 = b64url(&sig.to_bytes());
        let bad = format!("{signing_input}.{sig_b64}");
        assert_eq!(v.verify(&bad, 1_700_000_500), Err(VerifyError::WrongTyp));
    }

    #[test]
    fn verify_rejects_malformed_segment_count() {
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        assert_eq!(v.verify("aa.bb", 0), Err(VerifyError::Malformed));
        assert_eq!(v.verify("aa.bb.cc.dd", 0), Err(VerifyError::Malformed));
    }

    #[test]
    fn jwk_round_trip_shape() {
        let s = signer();
        let jwk = jwk_from_verifying_key(&s.verifying_key(), s.kid());
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.kid, "test-kid-1");
        assert_eq!(jwk.use_, "verify");
        assert_eq!(jwk.alg, "EdDSA");
        // x is the base64url-no-pad encoding of 32 raw bytes -> 43 chars.
        assert_eq!(jwk.x.len(), 43);
        assert!(jwk
            .x
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn build_claims_stamps_now_and_jti_uniqueness() {
        let r1 = build_claims(
            &IssueRequest {
                sub: "agent:gptbot",
                aud: "api.example.com",
                license_urn: "urn:rsl:1.0:api.example.com:42",
                scope_override: None,
                ttl_secs_override: None,
                content_key_seed: None,
            },
            "https://api.example.com",
            "ai-train",
            DEFAULT_TTL_SECS,
        );
        let r2 = build_claims(
            &IssueRequest {
                sub: "agent:gptbot",
                aud: "api.example.com",
                license_urn: "urn:rsl:1.0:api.example.com:42",
                scope_override: None,
                ttl_secs_override: None,
                content_key_seed: None,
            },
            "https://api.example.com",
            "ai-train",
            DEFAULT_TTL_SECS,
        );
        assert_ne!(r1.jti, r2.jti, "two consecutive jtis must differ");
        assert_eq!(r1.iss, "https://api.example.com");
        assert_eq!(r1.scope, "ai-train");
        assert_eq!(r1.exp - r1.iat, DEFAULT_TTL_SECS);
    }

    // --- WOR-808 PR8: EMS content-key binding ---

    #[test]
    fn ems_derives_distinct_key_per_jti() {
        // Two tokens issued from the same seed but different jtis
        // must derive different content keys (the jti is the HKDF
        // salt). A regression here would let one token's key
        // decrypt another's content.
        let seed = b"0123456789abcdef0123456789abcdef";
        let k1 = derive_ems_confirmation(seed, "jti-aaa");
        let k2 = derive_ems_confirmation(seed, "jti-bbb");
        assert_ne!(k1.jwk.k, k2.jwk.k);
    }

    #[test]
    fn ems_derives_deterministic_key_for_same_inputs() {
        // Idempotent: a decryptor that retains the jti can
        // recompute the same content key without storing the
        // material.
        let seed = b"0123456789abcdef0123456789abcdef";
        let a = derive_ems_confirmation(seed, "jti-stable");
        let b = derive_ems_confirmation(seed, "jti-stable");
        assert_eq!(a, b);
    }

    #[test]
    fn ems_confirmation_jwk_shape_is_oct_a256gcm_enc() {
        let cnf = derive_ems_confirmation(b"seed", "jti-1");
        assert_eq!(cnf.jwk.kty, "oct");
        assert_eq!(cnf.jwk.alg, "A256GCM");
        assert_eq!(cnf.jwk.use_, "enc");
        // AES-256-GCM key is 32 raw bytes; base64url no-pad is 43
        // chars.
        assert_eq!(cnf.jwk.k.len(), 43);
    }

    #[test]
    fn extract_ems_content_key_decodes_jwk_k() {
        let seed = b"a-seed";
        let cnf = derive_ems_confirmation(seed, "jti-x");
        let claims = OlpLicenseClaims {
            cnf: Some(cnf.clone()),
            ..sample_claims()
        };
        let extracted = extract_ems_content_key(&claims).expect("present");
        // The extracted bytes match what HKDF produced directly.
        let direct = sbproxy_security::hkdf_derive_purpose(
            seed,
            b"jti-x",
            sbproxy_security::HkdfPurpose::EmsContentKey,
            32,
        );
        assert_eq!(extracted, direct);
    }

    #[test]
    fn extract_ems_content_key_none_when_cnf_absent() {
        // Operator did not enable EMS for the origin -> no cnf
        // claim -> the helper returns None so callers know there
        // is no content key to use.
        let claims = OlpLicenseClaims {
            cnf: None,
            ..sample_claims()
        };
        assert!(extract_ems_content_key(&claims).is_none());
    }

    #[test]
    fn extract_ems_content_key_none_on_wrong_kty() {
        // A token whose cnf.jwk.kty is not `oct` is not a content
        // key; the helper refuses rather than returning garbage.
        let claims = OlpLicenseClaims {
            cnf: Some(Confirmation {
                jwk: ConfirmationJwk {
                    kty: "EC".to_string(),
                    alg: "A256GCM".to_string(),
                    use_: "enc".to_string(),
                    k: "AAAA".to_string(),
                },
            }),
            ..sample_claims()
        };
        assert!(extract_ems_content_key(&claims).is_none());
    }

    #[test]
    fn build_claims_emits_cnf_when_content_key_seed_provided() {
        let r = build_claims(
            &IssueRequest {
                sub: "agent:gptbot",
                aud: "api.example.com",
                license_urn: "urn:rsl:1.0:api.example.com:42",
                scope_override: None,
                ttl_secs_override: None,
                content_key_seed: Some(b"32-byte-content-encryption-seed!!"),
            },
            "https://api.example.com",
            "ai-train",
            DEFAULT_TTL_SECS,
        );
        let cnf = r.cnf.as_ref().expect("cnf present");
        assert_eq!(cnf.jwk.kty, "oct");
        assert_eq!(cnf.jwk.alg, "A256GCM");
    }

    #[test]
    fn build_claims_omits_cnf_when_no_seed() {
        let r = build_claims(
            &IssueRequest {
                sub: "agent:gptbot",
                aud: "api.example.com",
                license_urn: "urn:rsl:1.0:api.example.com:42",
                scope_override: None,
                ttl_secs_override: None,
                content_key_seed: None,
            },
            "https://api.example.com",
            "ai-train",
            DEFAULT_TTL_SECS,
        );
        assert!(r.cnf.is_none());
    }

    #[test]
    fn token_with_cnf_roundtrips_through_signer_and_verifier() {
        // The full path: build claims with a cnf claim, sign,
        // verify, extract the key. Pins that the cnf field
        // survives the JWS payload round-trip.
        let s = signer();
        let v = OlpTokenVerifier::new(s.verifying_key(), s.kid());
        let req = IssueRequest {
            sub: "agent:gptbot",
            aud: "api.example.com",
            license_urn: "urn:rsl:1.0:api.example.com:42",
            scope_override: None,
            ttl_secs_override: None,
            content_key_seed: Some(b"a-32-byte-content-encryption-seed"),
        };
        let claims = build_claims(&req, "https://api.example.com", "ai-train", 60);
        let token = s.sign(&claims).expect("sign");
        let decoded = v
            .verify(
                &token,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .expect("verify");
        let extracted = extract_ems_content_key(&decoded).expect("extracted");
        assert_eq!(extracted.len(), 32);
    }

    #[test]
    fn build_claims_honours_overrides() {
        let r = build_claims(
            &IssueRequest {
                sub: "agent:gptbot",
                aud: "api.example.com",
                license_urn: "urn:rsl:1.0:api.example.com:42",
                scope_override: Some("search"),
                ttl_secs_override: Some(60),
                content_key_seed: None,
            },
            "https://api.example.com",
            "ai-train",
            DEFAULT_TTL_SECS,
        );
        assert_eq!(r.scope, "search");
        assert_eq!(r.exp - r.iat, 60);
    }

    // --- WOR-808 PR9 introspect + revocation ---

    fn mint(now: u64, exp_offset: u64, sub: &str) -> (String, OlpTokenVerifier) {
        let signer = OlpTokenSigner::from_seed_bytes(fixed_seed(), "kid-1");
        let claims = OlpLicenseClaims {
            iss: "https://api.example.com".to_string(),
            sub: sub.to_string(),
            aud: "api.example.com".to_string(),
            iat: now,
            exp: now + exp_offset,
            jti: format!("jti-{sub}"),
            scope: "ai-input".to_string(),
            license_urn: "urn:rsl:1.0:api.example.com:1".to_string(),
            cnf: None,
        };
        let token = signer.sign(&claims).expect("sign");
        let verifier = OlpTokenVerifier::new(signer.verifying_key(), "kid-1");
        (token, verifier)
    }

    fn mem_store() -> std::sync::Arc<dyn sbproxy_platform::storage::KVStore> {
        std::sync::Arc::new(sbproxy_platform::storage::MemoryKVStore::new(1024))
    }

    #[test]
    fn introspect_returns_active_true_for_valid_token() {
        let now = 1_700_000_000;
        let (token, verifier) = mint(now, 300, "alice");
        let rev = KvRevocationStore::new(mem_store(), "api.example.com");
        let r = introspect(&verifier, &rev, &token, now, true).unwrap();
        assert!(r.active);
        assert_eq!(r.sub.as_deref(), Some("alice"));
        assert_eq!(r.client_id.as_deref(), Some("alice"));
        assert_eq!(r.token_type.as_deref(), Some(OLP_TOKEN_TYPE));
        assert_eq!(r.scope.as_deref(), Some("ai-input"));
        assert_eq!(r.iss.as_deref(), Some("https://api.example.com"));
        assert_eq!(r.aud.as_deref(), Some("api.example.com"));
        assert_eq!(r.exp, Some(now + 300));
    }

    #[test]
    fn introspect_returns_active_false_for_bad_signature() {
        // Flip a character in the middle segment to break the JWS.
        let now = 1_700_000_000;
        let (token, verifier) = mint(now, 300, "alice");
        let mut bad = token.clone();
        // Flip one character of the JWS payload segment.
        let parts: Vec<&str> = bad.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut payload = parts[1].to_string();
        let last = payload.len() - 1;
        let c = payload.as_bytes()[last];
        let flipped = if c == b'A' { 'B' } else { 'A' };
        payload.replace_range(last.., &flipped.to_string());
        bad = format!("{}.{}.{}", parts[0], payload, parts[2]);
        let rev = KvRevocationStore::new(mem_store(), "api.example.com");
        let r = introspect(&verifier, &rev, &bad, now, true).unwrap();
        assert!(!r.active);
        assert!(r.sub.is_none(), "inactive must not leak claims");
    }

    #[test]
    fn introspect_returns_active_false_for_expired_token() {
        let now = 1_700_000_000;
        let (token, verifier) = mint(now, 60, "alice");
        let rev = KvRevocationStore::new(mem_store(), "api.example.com");
        // Verifier clock skipped past exp.
        let r = introspect(&verifier, &rev, &token, now + 120, true).unwrap();
        assert!(!r.active);
        assert!(r.exp.is_none());
    }

    #[test]
    fn introspect_returns_active_false_after_revoke() {
        let now = 1_700_000_000;
        let (token, verifier) = mint(now, 300, "alice");
        let rev = KvRevocationStore::new(mem_store(), "api.example.com");
        let r = introspect(&verifier, &rev, &token, now, true).unwrap();
        assert!(r.active);
        rev.revoke("jti-alice", 300, "operator action").unwrap();
        let r = introspect(&verifier, &rev, &token, now, true).unwrap();
        assert!(!r.active);
        assert!(r.jti.is_none(), "inactive response leaks jti");
    }

    #[test]
    fn introspect_mirrors_cnf_when_configured() {
        let now = 1_700_000_000;
        let signer = OlpTokenSigner::from_seed_bytes(fixed_seed(), "kid-1");
        let cnf = derive_ems_confirmation(b"a-seed-of-at-least-32-bytes-1234", "jti-cnf");
        let claims = OlpLicenseClaims {
            iss: "i".into(),
            sub: "s".into(),
            aud: "a".into(),
            iat: now,
            exp: now + 60,
            jti: "jti-cnf".into(),
            scope: "x".into(),
            license_urn: "u".into(),
            cnf: Some(cnf.clone()),
        };
        let token = signer.sign(&claims).unwrap();
        let verifier = OlpTokenVerifier::new(signer.verifying_key(), "kid-1");
        let rev = KvRevocationStore::new(mem_store(), "a");

        let with_cnf = introspect(&verifier, &rev, &token, now, true).unwrap();
        assert!(with_cnf.cnf.is_some(), "mirror_cnf=true must surface cnf");

        let without_cnf = introspect(&verifier, &rev, &token, now, false).unwrap();
        assert!(without_cnf.cnf.is_none(), "mirror_cnf=false must strip cnf");
    }

    #[test]
    fn revocation_store_scopes_keys_by_audience() {
        let store = mem_store();
        let rev_a = KvRevocationStore::new(store.clone(), "alpha.example.com");
        let rev_b = KvRevocationStore::new(store.clone(), "beta.example.com");
        rev_a.revoke("jti-1", 300, "test").unwrap();
        assert!(rev_a.is_revoked("jti-1").unwrap());
        assert!(
            !rev_b.is_revoked("jti-1").unwrap(),
            "revoking under alpha must not affect beta's view"
        );
    }

    #[test]
    fn inactive_response_serializes_to_minimal_json() {
        // RFC 7662 §2.2: SHOULD NOT include additional information
        // about an inactive token. The on-the-wire JSON must be
        // literally `{"active":false}`.
        let body = serde_json::to_string(&IntrospectResponse::inactive()).unwrap();
        assert_eq!(body, r#"{"active":false}"#);
    }
}
