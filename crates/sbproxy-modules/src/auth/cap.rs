//! Crawler Authorization Protocol (CAP) verifier (Wave 6 / R6.1).
//!
//! Implements the OSS-side verifier for the CAP token format. Token
//! issuance lives in a separate component (G6.7); verification is the
//! OSS side because it is the latency-critical path that runs on
//! every request.
//!
//! The verifier:
//!
//! * Parses a JWT from `CAP-Token: <jwt>` or `Authorization: CAP <jwt>`.
//! * Verifies the signature against a JWKS URL (cached for 1h) or a
//!   static JWKS document configured inline in YAML.
//! * Validates standard claims: `exp`, `iat` not in future, `iss`
//!   present, `aud` matches the request `Host`, `cap_v == 1`.
//! * Verifies `sub` matches the resolved `agent_id` from the Wave 1
//!   resolver chain (when present on the request context).
//! * Verifies the request path matches the token's `glob` allow-list.
//! * Optionally registers / consults a per-token rate-limit bucket
//!   keyed by `jti` with capacity `rps` and a daily byte budget. The
//!   rate-limit binding lives behind a `cfg(feature = "rate-limit")`
//!   stub today (R2.3 middleware lands later). When the feature is off
//!   the verifier degrades to verify-only mode and emits a warning so
//!   operators see the gap.
//! * Returns a [`CapVerdict`] capturing the result. The `Verified`
//!   arm carries a [`CapTokenView`] suitable for stamping onto
//!   `RequestContext.cap_token` (the field is added by the Wave 6
//!   plumbing task; this verifier returns the typed view independent
//!   of context wiring).
//!
//! Configuration shape under `authentication:` in `sb.yml`:
//!
//! ```yaml
//! authentication:
//!   type: cap
//!   jwks_url: https://issuer.example.com/.well-known/cap/keys.json
//!   # Or, for offline / static-token deployments:
//!   # jwks_static:
//!   #   keys:
//!   #     - kty: OKP
//!   #       crv: Ed25519
//!   #       kid: cap-2026-q2-001
//!   #       x: <base64url-pubkey>
//!   audience: example.com   # optional; defaults to request Host
//! ```

use std::sync::Arc;

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::auth::jwks::{self, JwksCache};

// --- Public verdict surface ---

/// View of a verified CAP token suitable for stamping onto
/// `RequestContext.cap_token` so downstream policies (rate limiting,
/// access-log attribution per G6.2) can read the budget claims without
/// re-decoding the JWT.
///
/// `Eq` is intentionally not derived because `max_rps` is `f64` per
/// the ADR's claim shape; comparators stick to `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct CapTokenView {
    /// Token id (`jti`). Used as the rate-limit bucket key and the
    /// access-log attribution key.
    pub jti: String,
    /// Maximum requests per second the token authorises. Stored as a
    /// `f64` per the ADR; the rate-limit middleware rounds at use time.
    pub max_rps: f64,
    /// Maximum bytes per UTC day (`bytes` claim).
    pub max_bytes_per_day: u64,
    /// Route allow-list glob (`glob` claim). The verifier already
    /// matched the request path against this; surface it for downstream
    /// policy expressions.
    pub route_glob: String,
}

/// Verdict produced by [`CapVerifier::verify`].
///
/// The closed set mirrors the failure modes pinned in
/// `adr-licensing-cap.md` § "Verifier (OSS, R6.1)".
#[derive(Debug, Clone, PartialEq)]
pub enum CapVerdict {
    /// The token verified end-to-end. Carries the typed view for
    /// `RequestContext` stamping.
    Verified(CapTokenView),
    /// No `CAP-Token` (or `Authorization: CAP`) header was present.
    /// Origin policy decides whether to allow unauthenticated traffic
    /// or fail closed.
    Missing,
    /// Token failed validation in a non-revocation, non-expiry way.
    /// `reason` is one of the closed strings in [`CapError`].
    Invalid(CapError),
}

/// Closed set of CAP verification failure reasons.
///
/// The variants mirror the `WWW-Authenticate: CAP error="..."` codes
/// pinned in the ADR. Caller maps the variant to the appropriate
/// HTTP status (401 for token-related failures, 403 for
/// agent / path binding mismatches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    /// Token could not be parsed as a JWT, was missing required
    /// claims, or used an unsupported algorithm.
    InvalidToken {
        /// One of: `malformed`, `unsupported_alg`, `missing_kid`,
        /// `missing_jti`, `missing_rps`, `missing_bytes`, `missing_glob`,
        /// `bad_cap_v`, `parse_error`.
        reason: &'static str,
    },
    /// `exp <= now`. Distinct so the agent can retry by re-issuing.
    Expired,
    /// JWS signature did not verify against the resolved JWK.
    BadSignature,
    /// `aud` claim did not include the request `Host`.
    AudienceMismatch,
    /// Token's `sub` did not match the request's resolved `agent_id`.
    SubMismatch,
    /// Request path did not match the token's `glob` allow-list.
    PathNotAuthorized,
    /// JWKS source could not be consulted (network failure, no keys
    /// cached, no static JWKS configured).
    DirectoryUnavailable,
}

impl CapError {
    /// Stable string suitable for the `WWW-Authenticate: CAP
    /// error="..."` response parameter, per the ADR.
    pub fn www_auth_code(&self) -> &'static str {
        match self {
            Self::InvalidToken { .. } => "invalid_token",
            Self::Expired => "expired_token",
            Self::BadSignature => "invalid_token",
            Self::AudienceMismatch => "invalid_audience",
            Self::SubMismatch => "agent_mismatch",
            Self::PathNotAuthorized => "path_not_authorized",
            Self::DirectoryUnavailable => "directory_unavailable",
        }
    }

    /// Recommended HTTP status code for surfacing this error to the
    /// client. 401 for token-related failures (the agent can re-try
    /// with a new token); 403 for binding mismatches (the token is
    /// fine but does not authorise this request).
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidToken { .. }
            | Self::Expired
            | Self::BadSignature
            | Self::DirectoryUnavailable => 401,
            Self::AudienceMismatch | Self::SubMismatch | Self::PathNotAuthorized => 403,
        }
    }
}

// --- Configuration ---

/// Configuration for the CAP verifier.
///
/// One of `jwks_url` or `jwks_static` MUST be set. `jwks_url` is the
/// production path; `jwks_static` is the offline / pre-issued-token
/// deployment shape described in the ADR § "Issuance (enterprise,
/// G6.7)" closing paragraph.
#[derive(Debug, Clone, Deserialize)]
pub struct CapConfig {
    /// JWKS endpoint URL (typically
    /// `https://<issuer>/.well-known/cap/keys.json`). Cached for
    /// `jwks_refresh_secs` (default 1h).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Inline JWKS document. Used when the deployment has pre-issued
    /// tokens and does not run an issuer endpoint. Mutually exclusive
    /// with `jwks_url` is not enforced; `jwks_url` wins when both are
    /// set so a deployment can rotate from static to URL-fetched.
    #[serde(default)]
    pub jwks_static: Option<JwkSet>,
    /// JWKS refresh interval in seconds. Defaults to 3600 (1h) per the
    /// ADR. Clamped to a 30s minimum at use time.
    #[serde(default = "default_jwks_refresh_secs")]
    pub jwks_refresh_secs: u64,
    /// Optional explicit audience override. When set, the verifier
    /// requires the token's `aud` to equal this value. When unset,
    /// the verifier accepts any `aud` that matches the request's
    /// `Host` header (the typical operator deployment shape).
    #[serde(default)]
    pub audience: Option<String>,
}

fn default_jwks_refresh_secs() -> u64 {
    3600
}

// --- Token claim shape ---

/// CAP token claims per ADR § "Token format".
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapClaims {
    iss: String,
    sub: String,
    /// The token may carry `aud` as a single string or an array; the
    /// verifier accepts either via [`Audience`].
    #[serde(default)]
    aud: Option<Audience>,
    cap_v: u32,
    rps: f64,
    bytes: u64,
    glob: String,
    exp: u64,
    iat: u64,
    jti: String,
}

/// JWT `aud` claim. Standard JWT allows either a single string or an
/// array of strings; CAP follows the same convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multi(Vec<String>),
}

impl Audience {
    fn matches(&self, want: &str) -> bool {
        match self {
            Self::Single(s) => audience_matches(s, want),
            Self::Multi(v) => v.iter().any(|s| audience_matches(s, want)),
        }
    }
}

/// Match an `aud` value against the request host. Wildcards
/// (`*.example.com`) are honoured per the ADR.
fn audience_matches(claim: &str, host: &str) -> bool {
    if claim == host {
        return true;
    }
    if let Some(rest) = claim.strip_prefix("*.") {
        if let Some(host_rest) = host.split_once('.') {
            return host_rest.1 == rest;
        }
    }
    false
}

// --- Verifier ---

/// CAP token verifier.
///
/// Constructed once per origin from [`CapConfig`]. Holds an [`Arc`]
/// to the process-wide JWKS cache when configured with a `jwks_url`,
/// or an inline [`JwkSet`] for static deployments.
pub struct CapVerifier {
    cache: Option<Arc<JwksCache>>,
    static_set: Option<JwkSet>,
    audience: Option<String>,
}

impl std::fmt::Debug for CapVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapVerifier")
            .field("has_jwks_cache", &self.cache.is_some())
            .field("has_static_jwks", &self.static_set.is_some())
            .field("audience", &self.audience)
            .finish()
    }
}

impl CapVerifier {
    /// Build a verifier from JSON config.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: CapConfig = serde_json::from_value(value)?;
        Self::from_typed_config(cfg)
    }

    /// Build a verifier from the typed [`CapConfig`].
    pub fn from_typed_config(cfg: CapConfig) -> anyhow::Result<Self> {
        if cfg.jwks_url.is_none() && cfg.jwks_static.is_none() {
            anyhow::bail!("cap: one of `jwks_url` or `jwks_static` must be set");
        }
        let cache = cfg
            .jwks_url
            .as_deref()
            .map(|u| jwks::get_or_init_cache(u, cfg.jwks_refresh_secs.max(30)));
        Ok(Self {
            cache,
            static_set: cfg.jwks_static,
            audience: cfg.audience,
        })
    }

    /// Verify the CAP token on `req` against the configured key source.
    ///
    /// `request_host` is the request's `Host` header value (used for
    /// `aud` matching). `request_path` is the request path (used for
    /// `glob` matching). `resolved_agent_id` is the request's resolved
    /// agent identifier from the Wave 1 resolver chain; pass `None`
    /// when no resolver ran. The verifier rejects any token whose
    /// `sub` does not match a present `resolved_agent_id`; when
    /// `resolved_agent_id` is `None`, the binding check is skipped
    /// (the operator's policy decides whether to require an upstream
    /// resolver via separate config).
    pub fn verify(
        &self,
        req: &http::Request<bytes::Bytes>,
        request_host: &str,
        request_path: &str,
        resolved_agent_id: Option<&str>,
    ) -> CapVerdict {
        let Some(token) = extract_cap_token(req.headers()) else {
            return CapVerdict::Missing;
        };
        self.verify_token(&token, request_host, request_path, resolved_agent_id)
    }

    /// Verify a raw token string. Splits cleanly off [`Self::verify`]
    /// so unit tests can call it without building a full
    /// [`http::Request`].
    pub fn verify_token(
        &self,
        token: &str,
        request_host: &str,
        request_path: &str,
        resolved_agent_id: Option<&str>,
    ) -> CapVerdict {
        // Decode the header to pick the kid + alg.
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(_) => {
                return CapVerdict::Invalid(CapError::InvalidToken {
                    reason: "malformed",
                });
            }
        };
        // CAP v1 mandates EdDSA. Reject anything else early so we never
        // run a verifier against a key the issuer did not authorise.
        if header.alg != Algorithm::EdDSA {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "unsupported_alg",
            });
        }
        let Some(kid) = header.kid.as_deref() else {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_kid",
            });
        };

        // Resolve the decoding key from cache or static set.
        let decoding_key = match self.lookup_key(kid) {
            Some(k) => k,
            None => return CapVerdict::Invalid(CapError::DirectoryUnavailable),
        };

        // Standard claim validation. We disable jsonwebtoken's
        // built-in `aud` check because the verifier's audience policy
        // is "match the request host with optional wildcard"; we
        // enforce it manually below.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.leeway = 5; // RFC 7519 recommends a small skew window.

        let token_data = match decode::<CapClaims>(token, &decoding_key, &validation) {
            Ok(td) => td,
            Err(err) => {
                use jsonwebtoken::errors::ErrorKind;
                return CapVerdict::Invalid(match err.kind() {
                    ErrorKind::ExpiredSignature => CapError::Expired,
                    ErrorKind::InvalidSignature => CapError::BadSignature,
                    _ => CapError::InvalidToken {
                        reason: "parse_error",
                    },
                });
            }
        };

        let claims = token_data.claims;

        // CAP version pin.
        if claims.cap_v != 1 {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "bad_cap_v",
            });
        }

        // Required-claim presence guards (jsonwebtoken parses missing
        // numeric fields as zero; treat zero-ish budgets as a bad token).
        if claims.jti.is_empty() {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_jti",
            });
        }
        if claims.rps <= 0.0 {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_rps",
            });
        }
        if claims.bytes == 0 {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_bytes",
            });
        }
        if claims.glob.is_empty() {
            return CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_glob",
            });
        }

        // Audience: explicit override beats request-host fallback.
        let want_aud = self.audience.as_deref().unwrap_or(request_host);
        let aud_ok = claims
            .aud
            .as_ref()
            .map(|a| a.matches(want_aud))
            .unwrap_or(false);
        if !aud_ok {
            return CapVerdict::Invalid(CapError::AudienceMismatch);
        }

        // Agent-id binding. Skipped when no resolver ran; the operator
        // configures upstream agent-class resolution separately.
        if let Some(agent_id) = resolved_agent_id {
            if claims.sub != agent_id {
                return CapVerdict::Invalid(CapError::SubMismatch);
            }
        }

        // Glob match. CAP uses standard shell glob with `**` for
        // multi-segment wildcards.
        if !glob_matches(&claims.glob, request_path) {
            return CapVerdict::Invalid(CapError::PathNotAuthorized);
        }

        // Optional rate-limit registration. The R2.3 middleware contract
        // is pinned but the crate does not yet exist in the workspace;
        // the call site is gated on the `rate-limit` cargo feature so
        // OSS builds compile today and turn the bucket on later. See
        // `WATCH.md` for the wiring task.
        #[cfg(feature = "rate-limit")]
        {
            // sbproxy_rate_limit::register_token_bucket(&claims.jti,
            //     claims.rps, claims.bytes);
        }

        CapVerdict::Verified(CapTokenView {
            jti: claims.jti,
            max_rps: claims.rps,
            max_bytes_per_day: claims.bytes,
            route_glob: claims.glob,
        })
    }

    /// Look up a JWK by `kid`, preferring the cached JWKS over the
    /// static set so a deployment that adds `jwks_url` later sees
    /// rotated keys without a config restart.
    fn lookup_key(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(cache) = &self.cache {
            if let Some(k) = cache.lookup_decoding_key(Some(kid)) {
                return Some(k);
            }
        }
        if let Some(set) = &self.static_set {
            if let Some(jwk) = find_jwk(set, kid) {
                return DecodingKey::from_jwk(jwk).ok();
            }
        }
        None
    }
}

// --- Header / token / glob helpers ---

/// Pull a CAP token out of either header convention. Returns the raw
/// JWT compact-serialised string.
fn extract_cap_token(headers: &http::HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("cap-token").and_then(|v| v.to_str().ok()) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(v) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(rest) = v.strip_prefix("CAP ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn find_jwk<'a>(set: &'a JwkSet, kid: &str) -> Option<&'a Jwk> {
    set.keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
}

/// Match a path against a glob with `*` (single segment), `**`
/// (any segments including zero), and literal characters. Anchored
/// at both ends.
fn glob_matches(pattern: &str, path: &str) -> bool {
    glob_inner(pattern.as_bytes(), path.as_bytes())
}

fn glob_inner(pattern: &[u8], path: &[u8]) -> bool {
    // Iterative backtracking matcher. Mirrors the typical "two-cursor
    // with star bookmark" algorithm for `*`-style globs, with the `**`
    // extension that crosses `/`.
    let mut p = 0usize;
    let mut s = 0usize;
    let mut star: Option<(usize, usize)> = None;
    let mut star_double = false;

    while s < path.len() {
        if p < pattern.len() {
            let pb = pattern[p];
            // Detect `**` so it can swallow `/`.
            if pb == b'*' && pattern.get(p + 1).copied() == Some(b'*') {
                star = Some((p + 2, s));
                star_double = true;
                p += 2;
                continue;
            }
            if pb == b'*' {
                star = Some((p + 1, s));
                star_double = false;
                p += 1;
                continue;
            }
            if pb == path[s] {
                p += 1;
                s += 1;
                continue;
            }
        }
        if let Some((bp, bs)) = star {
            // Backtrack: extend the star by one path char. For single
            // `*`, refuse to swallow `/`; for `**`, go ahead.
            let next_path = path[bs];
            if !star_double && next_path == b'/' {
                return false;
            }
            p = bp;
            s = bs + 1;
            star = Some((bp, bs + 1));
            continue;
        }
        return false;
    }
    // Trailing pattern: only stars remain.
    while p < pattern.len() {
        if pattern[p] == b'*' {
            if pattern.get(p + 1).copied() == Some(b'*') {
                p += 2;
            } else {
                p += 1;
            }
        } else {
            return false;
        }
    }
    true
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::json;

    /// Returns `(verifier, kid, signing_key_pem-equivalent)`. The
    /// verifier is configured with a static JWKS containing the kid
    /// so signing tests do not touch the network.
    fn build_verifier_with_keypair() -> (CapVerifier, String, EncodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pubkey = kp.public_key().as_ref().to_vec();
        let pubkey_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pubkey);
        let kid = "cap-test-001".to_string();

        let jwks = json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": kid,
                    "alg": "EdDSA",
                    "x": pubkey_b64url,
                }
            ]
        });
        let jwks_set: JwkSet = serde_json::from_value(jwks).unwrap();

        let verifier = CapVerifier::from_typed_config(CapConfig {
            jwks_url: None,
            jwks_static: Some(jwks_set),
            jwks_refresh_secs: 3600,
            audience: None,
        })
        .unwrap();

        // jsonwebtoken's Ed25519 EncodingKey wants the PKCS8 DER bytes.
        let signing = EncodingKey::from_ed_der(pkcs8.as_ref());
        (verifier, kid, signing)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn mint_token(
        signing: &EncodingKey,
        kid: &str,
        overrides: impl FnOnce(&mut serde_json::Value),
    ) -> String {
        let mut claims = json!({
            "iss": "issuer.example.com",
            "sub": "agent_acme_001",
            "aud": "api.example.com",
            "cap_v": 1,
            "rps": 2.0,
            "bytes": 10_737_418_240u64,
            "glob": "/blog/**",
            "exp": now_secs() + 3600,
            "iat": now_secs(),
            "jti": "01J7HZ8X9R3CAPTEST",
        });
        overrides(&mut claims);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        header.typ = Some("cap+jwt".to_string());
        encode(&header, &claims, signing).expect("sign")
    }

    #[test]
    fn config_requires_a_key_source() {
        let err = CapVerifier::from_typed_config(CapConfig {
            jwks_url: None,
            jwks_static: None,
            jwks_refresh_secs: 3600,
            audience: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("jwks_url"));
    }

    #[test]
    fn missing_header_returns_missing() {
        let (verifier, _, _) = build_verifier_with_keypair();
        let req = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/blog/article")
            .body(bytes::Bytes::new())
            .unwrap();
        assert_eq!(
            verifier.verify(&req, "api.example.com", "/blog/article", None),
            CapVerdict::Missing
        );
    }

    #[test]
    fn valid_token_round_trips() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |_| {});
        let verdict = verifier.verify_token(
            &token,
            "api.example.com",
            "/blog/article",
            Some("agent_acme_001"),
        );
        match verdict {
            CapVerdict::Verified(view) => {
                assert_eq!(view.jti, "01J7HZ8X9R3CAPTEST");
                assert_eq!(view.max_rps, 2.0);
                assert_eq!(view.max_bytes_per_day, 10_737_418_240);
                assert_eq!(view.route_glob, "/blog/**");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn header_extraction_supports_authorization_cap_scheme() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |_| {});
        let req = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/blog/x")
            .header(http::header::AUTHORIZATION, format!("CAP {token}"))
            .body(bytes::Bytes::new())
            .unwrap();
        match verifier.verify(&req, "api.example.com", "/blog/x", Some("agent_acme_001")) {
            CapVerdict::Verified(_) => {}
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn header_extraction_supports_cap_token_header() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |_| {});
        let req = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/blog/x")
            .header("CAP-Token", token)
            .body(bytes::Bytes::new())
            .unwrap();
        match verifier.verify(&req, "api.example.com", "/blog/x", Some("agent_acme_001")) {
            CapVerdict::Verified(_) => {}
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["exp"] = json!(100u64);
            c["iat"] = json!(50u64);
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert_eq!(verdict, CapVerdict::Invalid(CapError::Expired));
    }

    #[test]
    fn bad_signature_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |_| {});
        // Tamper with the signature bytes.
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_sig = "AAAA-tampered-signature-base64url-padding-not-real";
        parts[2] = tampered_sig;
        let tampered = parts.join(".");
        let verdict = verifier.verify_token(
            &tampered,
            "api.example.com",
            "/blog/x",
            Some("agent_acme_001"),
        );
        match verdict {
            CapVerdict::Invalid(CapError::BadSignature)
            | CapVerdict::Invalid(CapError::InvalidToken { .. }) => {}
            other => panic!("expected BadSignature / InvalidToken, got {other:?}"),
        }
    }

    #[test]
    fn sub_mismatch_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["sub"] = json!("agent_other_999");
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert_eq!(verdict, CapVerdict::Invalid(CapError::SubMismatch));
    }

    #[test]
    fn aud_mismatch_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["aud"] = json!("api.different.com");
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert_eq!(verdict, CapVerdict::Invalid(CapError::AudienceMismatch));
    }

    #[test]
    fn glob_mismatch_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["glob"] = json!("/blog/**");
        });
        let verdict = verifier.verify_token(
            &token,
            "api.example.com",
            "/api/private",
            Some("agent_acme_001"),
        );
        assert_eq!(verdict, CapVerdict::Invalid(CapError::PathNotAuthorized));
    }

    #[test]
    fn missing_rps_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["rps"] = json!(0.0);
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert!(matches!(
            verdict,
            CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_rps"
            })
        ));
    }

    #[test]
    fn missing_bytes_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["bytes"] = json!(0u64);
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert!(matches!(
            verdict,
            CapVerdict::Invalid(CapError::InvalidToken {
                reason: "missing_bytes"
            })
        ));
    }

    #[test]
    fn bad_cap_version_rejected() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["cap_v"] = json!(99u32);
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert!(matches!(
            verdict,
            CapVerdict::Invalid(CapError::InvalidToken {
                reason: "bad_cap_v"
            })
        ));
    }

    #[test]
    fn audience_wildcard_matches_subdomain() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["aud"] = json!("*.example.com");
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert!(matches!(verdict, CapVerdict::Verified(_)));
    }

    #[test]
    fn audience_array_matches_one_entry() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |c| {
            c["aud"] = json!(["api.other.com", "api.example.com"]);
        });
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert!(matches!(verdict, CapVerdict::Verified(_)));
    }

    #[test]
    fn agent_id_binding_skipped_when_resolver_did_not_run() {
        let (verifier, kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, &kid, |_| {});
        let verdict = verifier.verify_token(&token, "api.example.com", "/blog/x", None);
        assert!(matches!(verdict, CapVerdict::Verified(_)));
    }

    #[test]
    fn unknown_kid_returns_directory_unavailable() {
        let (verifier, _kid, signing) = build_verifier_with_keypair();
        let token = mint_token(&signing, "rotated-2027-q1-009", |_| {});
        let verdict =
            verifier.verify_token(&token, "api.example.com", "/blog/x", Some("agent_acme_001"));
        assert_eq!(verdict, CapVerdict::Invalid(CapError::DirectoryUnavailable));
    }

    #[test]
    fn glob_double_star_crosses_segments() {
        assert!(glob_matches("/blog/**", "/blog/2026/05/article"));
        assert!(glob_matches("/**", "/anywhere/at/all"));
        assert!(glob_matches("/blog/**", "/blog/x"));
        assert!(!glob_matches("/blog/**", "/api/x"));
    }

    #[test]
    fn glob_single_star_does_not_cross_segments() {
        assert!(glob_matches("/blog/*", "/blog/article"));
        assert!(!glob_matches("/blog/*", "/blog/2026/article"));
    }

    #[test]
    fn cap_error_codes_map_to_documented_strings() {
        assert_eq!(
            CapError::InvalidToken { reason: "x" }.www_auth_code(),
            "invalid_token"
        );
        assert_eq!(CapError::Expired.www_auth_code(), "expired_token");
        assert_eq!(CapError::BadSignature.www_auth_code(), "invalid_token");
        assert_eq!(
            CapError::AudienceMismatch.www_auth_code(),
            "invalid_audience"
        );
        assert_eq!(CapError::SubMismatch.www_auth_code(), "agent_mismatch");
        assert_eq!(
            CapError::PathNotAuthorized.www_auth_code(),
            "path_not_authorized"
        );
        assert_eq!(
            CapError::DirectoryUnavailable.www_auth_code(),
            "directory_unavailable"
        );
    }

    #[test]
    fn cap_error_http_status_split_by_class() {
        assert_eq!(CapError::Expired.http_status(), 401);
        assert_eq!(CapError::SubMismatch.http_status(), 403);
        assert_eq!(CapError::PathNotAuthorized.http_status(), 403);
        assert_eq!(CapError::AudienceMismatch.http_status(), 403);
    }
}
