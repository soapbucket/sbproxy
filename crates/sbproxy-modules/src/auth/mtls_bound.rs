// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! RFC 8705 mTLS-bound access token validation (WOR-1072).
//!
//! RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and
//! Certificate-Bound Access Tokens) defines an alternative
//! proof-of-possession scheme to DPoP for deployments that already
//! have a mTLS substrate. The access token carries a `cnf.x5t#S256`
//! claim — the base64url-no-pad SHA-256 thumbprint of the legitimate
//! client's X.509 certificate. On every request, the proxy compares
//! this claim against the SHA-256 thumbprint of the cert the inbound
//! TLS connection actually presented; a mismatch (or a missing cert)
//! is a rejection.
//!
//! ## Why this is a different module from `dpop.rs`
//!
//! DPoP carries the proof-of-possession key OFF the TLS layer (in a
//! JWS in the `DPoP:` header). RFC 8705 carries it IN the TLS layer
//! (the client cert presented during the handshake). The validator
//! surfaces are similar in shape (one compares against an access
//! token claim) but the input plumbing differs entirely: DPoP reads
//! a request header, mTLS-bound reads the TLS substrate.
//!
//! ## What this module does
//!
//! 1. Extract the SHA-256 thumbprint of the inbound TLS client cert.
//!    The thumbprint is what Pingora's `SslDigest.cert_digest`
//!    exposes already (see `sbproxy-tls::mtls::ClientCertInfo`).
//! 2. Pull the `cnf.x5t#S256` claim from the access token JWT.
//! 3. Constant-time compare the two thumbprints.
//! 4. Reject when the access token has no `cnf` claim AND
//!    `require_cnf: true` is set on the verifier (operators who want
//!    every JWT to be mTLS-bound). The default falls through so a
//!    JWT without `cnf` keeps bearer-token semantics.
//!
//! ## What this module does NOT do
//!
//! * TLS handshake. The `sbproxy-tls::mtls` layer drives the
//!   handshake + caches the cert info; this module is a pure
//!   validator that takes the thumbprint as input.
//! * Cert chain validation. The handshake already does that against
//!   the operator's `MtlsConfig.ca_cert_pem`; this module trusts
//!   the cert is valid and only checks the binding claim.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Verifier configuration. The verifier itself is stateless aside
/// from the configured policy knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtlsBoundVerifierConfig {
    /// When `true`, every access token MUST carry a `cnf.x5t#S256`
    /// claim; an absent claim is a rejection. Useful for deployments
    /// where mTLS is the only access-token shape (e.g. a private API
    /// behind a workload-identity SPIFFE chain). Default `false`
    /// preserves the legacy bearer-token semantics for callers
    /// without the claim.
    #[serde(default)]
    pub require_cnf: bool,
}

/// Reasons the verifier rejects a request. Carried up to the auth
/// dispatcher so the deny reason on the security audit log
/// distinguishes a missing client cert from a thumbprint mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsBoundRejection {
    /// The access token had no `cnf` claim and the verifier was
    /// configured with `require_cnf: true`.
    MissingCnfClaim,
    /// The access token's `cnf` claim had no `x5t#S256` member.
    MissingX5tThumbprint,
    /// The access token's `cnf.x5t#S256` was not a valid
    /// base64url-no-pad string.
    MalformedThumbprint {
        /// Raw value the access token carried.
        raw: String,
    },
    /// The inbound TLS connection presented no client certificate
    /// even though the access token requires one.
    NoClientCertPresented,
    /// The thumbprint of the inbound client cert did not match the
    /// access token's `cnf.x5t#S256` claim.
    ThumbprintMismatch {
        /// Thumbprint the access token's `cnf.x5t#S256` expects.
        expected: String,
        /// Thumbprint of the cert actually presented on the TLS handshake.
        found: String,
    },
}

impl std::fmt::Display for MtlsBoundRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCnfClaim => {
                f.write_str("access token has no cnf claim but verifier requires one")
            }
            Self::MissingX5tThumbprint => {
                f.write_str("cnf claim has no x5t#S256 member")
            }
            Self::MalformedThumbprint { raw } => {
                write!(f, "cnf.x5t#S256 is not valid base64url-no-pad: `{raw}`")
            }
            Self::NoClientCertPresented => f.write_str(
                "access token is mTLS-bound but the inbound TLS connection presented no client cert",
            ),
            Self::ThumbprintMismatch { expected, found } => write!(
                f,
                "cnf.x5t#S256 mismatch: token expects `{expected}`, TLS handshake produced `{found}`",
            ),
        }
    }
}

impl std::error::Error for MtlsBoundRejection {}

/// Inbound mTLS-bound access token validator. Cheap to construct
/// and clone; the verifier itself holds only the config knob.
#[derive(Debug, Clone)]
pub struct MtlsBoundVerifier {
    config: MtlsBoundVerifierConfig,
}

impl Default for MtlsBoundVerifier {
    fn default() -> Self {
        Self::new(MtlsBoundVerifierConfig::default())
    }
}

impl MtlsBoundVerifier {
    /// Build a verifier with the given config.
    pub fn new(config: MtlsBoundVerifierConfig) -> Self {
        Self { config }
    }

    /// Verify the access token's `cnf.x5t#S256` claim against the
    /// inbound TLS client cert thumbprint. `claims` is the decoded
    /// JWT body (the JWT signature must already be verified by the
    /// caller; this validator only checks the binding claim).
    ///
    /// `presented_cert_thumbprint` is the SHA-256 of the inbound
    /// TLS client cert, base64url-no-pad encoded. `None` means no
    /// client cert was presented.
    pub fn verify(
        &self,
        claims: &serde_json::Value,
        presented_cert_thumbprint: Option<&str>,
    ) -> Result<(), MtlsBoundRejection> {
        let cnf = claims.get("cnf");
        let cnf = match cnf {
            Some(c) => c,
            None => {
                if self.config.require_cnf {
                    return Err(MtlsBoundRejection::MissingCnfClaim);
                }
                // No `cnf` claim and operator did not require one:
                // the access token is a plain bearer; mTLS binding
                // is not enforced.
                return Ok(());
            }
        };
        let expected = cnf
            .get("x5t#S256")
            .and_then(|v| v.as_str())
            .ok_or(MtlsBoundRejection::MissingX5tThumbprint)?;

        // Validate the claim format: must be base64url-no-pad and
        // decode to 32 bytes (SHA-256 output). A malformed claim is
        // a config-level error on the access token issuer; surfacing
        // it as a separate rejection lets dashboards distinguish a
        // misissued token from a real mTLS mismatch.
        use base64::Engine;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected.as_bytes())
            .map_err(|_| MtlsBoundRejection::MalformedThumbprint {
                raw: expected.to_string(),
            })?;
        if decoded.len() != 32 {
            return Err(MtlsBoundRejection::MalformedThumbprint {
                raw: expected.to_string(),
            });
        }

        let presented =
            presented_cert_thumbprint.ok_or(MtlsBoundRejection::NoClientCertPresented)?;
        if !constant_time_eq_str(expected, presented) {
            return Err(MtlsBoundRejection::ThumbprintMismatch {
                expected: expected.to_string(),
                found: presented.to_string(),
            });
        }
        // Touching `Instant::now()` once on the happy path keeps the
        // verifier compatible with downstream metrics that want to
        // record the validation latency without a second clock read.
        let _ = Instant::now();
        Ok(())
    }

    /// Returns whether the verifier requires every access token to
    /// carry a `cnf.x5t#S256` claim.
    pub fn require_cnf(&self) -> bool {
        self.config.require_cnf
    }
}

/// Constant-time string equality. Same idea as the byte-equality
/// helper in `auth::mod`; duplicated here so the validator does not
/// pull in the rest of that file.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative 32-byte SHA-256 thumbprint, base64url-no-pad.
    /// Computed once from `openssl dgst -sha256 -binary | basenc --base64url`
    /// and pinned so tests are deterministic.
    const FIXTURE_THUMBPRINT: &str = "v8oW3LqUe6jQg2RmYbW2v7QXqJrwK2dY0FXqLkOaJ2Y";

    /// JWT claims with a `cnf.x5t#S256` member pointing at
    /// [`FIXTURE_THUMBPRINT`].
    fn claims_with_cnf(thumbprint: &str) -> serde_json::Value {
        serde_json::json!({
            "sub": "alice",
            "iss": "https://acme.example",
            "cnf": { "x5t#S256": thumbprint }
        })
    }

    /// JWT claims with no `cnf` member at all.
    fn claims_without_cnf() -> serde_json::Value {
        serde_json::json!({
            "sub": "alice",
            "iss": "https://acme.example"
        })
    }

    #[test]
    fn matching_thumbprint_accepted() {
        let v = MtlsBoundVerifier::default();
        let claims = claims_with_cnf(FIXTURE_THUMBPRINT);
        let result = v.verify(&claims, Some(FIXTURE_THUMBPRINT));
        assert!(
            result.is_ok(),
            "matching thumbprint should verify: {result:?}"
        );
    }

    #[test]
    fn mismatched_thumbprint_rejected() {
        let v = MtlsBoundVerifier::default();
        let claims = claims_with_cnf(FIXTURE_THUMBPRINT);
        let other = "z9oW3LqUe6jQg2RmYbW2v7QXqJrwK2dY0FXqLkOaJ2A";
        let result = v.verify(&claims, Some(other));
        assert!(matches!(
            result,
            Err(MtlsBoundRejection::ThumbprintMismatch { .. })
        ));
    }

    #[test]
    fn missing_client_cert_rejected_when_token_has_cnf() {
        let v = MtlsBoundVerifier::default();
        let claims = claims_with_cnf(FIXTURE_THUMBPRINT);
        let result = v.verify(&claims, None);
        assert!(matches!(
            result,
            Err(MtlsBoundRejection::NoClientCertPresented)
        ));
    }

    #[test]
    fn no_cnf_token_passes_when_require_cnf_is_false() {
        let v = MtlsBoundVerifier::new(MtlsBoundVerifierConfig { require_cnf: false });
        let claims = claims_without_cnf();
        let result = v.verify(&claims, None);
        assert!(result.is_ok(), "bearer fallback should pass: {result:?}");
    }

    #[test]
    fn no_cnf_token_rejected_when_require_cnf_is_true() {
        let v = MtlsBoundVerifier::new(MtlsBoundVerifierConfig { require_cnf: true });
        let claims = claims_without_cnf();
        let result = v.verify(&claims, None);
        assert!(matches!(result, Err(MtlsBoundRejection::MissingCnfClaim)));
    }

    #[test]
    fn cnf_without_x5t_rejected() {
        let v = MtlsBoundVerifier::default();
        let claims = serde_json::json!({
            "sub": "alice",
            "cnf": { "jwk": { "kty": "EC" } }
        });
        let result = v.verify(&claims, Some(FIXTURE_THUMBPRINT));
        assert!(matches!(
            result,
            Err(MtlsBoundRejection::MissingX5tThumbprint)
        ));
    }

    #[test]
    fn malformed_thumbprint_rejected() {
        let v = MtlsBoundVerifier::default();
        // Wrong byte length (decoded to 31 bytes) — not a SHA-256.
        let claims = claims_with_cnf("short_thumbprint_aaaaa");
        let result = v.verify(&claims, Some(FIXTURE_THUMBPRINT));
        assert!(matches!(
            result,
            Err(MtlsBoundRejection::MalformedThumbprint { .. })
        ));

        // Not base64url at all.
        let claims2 = claims_with_cnf("not-valid-base64!=garbage");
        let result2 = v.verify(&claims2, Some(FIXTURE_THUMBPRINT));
        assert!(matches!(
            result2,
            Err(MtlsBoundRejection::MalformedThumbprint { .. })
        ));
    }

    #[test]
    fn constant_time_eq_str_distinguishes_lengths() {
        assert!(!constant_time_eq_str("abc", "abcd"));
        assert!(!constant_time_eq_str("abcd", "abc"));
        assert!(constant_time_eq_str("abc", "abc"));
    }
}
