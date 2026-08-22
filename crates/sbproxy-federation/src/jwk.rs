//! Federation JWK set + RFC 7638 SHA-256 thumbprint.
//!
//! An entity statement carries the issuer's public keys under a
//! top-level `jwks` claim (§3.1.1). The set is a JWKS per RFC 7517;
//! this module wraps the JSON shape with a Rust API + the thumbprint
//! helper an operator uses to derive a stable `kid`.

use serde::{Deserialize, Serialize};

use crate::errors::FederationError;

/// JWKS that travels in `entity_statement.jwks`. We do not re-implement
/// the cryptographic shape; the inner `keys` list is a passthrough of
/// the operator's JWK JSON. The intent of this type is documentation +
/// the `kid` lookup helper, not parsing the EC / RSA / OKP coordinate
/// bytes (the JWS verifier already does that via `jsonwebtoken`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationKeySet {
    /// One or more public keys. The OIDF spec is silent on minimum
    /// count; in practice an entity ships its current key plus one
    /// rolled-over key during a rotation window.
    pub keys: Vec<serde_json::Value>,
}

impl FederationKeySet {
    /// Build an empty key set. Mostly useful for tests; production
    /// federations always ship at least one key.
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Append a JWK to the set. The caller is responsible for
    /// ensuring the JWK carries a `kid`; without one the JWS verifier
    /// cannot pick the right key.
    pub fn push(&mut self, jwk: serde_json::Value) {
        self.keys.push(jwk);
    }

    /// Look up a key by `kid`. Returns `None` when no key matches.
    pub fn find_by_kid(&self, kid: &str) -> Option<&serde_json::Value> {
        self.keys
            .iter()
            .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
    }

    /// Lift the matching JWK to a `jsonwebtoken::DecodingKey` so the
    /// verifier can check a signature against it. Returns
    /// [`FederationError::UnsupportedJwk`] when the JWK shape is
    /// neither EC / RSA / OKP (an `oct` symmetric JWK is rejected on
    /// principle: an entity statement MUST be verifiable by any peer).
    pub fn decoding_key_for(
        &self,
        kid: &str,
    ) -> Result<jsonwebtoken::DecodingKey, FederationError> {
        let jwk = self
            .find_by_kid(kid)
            .ok_or_else(|| FederationError::UnknownKid(kid.to_string()))?;
        let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
            FederationError::UnsupportedJwk {
                kid: kid.to_string(),
                kty: "missing".to_string(),
            }
        })?;
        match kty {
            "EC" => {
                let x = jwk_str(jwk, "x", kid)?;
                let y = jwk_str(jwk, "y", kid)?;
                jsonwebtoken::DecodingKey::from_ec_components(x, y).map_err(|_| {
                    FederationError::UnsupportedJwk {
                        kid: kid.to_string(),
                        kty: kty.to_string(),
                    }
                })
            }
            "RSA" => {
                let n = jwk_str(jwk, "n", kid)?;
                let e = jwk_str(jwk, "e", kid)?;
                jsonwebtoken::DecodingKey::from_rsa_components(n, e).map_err(|_| {
                    FederationError::UnsupportedJwk {
                        kid: kid.to_string(),
                        kty: kty.to_string(),
                    }
                })
            }
            "OKP" => {
                let x = jwk_str(jwk, "x", kid)?;
                jsonwebtoken::DecodingKey::from_ed_components(x).map_err(|_| {
                    FederationError::UnsupportedJwk {
                        kid: kid.to_string(),
                        kty: kty.to_string(),
                    }
                })
            }
            other => Err(FederationError::UnsupportedJwk {
                kid: kid.to_string(),
                kty: other.to_string(),
            }),
        }
    }
}

fn jwk_str<'a>(
    jwk: &'a serde_json::Value,
    field: &'static str,
    kid: &str,
) -> Result<&'a str, FederationError> {
    jwk.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::UnsupportedJwk {
            kid: kid.to_string(),
            kty: format!("missing field `{field}`"),
        })
}

/// Compute the RFC 7638 SHA-256 thumbprint of a JWK. Returns the
/// base64url-no-pad encoding so it matches the conventional `kid`
/// shape an OIDF deployment uses when an operator does not pre-assign
/// a key id.
///
/// Only the canonical members per `kty` are included in the input
/// per RFC 7638 §3.2:
/// * `EC`: `crv`, `kty`, `x`, `y`
/// * `RSA`: `e`, `kty`, `n`
/// * `OKP`: `crv`, `kty`, `x`
///
/// Returns `None` when the JWK is missing a required canonical
/// member or carries an unsupported `kty`.
pub fn jwk_thumbprint_sha256(jwk: &serde_json::Value) -> Option<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let kty = jwk.get("kty")?.as_str()?;
    let canonical = match kty {
        "EC" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = jwk.get("e")?.as_str()?;
            let n = jwk.get("n")?.as_str()?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "OKP" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        _ => return None,
    };
    let digest = Sha256::digest(canonical.as_bytes());
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 Appendix A.1 worked example: the SHA-256 thumbprint
    /// of the example RSA JWK is
    /// `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. Pinning the
    /// example guards against subtle canonicalisation regressions.
    #[test]
    fn rfc7638_appendix_a_thumbprint() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            jwk_thumbprint_sha256(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// `find_by_kid` returns the matching JWK when present and `None`
    /// when absent. The base case of the JWS verification path.
    #[test]
    fn find_by_kid_returns_matching_or_none() {
        let mut set = FederationKeySet::empty();
        set.push(serde_json::json!({"kid": "key-2026", "kty": "EC"}));
        set.push(serde_json::json!({"kid": "key-2025", "kty": "EC"}));
        assert!(set.find_by_kid("key-2026").is_some());
        assert!(set.find_by_kid("key-2025").is_some());
        assert!(set.find_by_kid("absent").is_none());
    }

    /// `decoding_key_for` rejects an `oct` (symmetric) JWK because an
    /// entity statement MUST be verifiable by any peer holding the
    /// issuer's public key. Symmetric secrets break the federation
    /// trust model.
    #[test]
    fn decoding_key_rejects_symmetric_jwk() {
        let mut set = FederationKeySet::empty();
        set.push(serde_json::json!({"kid": "sym-1", "kty": "oct", "k": "AAAA"}));
        // `DecodingKey` does not implement Debug, so the `Result`
        // cannot use `unwrap_err`; pattern-match instead.
        let Err(err) = set.decoding_key_for("sym-1") else {
            panic!("expected UnsupportedJwk for symmetric JWK");
        };
        assert!(matches!(err, FederationError::UnsupportedJwk { .. }));
    }

    /// `decoding_key_for` on an unknown `kid` returns the typed
    /// [`FederationError::UnknownKid`] rather than silently falling
    /// back; the OIDF spec forbids verifying with an unannounced key.
    #[test]
    fn decoding_key_rejects_unknown_kid() {
        let set = FederationKeySet::empty();
        let Err(err) = set.decoding_key_for("missing") else {
            panic!("expected UnknownKid for absent kid");
        };
        assert!(matches!(err, FederationError::UnknownKid(k) if k == "missing"));
    }
}
