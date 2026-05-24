//! Web Bot Auth hosted key directory (WOR-805).
//!
//! Serves SBproxy's own Ed25519 public keys as an HTTP Message
//! Signatures directory per draft-meunier-http-message-signatures-
//! directory, so a third party (or SBproxy's own `bot_auth` directory
//! client) can fetch the keys needed to verify the Web Bot Auth
//! signatures SBproxy produces on its outbound requests.
//!
//! The directory document is a JWK Set: each key is an OKP / Ed25519
//! JWK carrying the raw 32-byte public key in the base64url (no pad)
//! `x` field and the configured `kid`. The serving content type is
//! `application/http-message-signatures-directory+json`.
//!
//! This module only derives and publishes the *public* half; the
//! 32-byte seed stays in config and is used by [`MessageSigner`] for
//! outbound signing.
//!
//! [`MessageSigner`]: crate::signatures_egress::MessageSigner

use base64::Engine as _;
use ed25519_dalek::SigningKey;

/// Content type for the hosted directory document, per
/// draft-meunier-http-message-signatures-directory.
pub const DIRECTORY_CONTENT_TYPE: &str = "application/http-message-signatures-directory+json";

/// One Ed25519 signing identity to publish in the directory.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryIdentity<'a> {
    /// Advertised key id (the JWK `kid` and the RFC 9421 `keyid`).
    pub key_id: &'a str,
    /// The 32-byte Ed25519 private seed. Only the derived public key
    /// is published.
    pub seed: &'a [u8; 32],
}

/// Build the OKP / Ed25519 JWK (as a `serde_json::Value`) for the
/// public key derived from `seed`. The `x` field is the base64url
/// (no pad) encoding of the 32-byte public key, matching the encoding
/// the inbound directory client decodes.
pub fn ed25519_public_jwk(key_id: &str, seed: &[u8; 32]) -> serde_json::Value {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": key_id,
        "use": "sig",
        "alg": "EdDSA",
    })
}

/// Build the directory document (a JWK Set) from one or more
/// identities. Returns the serialized JSON string ready to serve with
/// [`DIRECTORY_CONTENT_TYPE`].
pub fn build_signature_directory(identities: &[DirectoryIdentity<'_>]) -> String {
    let keys: Vec<serde_json::Value> = identities
        .iter()
        .map(|id| ed25519_public_jwk(id.key_id, id.seed))
        .collect();
    serde_json::json!({ "keys": keys }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

    fn seed() -> [u8; 32] {
        // Deterministic non-zero seed for tests.
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        s
    }

    fn decode_x(jwk: &serde_json::Value) -> [u8; 32] {
        let x = jwk["x"].as_str().unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn jwk_has_expected_okp_shape() {
        let jwk = ed25519_public_jwk("kid-1", &seed());
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["kid"], "kid-1");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(decode_x(&jwk).len(), 32);
    }

    #[test]
    fn directory_is_a_jwk_set() {
        let s = seed();
        let doc = build_signature_directory(&[DirectoryIdentity {
            key_id: "kid-1",
            seed: &s,
        }]);
        let parsed: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"][0]["kid"], "kid-1");
    }

    #[test]
    fn published_key_equals_the_seed_public_key() {
        let s = seed();
        let expected = SigningKey::from_bytes(&s).verifying_key().to_bytes();
        assert_eq!(decode_x(&ed25519_public_jwk("kid-1", &s)), expected);
    }

    #[test]
    fn published_key_verifies_a_signature_from_the_seed() {
        // Round-trip self-verify: a signature made with the seed
        // verifies under only the public key recovered from the
        // published directory JWK. This proves the directory advertises
        // the correct key for SBproxy's own signatures.
        let s = seed();
        let signing = SigningKey::from_bytes(&s);
        let message = b"web-bot-auth directory round-trip";
        let sig: Signature = signing.sign(message);

        let recovered = VerifyingKey::from_bytes(&decode_x(&ed25519_public_jwk("kid-1", &s)))
            .expect("valid ed25519 public key");
        recovered
            .verify(message, &sig)
            .expect("published key must verify the seed's signature");
    }
}
