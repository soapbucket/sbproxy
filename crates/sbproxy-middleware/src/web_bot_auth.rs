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
#[derive(Clone, Copy)]
pub struct DirectoryIdentity<'a> {
    /// Advertised key id (the JWK `kid` and the RFC 9421 `keyid`).
    pub key_id: &'a str,
    /// The 32-byte Ed25519 private seed. Only the derived public key
    /// is published.
    pub seed: &'a [u8; 32],
}

/// Redacted `Debug` (WOR-2606). `seed` is a 32-byte Ed25519 *private*
/// seed, borrowed rather than owned, which is what made it easy to miss
/// behind a derive on a `Copy` type. Anything that reads it signs
/// directory and agent card responses every Web Bot Auth verifier will
/// accept as this operator's, which is the whole trust loop this module
/// exists to close.
///
/// The key id stays: it is published on purpose and it is what names
/// which identity a failed signature belongs to. The runtime twin of
/// `sbproxy_config::WebBotAuthPublishConfig.signing_key_hex`.
impl std::fmt::Debug for DirectoryIdentity<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryIdentity")
            .field("key_id", &self.key_id)
            .field("seed", &"[REDACTED; 32 bytes]")
            .finish()
    }
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

    /// The published identity's private seed, pinned (WOR-2606).
    ///
    /// A borrowed `&[u8; 32]` behind a derive on a `Copy` type is easy
    /// to miss, and the value is the Ed25519 private half of the key the
    /// directory publishes.
    #[test]
    fn debug_never_renders_the_directory_signing_seed() {
        let seed = [7u8; 32];
        let identity = DirectoryIdentity {
            key_id: "kid-1",
            seed: &seed,
        };
        let rendered = format!("{identity:?}");
        assert!(
            !rendered.contains("07070707") && !rendered.contains("[7, 7,"),
            "the Ed25519 private seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("kid-1"),
            "the key id must survive: it is published on purpose and names which \
             identity a failed signature belongs to: {rendered}"
        );
        assert!(
            rendered.contains("32 bytes"),
            "the length must survive: a seed of the wrong length is the usual \
             misconfiguration and the length discloses nothing: {rendered}"
        );
    }
}
