//! WOR-892 PR1: sealed-cookie AEAD for the OIDC session + transaction
//! cookies.
//!
//! AES-256-GCM with a fresh 12-byte random nonce per seal. The wire
//! format is:
//!
//! ```text
//! base64url-no-pad( nonce || ciphertext || tag )
//! ```
//!
//! Key separation is enforced by [`HkdfPurpose`]: the OIDC session
//! cookie and the OIDC transaction cookie derive distinct keys from
//! the same operator-supplied secret via `HkdfPurpose::OidcSessionCookie`
//! and `HkdfPurpose::OidcTxCookie`. Two cookies never share a key, so a
//! ciphertext captured from one can never be decrypted as the other.
//!
//! NIST SP 800-38D requires the 96-bit GCM nonce to never repeat under
//! the same key. A 12-byte CSPRNG draw via the `aes_gcm` AEAD's
//! `OsRng` makes the collision probability negligible (~2^-32 after
//! 2^32 seals under one key); rotate the operator secret if you
//! expect that many seals.

use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::Engine as _;

use crate::crypto::{hkdf_derive_purpose, HkdfPurpose};

/// AES-256 key length in bytes. Pinned by the cipher choice; the HKDF
/// derivation requests exactly this many bytes.
const KEY_LEN: usize = 32;

/// GCM nonce length in bytes (NIST SP 800-38D §5.2.1.1).
const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` under a per-purpose key derived from `ikm`.
///
/// The returned base64url-no-pad string is safe to embed inside a
/// `Set-Cookie` value. Two seals of the same plaintext produce
/// distinct outputs because each seal draws a fresh 12-byte nonce.
pub fn seal(plaintext: &[u8], ikm: &[u8], purpose: HkdfPurpose) -> Result<String> {
    let key_bytes = hkdf_derive_purpose(ikm, b"", purpose, KEY_LEN);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("aes-gcm encrypt failed: {e}"))?;

    let mut wire = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire))
}

/// Decrypt a value produced by [`seal`]. Returns the original
/// plaintext or an error when the cookie is base64-malformed, too
/// short to carry a nonce, or the GCM tag does not authenticate.
///
/// The error variant is intentionally generic: callers MUST NOT
/// distinguish between "tampered" and "wrong key" to a remote
/// observer, since both indicate the same operational outcome (the
/// client gets a fresh challenge cookie).
pub fn open(b64: &str, ikm: &[u8], purpose: HkdfPurpose) -> Result<Vec<u8>> {
    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .context("cookie value is not base64url-no-pad")?;
    if wire.len() < NONCE_LEN {
        return Err(anyhow!(
            "cookie payload {} bytes is shorter than a 12-byte GCM nonce",
            wire.len()
        ));
    }
    let (nonce_bytes, ciphertext) = wire.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key_bytes = hkdf_derive_purpose(ikm, b"", purpose, KEY_LEN);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("aes-gcm decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IKM: &[u8] = b"operator-supplied-secret-of-arbitrary-length";

    #[test]
    fn seal_then_open_round_trips() {
        let plaintext = b"sub=alice|exp=1735689600";
        let sealed = seal(plaintext, IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        let opened = open(&sealed, IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn two_seals_of_same_plaintext_produce_distinct_ciphertext() {
        // Per NIST SP 800-38D the GCM nonce must never repeat under
        // the same key; a fresh CSPRNG nonce per seal makes two seals
        // of the same plaintext observably distinct on the wire.
        let plaintext = b"identical-payload";
        let a = seal(plaintext, IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        let b = seal(plaintext, IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        assert_ne!(a, b);
        // But both decrypt to the same plaintext.
        assert_eq!(
            open(&a, IKM, HkdfPurpose::OidcSessionCookie).unwrap(),
            open(&b, IKM, HkdfPurpose::OidcSessionCookie).unwrap()
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let sealed = seal(b"payload", IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        // Flip the last byte of the base64-decoded payload. The GCM
        // tag check MUST reject.
        let mut wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed.as_bytes())
            .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wire);
        assert!(open(&tampered, IKM, HkdfPurpose::OidcSessionCookie).is_err());
    }

    #[test]
    fn open_rejects_wrong_purpose_keyspace() {
        // A cookie sealed under OidcSessionCookie MUST NOT decrypt
        // under OidcTxCookie even when the ikm is identical. HKDF
        // purpose separation is the only thing standing between
        // session-cookie replay and tx-cookie forgery.
        let sealed = seal(b"payload", IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        assert!(open(&sealed, IKM, HkdfPurpose::OidcTxCookie).is_err());
    }

    #[test]
    fn open_rejects_wrong_ikm() {
        let sealed = seal(b"payload", IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        assert!(open(&sealed, b"different-secret", HkdfPurpose::OidcSessionCookie).is_err());
    }

    #[test]
    fn open_rejects_payload_shorter_than_nonce() {
        // 8 bytes < 12-byte nonce length. The error must be the size
        // check, not the AEAD verify (which would panic on an out-of-
        // range slice).
        let too_short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 8]);
        let err = open(&too_short, IKM, HkdfPurpose::OidcSessionCookie).unwrap_err();
        assert!(format!("{err}").contains("shorter than a 12-byte GCM nonce"));
    }

    #[test]
    fn open_rejects_non_base64_input() {
        let err = open("not!base64?@", IKM, HkdfPurpose::OidcSessionCookie).unwrap_err();
        assert!(format!("{err:#}").contains("base64url-no-pad"));
    }

    #[test]
    fn sealed_payload_is_url_safe_base64() {
        // The output MUST be embeddable in a Set-Cookie value without
        // percent-encoding. URL_SAFE_NO_PAD uses [A-Za-z0-9-_] only.
        let sealed = seal(b"x", IKM, HkdfPurpose::OidcSessionCookie).unwrap();
        for c in sealed.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-url-safe char {c:?} in sealed payload {sealed}"
            );
        }
    }
}
