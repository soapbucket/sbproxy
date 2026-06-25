//! AES-256-GCM authenticated-encryption helper used by the gossip loop and
//! the cross-node cache transport.
//!
//! # Rationale
//!
//! K2 and earlier wired the mesh protocols in plaintext. K3 makes the same
//! two wire formats (UDP heartbeats, TCP cache RPCs) optionally encrypted
//! under a single shared cluster key. When `MeshConfig.encryption.shared_key`
//! is absent, both paths stay plaintext - no behavior change.
//!
//! # Key derivation
//!
//! The shared secret is a user-supplied string (possibly read from an
//! environment variable or secrets manager in deployment). We hash it with
//! SHA-256 to obtain the 32-byte AES-256-GCM key. This keeps the operator
//! interface simple (any string works) while still feeding the cipher a
//! full-width key.
//!
//! # Wire format
//!
//! Every encrypted message is `[12-byte nonce][ciphertext || 16-byte tag]`.
//! The nonce is drawn from `rand::thread_rng()` per message; never reused.
//! On decrypt, malformed input or a MAC mismatch returns `None` so the
//! caller can silently drop the message (UDP) or tear down the connection
//! (TCP) without leaking whether the failure was structural or
//! cryptographic.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Length in bytes of the random nonce prepended to every ciphertext.
///
/// AES-256-GCM takes a 96-bit (12 byte) nonce. Chosen at random per message;
/// callers MUST NOT reuse a nonce under the same key.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication-tag length appended by AES-256-GCM.
pub const TAG_LEN: usize = 16;

// --- Cipher ---

/// AEAD helper that wraps a derived AES-256-GCM key.
///
/// Cheap to clone via `Arc` so the same cipher instance can be shared
/// across the gossip loop send/receive tasks and every outbound
/// `PeerClient` in the transport pool without duplicating the key
/// material.
#[derive(Clone)]
pub struct Cipher {
    /// Shared cipher handle. `Arc` because a single derived key is reused
    /// by all send/recv sites in the crate.
    inner: Arc<Aes256Gcm>,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque. Do not expose the derived key material
        // even in debug output.
        f.debug_struct("Cipher").finish_non_exhaustive()
    }
}

impl Cipher {
    /// Derive a cipher from a shared secret.
    ///
    /// Hashes the secret bytes with SHA-256 to produce the 32-byte
    /// AES-256-GCM key. Empty strings are tolerated (they derive a valid
    /// but deterministic key); callers are expected to reject empty
    /// secrets at the config layer.
    pub fn from_shared_key(shared_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(shared_key.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Self {
            inner: Arc::new(Aes256Gcm::new(key)),
        }
    }

    /// Encrypt `plaintext` and return `[nonce || ciphertext || tag]`.
    ///
    /// A fresh 12-byte random nonce is drawn per call; reusing a
    /// `Cipher` across many messages does not reuse nonces.
    ///
    /// AES-256-GCM's `encrypt` can only fail on invalid key/nonce sizes,
    /// which are compile-time constants here. `expect` is used so a
    /// regression in those constants surfaces immediately in tests.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .inner
            .encrypt(nonce, plaintext)
            .expect("aes-gcm encrypt cannot fail for valid key/nonce sizes");

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt `sealed = [nonce || ciphertext || tag]`.
    ///
    /// Returns `None` on:
    /// - malformed input (shorter than `NONCE_LEN + TAG_LEN`),
    /// - ciphertext that fails AEAD authentication.
    ///
    /// Callers treat `None` as "drop the message" (gossip) or "tear down
    /// the connection" (transport). No error type is surfaced because the
    /// distinction between "too short" and "tag mismatch" is not useful
    /// at the drop-site and conflating them avoids leaking any structural
    /// signal back to a probing peer.
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.inner.decrypt(nonce, ciphertext).ok()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_plaintext() {
        let c = Cipher::from_shared_key("cluster-secret");
        let plaintext = b"hello mesh world";
        let sealed = c.seal(plaintext);
        // Sealed length must be at least nonce + tag; for non-empty
        // plaintext it is strictly greater than either constant alone.
        assert!(sealed.len() >= NONCE_LEN + TAG_LEN + plaintext.len());
        let opened = c.open(&sealed).expect("open should succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let c = Cipher::from_shared_key("k");
        let sealed = c.seal(&[]);
        // `NONCE_LEN + TAG_LEN` is the minimum possible sealed size.
        assert_eq!(sealed.len(), NONCE_LEN + TAG_LEN);
        let opened = c.open(&sealed).expect("open empty");
        assert!(opened.is_empty());
    }

    #[test]
    fn tampered_ciphertext_returns_none() {
        let c = Cipher::from_shared_key("k");
        let mut sealed = c.seal(b"payload");
        // Flip a bit in the ciphertext body (past the nonce, before the
        // tag). Any modification must invalidate the tag.
        let idx = NONCE_LEN + 1;
        sealed[idx] ^= 0x80;
        assert!(c.open(&sealed).is_none());
    }

    #[test]
    fn tampered_tag_returns_none() {
        let c = Cipher::from_shared_key("k");
        let mut sealed = c.seal(b"payload");
        // Flip a bit in the last byte (tag territory).
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(c.open(&sealed).is_none());
    }

    #[test]
    fn malformed_input_shorter_than_nonce_tag_returns_none() {
        let c = Cipher::from_shared_key("k");
        // Any input below the `NONCE_LEN + TAG_LEN` floor is structurally
        // invalid and must not attempt AEAD decryption.
        assert!(c.open(&[]).is_none());
        assert!(c.open(&[0u8; NONCE_LEN]).is_none());
        assert!(c.open(&[0u8; NONCE_LEN + TAG_LEN - 1]).is_none());
    }

    #[test]
    fn different_keys_cannot_decrypt_each_others_output() {
        let a = Cipher::from_shared_key("key-a");
        let b = Cipher::from_shared_key("key-b");
        let sealed = a.seal(b"confidential");
        // `b` must not decrypt `a`'s output; the derived keys differ.
        assert!(b.open(&sealed).is_none());
        // Symmetric check.
        let sealed_b = b.seal(b"confidential");
        assert!(a.open(&sealed_b).is_none());
    }

    #[test]
    fn nonce_varies_across_seals_of_same_plaintext() {
        // Not a strict guarantee (two random 12-byte draws could collide),
        // but the collision probability is 2^-96 per pair. Asserting
        // inequality here guards against a broken RNG that returns zeros
        // or a hard-coded nonce.
        let c = Cipher::from_shared_key("k");
        let a = c.seal(b"x");
        let b = c.seal(b"x");
        assert_ne!(&a[..NONCE_LEN], &b[..NONCE_LEN]);
    }

    #[test]
    fn same_key_from_different_instances_interoperates() {
        // Building a `Cipher` from the same shared key on two sides of
        // the wire must produce the same derived key, so one side can
        // `open` what the other `seal`ed.
        let a = Cipher::from_shared_key("shared");
        let b = Cipher::from_shared_key("shared");
        let sealed = a.seal(b"msg");
        let opened = b.open(&sealed).expect("interoperate");
        assert_eq!(opened, b"msg");
    }
}
