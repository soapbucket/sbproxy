// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Gossip message encryption using AES-256-GCM.
//!
//! All inter-node messages are encrypted with a shared cluster key
//! configured in sb.yml. Prevents eavesdropping on gossip traffic.
//!
//! # Implementation
//!
//! `GossipEncryption` is a thin facade over the workspace [`crate::crypto::Cipher`]
//! helper, which wraps the `aes-gcm` crate's `Aes256Gcm` AEAD primitive. The
//! shared secret is hashed to a 32-byte key with SHA-256 inside `Cipher`, and
//! every sealed message carries a fresh 12-byte random nonce plus a 16-byte
//! GCM authentication tag.
//!
//! The public API is intentionally unchanged from the prior placeholder
//! implementation so call sites in `gossip_loop` and the transport layer do
//! not need to be touched. The wire format is also identical:
//! `[12-byte nonce][ciphertext][16-byte tag]`. A receiver that fails to
//! authenticate the tag gets an error rather than corrupted plaintext.

use anyhow::Result;

use crate::crypto::Cipher;

/// Provides symmetric encryption for gossip messages.
///
/// Cheap to clone via the embedded `Cipher` (which holds an `Arc` to the
/// derived AES key), so the same instance can be shared across every gossip
/// task without duplicating key material.
#[derive(Clone)]
pub struct GossipEncryption {
    /// Concrete AEAD cipher. `None` when encryption is disabled, in which
    /// case the wire path is plaintext (legacy / unencrypted-cluster mode).
    cipher: Option<Cipher>,
}

impl GossipEncryption {
    /// Create from a shared secret string.
    ///
    /// The secret is hashed to a 32-byte AES-256-GCM key inside
    /// [`Cipher::from_shared_key`]. Any string is accepted; operators are
    /// expected to reject empty strings at the config layer (see
    /// [`crate::config::EncryptionConfig`]).
    pub fn new(shared_secret: &str) -> Self {
        Self {
            cipher: Some(Cipher::from_shared_key(shared_secret)),
        }
    }

    /// Create disabled encryption (messages pass through unmodified).
    ///
    /// Used by clusters that have not configured `encryption.shared_key` and
    /// by tests that want to assert the plaintext fallback path.
    pub fn disabled() -> Self {
        Self { cipher: None }
    }

    /// Returns `true` when encryption is active.
    pub fn is_enabled(&self) -> bool {
        self.cipher.is_some()
    }

    /// Encrypt a message. Returns `nonce (12 B) || ciphertext || tag (16 B)`.
    ///
    /// When encryption is disabled the plaintext is returned unchanged so
    /// the caller can hand the bytes straight to the wire path.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher {
            None => Ok(plaintext.to_vec()),
            Some(c) => Ok(c.seal(plaintext)),
        }
    }

    /// Decrypt a message. Input must be `nonce (12 B) || ciphertext || tag (16 B)`.
    ///
    /// Returns an error when the input is structurally invalid (shorter
    /// than `12 + 16` bytes) or the AEAD tag does not verify. When
    /// encryption is disabled the data is returned unchanged.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher {
            None => Ok(data.to_vec()),
            Some(c) => c
                .open(data)
                .ok_or_else(|| anyhow::anyhow!("gossip message authentication failed")),
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let enc = GossipEncryption::new("my-cluster-secret");
        let plaintext = b"hello mesh world";

        let ciphertext = enc.encrypt(plaintext).expect("encrypt");
        let recovered = enc.decrypt(&ciphertext).expect("decrypt");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aes_gcm_ciphertext_does_not_contain_plaintext() {
        // AES-GCM ciphertext should not literally contain the plaintext
        // anywhere in the output. The XOR placeholder failed this check
        // under structured input; this guards against regression.
        let enc = GossipEncryption::new("k");
        let plaintext = b"plaintext-search-marker-AAAAAAAAAA";
        let ciphertext = enc.encrypt(plaintext).expect("encrypt");
        assert!(
            !ciphertext.windows(plaintext.len()).any(|w| w == plaintext),
            "ciphertext leaked plaintext bytes"
        );
    }

    #[test]
    fn nonce_varies_per_message() {
        // The first 12 bytes of two seals of the same plaintext must
        // differ. A reused nonce under the same key is catastrophic for
        // AES-GCM; this guards against a broken RNG or hard-coded nonce.
        let enc = GossipEncryption::new("k");
        let a = enc.encrypt(b"x").expect("encrypt a");
        let b = enc.encrypt(b"x").expect("encrypt b");
        assert_ne!(&a[..12], &b[..12]);
    }

    #[test]
    fn disabled_passthrough() {
        let enc = GossipEncryption::disabled();
        assert!(!enc.is_enabled());

        let data = b"some gossip data";
        let encrypted = enc.encrypt(data).expect("encrypt");
        assert_eq!(encrypted, data);

        let decrypted = enc.decrypt(data).expect("decrypt");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn tampered_message_fails_mac_verification() {
        let enc = GossipEncryption::new("secret");
        let plaintext = b"sensitive state delta";
        let mut ciphertext = enc.encrypt(plaintext).expect("encrypt");

        // Flip a byte in the ciphertext body (between nonce and tag).
        ciphertext[15] ^= 0xFF;

        let result = enc.decrypt(&ciphertext);
        assert!(result.is_err(), "expected MAC failure, got {:?}", result);
    }

    #[test]
    fn tampered_tag_fails_verification() {
        let enc = GossipEncryption::new("secret");
        let mut ciphertext = enc.encrypt(b"payload").expect("encrypt");
        // Flip a bit in the very last byte (tag territory).
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        assert!(enc.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn empty_message_roundtrip() {
        let enc = GossipEncryption::new("secret-key");
        let ciphertext = enc.encrypt(&[]).expect("encrypt empty");
        let recovered = enc.decrypt(&ciphertext).expect("decrypt empty");
        assert!(recovered.is_empty());
    }

    #[test]
    fn message_too_short_returns_error() {
        let enc = GossipEncryption::new("secret");
        // 27 bytes is below the 28-byte minimum (12 nonce + 16 tag).
        let result = enc.decrypt(&[0u8; 27]);
        assert!(result.is_err());
    }

    #[test]
    fn different_key_cannot_decrypt() {
        let enc_a = GossipEncryption::new("key-a");
        let enc_b = GossipEncryption::new("key-b");

        let ciphertext = enc_a.encrypt(b"secret message").expect("encrypt");
        let result = enc_b.decrypt(&ciphertext);
        assert!(result.is_err(), "different key should fail MAC");
    }

    #[test]
    fn same_secret_interoperates_across_instances() {
        // Two independently-constructed instances with the same shared
        // key must be able to decrypt each other's output. This is what
        // makes encrypted gossip work across nodes.
        let a = GossipEncryption::new("shared-secret");
        let b = GossipEncryption::new("shared-secret");
        let sealed = a.encrypt(b"hello").expect("encrypt");
        let opened = b.decrypt(&sealed).expect("decrypt");
        assert_eq!(opened, b"hello");
    }
}
