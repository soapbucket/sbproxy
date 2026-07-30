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
//! # Key derivation, and why there are two of them
//!
//! The shared secret is a user-supplied string (possibly read from an
//! environment variable or secrets manager in deployment). Historically it
//! was hashed with plain SHA-256 to obtain the 32-byte AES-256-GCM key,
//! which is the one derivation in this workspace that sits outside the
//! shared [`sbproxy_security::crypto`] model: everywhere else, a key comes
//! from `hkdf_derive_purpose` with a purpose-separated, versioned `info`
//! string, so no two uses of one operator secret can derive the same key.
//!
//! Changing the derivation changes the key, and a cluster whose nodes
//! disagree about the key cannot talk: gossip is UDP and drops silently,
//! and the transport tears the connection down. A flag day is therefore
//! not available, so the migration is staged and the reader side ships
//! first.
//!
//! [`Cipher`] accepts **both** derivations on `open` and seals under
//! whichever [`KeyDerivation`] it was built with. The default is still
//! [`KeyDerivation::Sha256`], so behaviour is unchanged until an operator
//! opts in. The rollout is:
//!
//! 1. Upgrade every node. Each one now opens either derivation and still
//!    seals SHA-256, so a half-upgraded cluster keeps working.
//! 2. Set `key_derivation: hkdf` node by node. Peers that have not been
//!    flipped yet still open what a flipped node seals.
//! 3. A later major release drops SHA-256 sealing, and then opening.
//!
//! Accepting two keys on open costs one extra trial decryption on a
//! message this node cannot open, which happens only during a migration
//! or under an attacker sending garbage. It does not weaken anything:
//! both candidates derive from the same operator secret, so accepting
//! both grants no capability that holding the secret did not already.
//!
//! # What this migration is and is not worth
//!
//! Worth being precise, because the honest answer is narrower than it
//! sounds. There was never a key collision to fix: a bare SHA-256 does
//! not collide with any HKDF-derived key, so an operator reusing one
//! secret across the mesh and the response cache already got two
//! unrelated keys, by accident rather than by design. Nor is this a
//! password-hardening change. HKDF-Extract is one HMAC round, so it
//! costs an attacker no more than a bare SHA-256 and does nothing for a
//! weak passphrase. The fix for that is 32 random bytes, which the docs
//! say.
//!
//! What is actually being bought is the invariant. "Every key in this
//! workspace comes from one audited derivation with a distinct purpose"
//! is only worth something without exceptions; one exception means every
//! future reviewer has to work out which side of the line a given key
//! falls on, and the next feature that copies the nearest example may
//! copy the wrong one.
//!
//! Two alternatives were rejected. Leaving it and documenting it, which
//! the ticket offered, would mean the eventual migration starts from
//! zero and needs its own full upgrade cycle before anything can move;
//! the reader-side change is small and safe on its own, so it ships now.
//! Negotiating the derivation in the gossip heartbeat is more faithful to
//! "version negotiation" and worse: it puts a new field in the frame that
//! old nodes must tolerate, which is the same rolling-upgrade problem one
//! layer down. The operator already knows which nodes they upgraded, so
//! config is the honest place to say it.
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
use sbproxy_security::crypto::{hkdf_derive_purpose, HkdfPurpose};
use sha2::{Digest, Sha256};

/// Length in bytes of the random nonce prepended to every ciphertext.
///
/// AES-256-GCM takes a 96-bit (12 byte) nonce. Chosen at random per message;
/// callers MUST NOT reuse a nonce under the same key.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication-tag length appended by AES-256-GCM.
pub const TAG_LEN: usize = 16;

// --- Cipher ---

/// How a shared secret becomes the 32-byte AES-256-GCM key.
///
/// See the module docs for why both exist and how to move between them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDerivation {
    /// `SHA-256(secret)`. The original scheme and still the default, so
    /// an upgrade never changes the key a node seals under.
    #[default]
    Sha256,
    /// `hkdf_derive_purpose(secret, "", MeshWire, 32)`, which puts the
    /// mesh wire key in the same purpose-separated keyspace as every
    /// other key this workspace derives.
    Hkdf,
}

impl KeyDerivation {
    /// Derive the AES-256-GCM key for `secret` under this scheme.
    fn derive(self, secret: &str) -> [u8; 32] {
        match self {
            KeyDerivation::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(secret.as_bytes());
                hasher.finalize().into()
            }
            KeyDerivation::Hkdf => {
                let derived =
                    hkdf_derive_purpose(secret.as_bytes(), b"", HkdfPurpose::MeshWire, 32);
                let mut key = [0u8; 32];
                key.copy_from_slice(&derived);
                key
            }
        }
    }

    /// Short name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyDerivation::Sha256 => "sha256",
            KeyDerivation::Hkdf => "hkdf",
        }
    }
}

/// AEAD helper that wraps a derived AES-256-GCM key.
///
/// Cheap to clone via `Arc` so the same cipher instance can be shared
/// across the gossip loop send/receive tasks and every outbound
/// `PeerClient` in the transport pool without duplicating the key
/// material.
#[derive(Clone)]
pub struct Cipher {
    /// Cipher that seals. `Arc` because a single derived key is reused by
    /// all send/recv sites in the crate.
    inner: Arc<Aes256Gcm>,
    /// Every cipher this node will open under, sealing one first. Holds
    /// both derivations of the same operator secret during a migration.
    openers: Arc<Vec<Aes256Gcm>>,
    /// Which derivation [`Self::inner`] came from, for logs.
    derivation: KeyDerivation,
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
        Self::with_derivation(shared_key, KeyDerivation::default())
    }

    /// Derive a cipher that seals under `derivation` and opens under every
    /// derivation this build knows.
    ///
    /// Empty strings are tolerated (they derive a valid but deterministic
    /// key); callers are expected to reject empty secrets at the config
    /// layer.
    pub fn with_derivation(shared_key: &str, derivation: KeyDerivation) -> Self {
        let sealing = derivation.derive(shared_key);
        // Sealing derivation first so the common case, a cluster where
        // every node agrees, opens on the first attempt.
        let mut openers = vec![Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sealing))];
        for candidate in [KeyDerivation::Sha256, KeyDerivation::Hkdf] {
            if candidate == derivation {
                continue;
            }
            let bytes = candidate.derive(shared_key);
            openers.push(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&bytes)));
        }
        Self {
            inner: Arc::new(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sealing))),
            openers: Arc::new(openers),
            derivation,
        }
    }

    /// Which derivation this cipher seals under.
    pub fn derivation(&self) -> KeyDerivation {
        self.derivation
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
        // Try the sealing derivation first, then the other. A peer
        // mid-migration seals under a key this node does not seal under
        // but does hold, which is what keeps a rolling flip from
        // partitioning the cluster.
        self.openers
            .iter()
            .find_map(|cipher| cipher.decrypt(nonce, ciphertext).ok())
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

    // --- Key-derivation migration ---

    #[test]
    fn the_default_derivation_is_unchanged_sha256() {
        // An upgrade must not change the key an existing cluster seals
        // under, or every node stops talking to every other node.
        let mut hasher = Sha256::new();
        hasher.update(b"cluster-secret");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(KeyDerivation::default(), KeyDerivation::Sha256);
        assert_eq!(KeyDerivation::Sha256.derive("cluster-secret"), expected);
        assert_eq!(
            Cipher::from_shared_key("cluster-secret").derivation(),
            KeyDerivation::Sha256
        );
    }

    #[test]
    fn the_two_derivations_produce_different_keys() {
        // Otherwise there would be nothing to migrate and no risk to
        // stage, so this is the assumption the whole rollout rests on.
        assert_ne!(
            KeyDerivation::Sha256.derive("cluster-secret"),
            KeyDerivation::Hkdf.derive("cluster-secret")
        );
    }

    #[test]
    fn a_node_still_on_sha256_opens_what_an_hkdf_node_sealed() {
        // Step 2 of the rollout: one node has been flipped, the rest have
        // not. The un-flipped nodes must keep reading its traffic.
        let flipped = Cipher::with_derivation("cluster-secret", KeyDerivation::Hkdf);
        let not_yet = Cipher::with_derivation("cluster-secret", KeyDerivation::Sha256);
        let sealed = flipped.seal(b"heartbeat");
        assert_eq!(
            not_yet.open(&sealed).expect("must open across derivations"),
            b"heartbeat"
        );
    }

    #[test]
    fn an_hkdf_node_opens_what_a_sha256_node_sealed() {
        // The other direction of the same window.
        let flipped = Cipher::with_derivation("cluster-secret", KeyDerivation::Hkdf);
        let not_yet = Cipher::with_derivation("cluster-secret", KeyDerivation::Sha256);
        let sealed = not_yet.seal(b"heartbeat");
        assert_eq!(
            flipped.open(&sealed).expect("must open across derivations"),
            b"heartbeat"
        );
    }

    #[test]
    fn accepting_both_derivations_does_not_accept_a_different_secret() {
        // Opening under two keys must widen what one secret can read, not
        // which secrets are accepted.
        let ours = Cipher::with_derivation("cluster-secret", KeyDerivation::Hkdf);
        for derivation in [KeyDerivation::Sha256, KeyDerivation::Hkdf] {
            let theirs = Cipher::with_derivation("a-completely-different-secret", derivation);
            assert!(ours.open(&theirs.seal(b"payload")).is_none());
        }
    }

    #[test]
    fn a_cipher_seals_under_the_derivation_it_was_built_with() {
        let hkdf = Cipher::with_derivation("cluster-secret", KeyDerivation::Hkdf);
        assert_eq!(hkdf.derivation(), KeyDerivation::Hkdf);
        // A cipher that only knows SHA-256 must not be able to open it,
        // which is what proves the seal really moved.
        let key = KeyDerivation::Sha256.derive("cluster-secret");
        let sha_only = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let sealed = hkdf.seal(b"payload");
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        assert!(sha_only
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .is_err());
    }
}
