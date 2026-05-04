//! Convergent encryption for detecting secret reuse across origins.
//!
//! Derives an encryption key from the plaintext via HMAC-SHA256, then uses
//! that key to produce a deterministic "fingerprint". Two identical secrets
//! within the same installation produce the same fingerprint, allowing
//! reuse detection without exposing the plaintext.
//!
//! Each [`ConvergentFingerprinter`] carries a per-installation derivation
//! key. Two different installations holding the same secret produce
//! different fingerprints, which prevents cross-installation rainbow-table
//! attacks against known-format secrets when fingerprints leak.

use std::sync::Arc;

use anyhow::{Context, Result};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use crate::manager::VaultBackend;

/// Length of the convergent derivation key in bytes (HMAC-SHA256 block size).
pub const DERIVATION_KEY_LEN: usize = 32;

/// HKDF info string used when deriving a convergent key from a vault root key.
pub const HKDF_INFO: &[u8] = b"sbproxy-convergent-v1";

/// Reserved vault path used to persist a randomly generated derivation key
/// on first run when neither operator config nor a vault root key is
/// available.
pub const RESERVED_VAULT_PATH: &str = "__sbproxy/convergent/derivation-key-v1";

/// Computes deterministic fingerprints of secret values using a
/// per-installation derivation key.
///
/// Use [`ConvergentFingerprinter::from_operator_key`] when an operator
/// supplies a derivation key in config, [`ConvergentFingerprinter::from_root_key`]
/// when an existing vault root key can seed HKDF, or
/// [`ConvergentFingerprinter::load_or_generate`] to read a persisted key
/// from a vault backend (generating and storing one on first run).
#[derive(Clone)]
pub struct ConvergentFingerprinter {
    key: Arc<[u8; DERIVATION_KEY_LEN]>,
}

impl ConvergentFingerprinter {
    /// Construct a fingerprinter from a 32-byte operator-provided key.
    pub fn from_operator_key(key: [u8; DERIVATION_KEY_LEN]) -> Self {
        Self { key: Arc::new(key) }
    }

    /// Derive a fingerprinter from a vault root key via HKDF-SHA256 with
    /// the [`HKDF_INFO`] context string.
    pub fn from_root_key(root_key: &[u8]) -> Self {
        let key = hkdf_sha256(root_key, &[], HKDF_INFO);
        Self { key: Arc::new(key) }
    }

    /// Load the per-installation key from `backend` at [`RESERVED_VAULT_PATH`].
    /// On first run (key absent) generate a fresh 32-byte random key via
    /// the OS CSPRNG and persist it before returning.
    pub fn load_or_generate(backend: &dyn VaultBackend) -> Result<Self> {
        if let Some(encoded) = backend
            .get(RESERVED_VAULT_PATH)
            .context("read convergent derivation key from vault")?
        {
            let bytes = hex::decode(encoded.trim())
                .context("convergent derivation key is not valid hex")?;
            let key: [u8; DERIVATION_KEY_LEN] = bytes
                .as_slice()
                .try_into()
                .ok()
                .context("convergent derivation key has wrong length")?;
            return Ok(Self::from_operator_key(key));
        }

        let mut key = [0u8; DERIVATION_KEY_LEN];
        SystemRandom::new()
            .fill(&mut key)
            .ok()
            .context("OS CSPRNG failed to produce convergent derivation key")?;
        backend
            .set(RESERVED_VAULT_PATH, &hex::encode(key))
            .context("persist convergent derivation key to vault")?;
        Ok(Self::from_operator_key(key))
    }

    /// Compute a deterministic fingerprint of `secret` using the
    /// installation key.
    pub fn fingerprint(&self, secret: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.key.as_ref());
        hmac::sign(&key, secret).as_ref().to_vec()
    }

    /// Hex-encoded fingerprint suitable for logging.
    pub fn fingerprint_hex(&self, secret: &[u8]) -> String {
        hex::encode(self.fingerprint(secret))
    }

    /// Constant-time equality check on the fingerprints of `a` and `b`.
    pub fn secrets_match(&self, a: &[u8], b: &[u8]) -> bool {
        let fa = self.fingerprint(a);
        let fb = self.fingerprint(b);
        if fa.len() != fb.len() {
            return false;
        }
        let mut acc = 0u8;
        for (x, y) in fa.iter().zip(fb.iter()) {
            acc |= x ^ y;
        }
        acc == 0
    }
}

// --- Internal HKDF-SHA256 (RFC 5869) ---

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; DERIVATION_KEY_LEN] {
    let salt_key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let prk = hmac::sign(&salt_key, ikm);

    let prk_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
    let mut t = Vec::with_capacity(info.len() + 1);
    t.extend_from_slice(info);
    t.push(0x01);
    let block = hmac::sign(&prk_key, &t);

    let mut out = [0u8; DERIVATION_KEY_LEN];
    out.copy_from_slice(&block.as_ref()[..DERIVATION_KEY_LEN]);
    out
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalVault;

    fn make_fingerprinter() -> ConvergentFingerprinter {
        ConvergentFingerprinter::from_operator_key([7u8; DERIVATION_KEY_LEN])
    }

    #[test]
    fn identical_secrets_produce_same_fingerprint_within_installation() {
        let fp = make_fingerprinter();
        assert_eq!(
            fp.fingerprint(b"my-api-key-12345"),
            fp.fingerprint(b"my-api-key-12345")
        );
    }

    #[test]
    fn different_secrets_produce_different_fingerprints() {
        let fp = make_fingerprinter();
        assert_ne!(fp.fingerprint(b"secret-a"), fp.fingerprint(b"secret-b"));
    }

    #[test]
    fn secrets_match_works() {
        let fp = make_fingerprinter();
        assert!(fp.secrets_match(b"same", b"same"));
        assert!(!fp.secrets_match(b"one", b"two"));
    }

    #[test]
    fn fingerprint_hex_is_deterministic_and_32_bytes() {
        let fp = make_fingerprinter();
        let h1 = fp.fingerprint_hex(b"test-secret");
        let h2 = fp.fingerprint_hex(b"test-secret");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn empty_secret_is_valid() {
        let fp = make_fingerprinter();
        let bytes = fp.fingerprint(b"");
        assert_eq!(bytes.len(), 32);
        assert_eq!(fp.fingerprint_hex(b"").len(), 64);
    }

    #[test]
    fn two_installations_with_same_secret_produce_different_fingerprints() {
        // Operator-supplied keys: simulate two distinct installations.
        let inst_a = ConvergentFingerprinter::from_operator_key([1u8; DERIVATION_KEY_LEN]);
        let inst_b = ConvergentFingerprinter::from_operator_key([2u8; DERIVATION_KEY_LEN]);
        let secret = b"shared-customer-api-key";
        assert_ne!(inst_a.fingerprint(secret), inst_b.fingerprint(secret));
        assert_ne!(
            inst_a.fingerprint_hex(secret),
            inst_b.fingerprint_hex(secret)
        );
    }

    #[test]
    fn from_root_key_is_deterministic_per_root() {
        let a1 = ConvergentFingerprinter::from_root_key(b"root-key-installation-1");
        let a2 = ConvergentFingerprinter::from_root_key(b"root-key-installation-1");
        let b = ConvergentFingerprinter::from_root_key(b"root-key-installation-2");
        let secret = b"shared-secret";
        assert_eq!(a1.fingerprint(secret), a2.fingerprint(secret));
        assert_ne!(a1.fingerprint(secret), b.fingerprint(secret));
    }

    #[test]
    fn load_or_generate_persists_key_across_calls() {
        let vault = LocalVault::new();
        let fp1 = ConvergentFingerprinter::load_or_generate(&vault).unwrap();
        let fp2 = ConvergentFingerprinter::load_or_generate(&vault).unwrap();
        let secret = b"reused-secret";
        assert_eq!(fp1.fingerprint(secret), fp2.fingerprint(secret));
    }

    #[test]
    fn load_or_generate_uses_distinct_keys_per_vault() {
        let vault_a = LocalVault::new();
        let vault_b = LocalVault::new();
        let fp_a = ConvergentFingerprinter::load_or_generate(&vault_a).unwrap();
        let fp_b = ConvergentFingerprinter::load_or_generate(&vault_b).unwrap();
        let secret = b"reused-secret";
        assert_ne!(fp_a.fingerprint(secret), fp_b.fingerprint(secret));
    }

    #[test]
    fn load_or_generate_reads_existing_persisted_key() {
        let vault = LocalVault::new();
        let known_key = [9u8; DERIVATION_KEY_LEN];
        vault
            .set(RESERVED_VAULT_PATH, &hex::encode(known_key))
            .unwrap();
        let fp = ConvergentFingerprinter::load_or_generate(&vault).unwrap();
        let direct = ConvergentFingerprinter::from_operator_key(known_key);
        assert_eq!(
            fp.fingerprint(b"compare-me"),
            direct.fingerprint(b"compare-me")
        );
    }
}
