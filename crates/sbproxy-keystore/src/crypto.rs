//! At-rest cryptographic material for the key store.
//!
//! Two distinct schemes live here, matching the two record kinds:
//!
//! * Inbound virtual keys are **hashed**. We never store a recoverable secret.
//!   The at-rest verifier is `HMAC-SHA256(secret, pepper)` (better than a bare
//!   `SHA-256` of the key because the server pepper means a stolen store is not
//!   offline-bruteable without it). Verification is constant-time.
//! * Upstream provider credentials are **encrypted** (AEAD envelope). The
//!   [`Envelope`] shape and the [`seal_envelope`] / [`open_envelope`] composition
//!   live here; the underlying AES-256-GCM primitive lives in `sbproxy-security`
//!   so the cipher has a single audited home.

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sbproxy_security::{
    aes256gcm_decrypt, aes256gcm_encrypt, hkdf_derive_purpose, random_aes256_key,
    random_aes_gcm_nonce, HkdfPurpose, AES256_KEY_LEN, AES_GCM_NONCE_LEN,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length in bytes of a freshly minted virtual-key secret.
const SECRET_BYTES: usize = 32;
/// Length in bytes of a minted public key id.
const KEY_ID_BYTES: usize = 8;

/// A minted virtual key: the public id, the one-time plaintext token shown to
/// the operator exactly once, and the at-rest hash that is persisted.
#[derive(Debug, Clone)]
pub struct MintedKey {
    /// Stable public identifier, the prefix of the token.
    pub key_id: String,
    /// The full bearer token `sk-<key_id>-<secret>`. Shown once, never stored.
    pub token: String,
    /// `HMAC-SHA256(secret, pepper)`, hex-encoded. This is what is persisted.
    pub secret_hash: String,
}

/// Mint a brand-new virtual key, returning the public id, the one-time token,
/// and the at-rest hash. `pepper` is the server-wide secret pepper.
pub fn mint_key(pepper: &[u8]) -> MintedKey {
    let key_id = random_hex(KEY_ID_BYTES);
    let secret = random_hex(SECRET_BYTES);
    let secret_hash = hash_secret(&secret, pepper);
    let token = format!("sk-{key_id}-{secret}");
    MintedKey {
        key_id,
        token,
        secret_hash,
    }
}

/// Parse a bearer token of the form `sk-<key_id>-<secret>` into its public id
/// and secret halves. Returns `None` for any other shape.
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix("sk-")?;
    let (key_id, secret) = rest.split_once('-')?;
    if key_id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((key_id, secret))
}

/// Compute the at-rest hash for a secret: `HMAC-SHA256(secret, pepper)`,
/// hex-encoded. The pepper is the key; the secret is the message, which keeps a
/// stolen store useless to an attacker who lacks the pepper.
pub fn hash_secret(secret: &str, pepper: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC-SHA256 accepts any key length");
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time verification of a presented secret against a stored hex hash.
///
/// Recomputes `HMAC-SHA256(secret, pepper)` and compares it to `expected_hex`
/// using the MAC's own constant-time verifier, so a timing side channel cannot
/// leak how many leading bytes matched.
pub fn verify_secret(secret: &str, pepper: &[u8], expected_hex: &str) -> bool {
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC-SHA256 accepts any key length");
    mac.update(secret.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Generate `n` random bytes hex-encoded (so the output is `2 * n` chars).
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// An AEAD envelope: a per-record data key (DEK) is generated, used to encrypt
/// the plaintext with AES-256-GCM, then itself wrapped under a master key. Only
/// the wrapped DEK, nonce, and ciphertext are persisted; the plaintext data key
/// never touches disk.
///
/// Sealed and opened by [`seal_envelope`] / [`open_envelope`]; this struct is
/// the serialized shape the key store persists and round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// AEAD scheme tag for forward migration (currently `aes-256-gcm.v1`).
    pub alg: String,
    /// The data key wrapped (encrypted) under the master key, with its own
    /// nonce prefixed by the wrapping helper.
    #[serde(with = "hex_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// The 96-bit nonce used to encrypt the payload under the data key.
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    /// The AES-256-GCM ciphertext of the payload (includes the auth tag).
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

/// The canonical AEAD scheme tag stamped onto freshly sealed envelopes.
pub const ENVELOPE_ALG_V1: &str = "aes-256-gcm.v1";

/// serde helper that (de)serializes a `Vec<u8>` as a lowercase hex string,
/// keeping persisted records human-diffable.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Seal `plaintext` into an [`Envelope`] under the operator `master` key, bound
/// to `record_id`.
///
/// Envelope encryption: a fresh per-record data key (DEK) encrypts the payload;
/// the DEK is then wrapped under a key derived from the master via
/// HKDF([`HkdfPurpose::KeyEnvelope`]). Only the wrapped DEK reaches disk, so the
/// master can be rotated (or moved to a KMS) without re-encrypting payloads, and
/// the `record_id` AAD pins each ciphertext to its record.
pub fn seal_envelope(master: &[u8], record_id: &str, plaintext: &[u8]) -> Result<Envelope> {
    let aad = record_id.as_bytes();
    let dek = random_aes256_key();
    let nonce = random_aes_gcm_nonce();
    let ciphertext = aes256gcm_encrypt(&dek, &nonce, plaintext, aad)?;

    let wrap_key = derive_wrap_key(master);
    let wrap_nonce = random_aes_gcm_nonce();
    let wrapped = aes256gcm_encrypt(&wrap_key, &wrap_nonce, &dek, aad)?;
    // wrapped_dek = wrap_nonce || wrapped-DEK-ciphertext.
    let mut wrapped_dek = Vec::with_capacity(AES_GCM_NONCE_LEN + wrapped.len());
    wrapped_dek.extend_from_slice(&wrap_nonce);
    wrapped_dek.extend_from_slice(&wrapped);

    Ok(Envelope {
        alg: ENVELOPE_ALG_V1.to_string(),
        wrapped_dek,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Open an [`Envelope`] sealed by [`seal_envelope`], recovering the plaintext.
pub fn open_envelope(master: &[u8], record_id: &str, env: &Envelope) -> Result<Vec<u8>> {
    if env.alg != ENVELOPE_ALG_V1 {
        return Err(anyhow!("unsupported envelope alg '{}'", env.alg));
    }
    let aad = record_id.as_bytes();
    if env.wrapped_dek.len() <= AES_GCM_NONCE_LEN {
        return Err(anyhow!("wrapped DEK is too short to carry a nonce"));
    }
    let (wrap_nonce, wrapped) = env.wrapped_dek.split_at(AES_GCM_NONCE_LEN);
    let wrap_nonce: [u8; AES_GCM_NONCE_LEN] = wrap_nonce.try_into().expect("split at nonce length");

    let wrap_key = derive_wrap_key(master);
    let dek_bytes = aes256gcm_decrypt(&wrap_key, &wrap_nonce, wrapped, aad)?;
    let dek: [u8; AES256_KEY_LEN] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("unwrapped DEK is not {AES256_KEY_LEN} bytes"))?;

    let nonce: [u8; AES_GCM_NONCE_LEN] = env
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("envelope nonce is not {AES_GCM_NONCE_LEN} bytes"))?;
    aes256gcm_decrypt(&dek, &nonce, &env.ciphertext, aad)
}

/// Derive the 32-byte DEK-wrapping key from the master key.
fn derive_wrap_key(master: &[u8]) -> [u8; AES256_KEY_LEN] {
    let bytes = hkdf_derive_purpose(master, b"", HkdfPurpose::KeyEnvelope, AES256_KEY_LEN);
    bytes
        .as_slice()
        .try_into()
        .expect("hkdf returns the requested length")
}

/// A consolidated crypto handle holding the two server secrets the key plane
/// needs: the `pepper` (inbound-key hashing) and the `master` (upstream-credential
/// envelope). One handle is shared by the auth, admin, and dispatch layers so
/// the secrets live in a single place.
#[derive(Clone)]
pub struct KeyCrypto {
    pepper: Vec<u8>,
    master: Vec<u8>,
}

impl KeyCrypto {
    /// Build a handle from the server pepper and master key.
    pub fn new(pepper: impl Into<Vec<u8>>, master: impl Into<Vec<u8>>) -> Self {
        Self {
            pepper: pepper.into(),
            master: master.into(),
        }
    }

    /// Mint a brand-new inbound key (id, one-time token, at-rest hash).
    pub fn mint_key(&self) -> MintedKey {
        mint_key(&self.pepper)
    }

    /// Hash a secret for at-rest storage.
    pub fn hash_secret(&self, secret: &str) -> String {
        hash_secret(secret, &self.pepper)
    }

    /// Constant-time verify a presented secret against a stored hash.
    pub fn verify_secret(&self, secret: &str, expected_hex: &str) -> bool {
        verify_secret(secret, &self.pepper, expected_hex)
    }

    /// Seal an upstream secret into an envelope bound to `record_id`.
    pub fn seal(&self, record_id: &str, plaintext: &[u8]) -> Result<Envelope> {
        seal_envelope(&self.master, record_id, plaintext)
    }

    /// Open an envelope sealed by [`Self::seal`].
    pub fn open(&self, record_id: &str, env: &Envelope) -> Result<Vec<u8>> {
        open_envelope(&self.master, record_id, env).context("open credential envelope")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_verify_roundtrips() {
        let pepper = b"server-pepper";
        let minted = mint_key(pepper);
        let (key_id, secret) = parse_token(&minted.token).expect("token parses");
        assert_eq!(key_id, minted.key_id);
        assert!(verify_secret(secret, pepper, &minted.secret_hash));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let pepper = b"server-pepper";
        let minted = mint_key(pepper);
        assert!(!verify_secret(
            "not-the-secret",
            pepper,
            &minted.secret_hash
        ));
    }

    #[test]
    fn verify_rejects_wrong_pepper() {
        let minted = mint_key(b"pepper-a");
        let (_, secret) = parse_token(&minted.token).unwrap();
        assert!(!verify_secret(secret, b"pepper-b", &minted.secret_hash));
    }

    #[test]
    fn parse_token_rejects_malformed() {
        assert!(parse_token("nope").is_none());
        assert!(parse_token("sk-only").is_none());
        assert!(parse_token("sk--secret").is_none());
        assert!(parse_token("sk-id-").is_none());
        assert!(parse_token("sk-id-secret").is_some());
    }

    #[test]
    fn hashes_are_unique_per_mint() {
        let pepper = b"p";
        let a = mint_key(pepper);
        let b = mint_key(pepper);
        assert_ne!(a.key_id, b.key_id);
        assert_ne!(a.secret_hash, b.secret_hash);
    }

    #[test]
    fn envelope_serde_roundtrips_as_hex() {
        let env = Envelope {
            alg: ENVELOPE_ALG_V1.to_string(),
            wrapped_dek: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            ciphertext: vec![7, 8, 9, 10],
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"010203\""), "wrapped_dek hex: {json}");
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_seal_open_roundtrips() {
        let master = b"operator-master-key";
        let env = seal_envelope(master, "cred-1", b"sk-upstream-secret").unwrap();
        // The plaintext is not recoverable from the persisted bytes.
        assert!(!env.ciphertext.windows(2).any(|w| w == b"sk"));
        let opened = open_envelope(master, "cred-1", &env).unwrap();
        assert_eq!(opened, b"sk-upstream-secret");
    }

    #[test]
    fn envelope_rejects_wrong_master_and_wrong_record() {
        let env = seal_envelope(b"master-a", "cred-1", b"secret").unwrap();
        assert!(open_envelope(b"master-b", "cred-1", &env).is_err());
        // AAD binding: an envelope sealed for cred-1 cannot open as cred-2.
        assert!(open_envelope(b"master-a", "cred-2", &env).is_err());
    }

    #[test]
    fn two_seals_differ_but_both_open() {
        let master = b"m";
        let a = seal_envelope(master, "c", b"same").unwrap();
        let b = seal_envelope(master, "c", b"same").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext, "fresh DEK + nonce per seal");
        assert_eq!(open_envelope(master, "c", &a).unwrap(), b"same");
        assert_eq!(open_envelope(master, "c", &b).unwrap(), b"same");
    }

    #[test]
    fn key_crypto_handle_combines_hash_and_envelope() {
        let kc = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let minted = kc.mint_key();
        let (_, secret) = parse_token(&minted.token).unwrap();
        assert!(kc.verify_secret(secret, &minted.secret_hash));
        assert!(!kc.verify_secret("wrong", &minted.secret_hash));

        let env = kc.seal("cred-1", b"api-key").unwrap();
        assert_eq!(kc.open("cred-1", &env).unwrap(), b"api-key");
    }
}
