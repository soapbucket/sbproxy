//! Ed25519 key manager for CoMP marketplace quote signatures.
//!
//! The enterprise source this crate was ported from shared one
//! `KeyManager` across three token surfaces (OLP, CAP, and CoMP) with
//! per-protocol kid namespacing so a token minted for one could never
//! be replayed as another. Two of those three surfaces already ship
//! OSS-side with their own, more capable implementations: the OLP
//! issuer and verifier live in `crates/sbproxy-modules/src/olp.rs`
//! (mint, verify, JWK publication, RFC 7662 introspection, RFC 7009
//! revocation), and the CAP verifier lives in
//! `crates/sbproxy-modules/src/auth/cap.rs`. Porting a second,
//! disconnected copy of either would have shipped a namespace this
//! crate never uses, so the namespace concept is dropped: this
//! `KeyManager` signs exactly one thing, a CoMP quote, under the
//! `comp-<rotation_id>` kid.
//!
//! Key derivation still mirrors the audit crate's HKDF approach so an
//! operator rotates one master key and the CoMP signing key inherits
//! the new derivation without a second key-management story.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use crate::error::LicensingError;

/// Kid prefix every key this manager derives carries.
const KID_PREFIX: &str = "comp";

/// HKDF salt for this crate's signing purpose.
const HKDF_SALT: &[u8] = b"sbproxy-licensing-comp-quote-v1";

// --- Master key ---

/// Long-lived master key supplied by the operator (file / env / KMS).
///
/// Wrapped to prevent accidental `Display` printing in tracing
/// statements. The constructor enforces a 32-byte minimum so HKDF has
/// enough entropy to expand from.
#[derive(Clone)]
pub struct MasterKey {
    bytes: Vec<u8>,
}

impl MasterKey {
    /// Build a master key from raw bytes.
    pub fn new<B: Into<Vec<u8>>>(bytes: B) -> Result<Self, LicensingError> {
        let bytes = bytes.into();
        if bytes.len() < 32 {
            return Err(LicensingError::Encode(
                "master key too short: at least 32 bytes required".into(),
            ));
        }
        Ok(Self { bytes })
    }

    /// Build a master key from a hex string (e.g. read from an
    /// operator-supplied file). 64+ hex chars required.
    pub fn from_hex(hex_str: &str) -> Result<Self, LicensingError> {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| LicensingError::Encode(format!("master hex decode: {e}")))?;
        Self::new(bytes)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

fn derive_key(
    master: &MasterKey,
    rotation_id: &str,
) -> Result<(String, SigningKey), LicensingError> {
    let kid = format!("{KID_PREFIX}-{rotation_id}");

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &master.bytes);
    let mut seed = [0u8; 32];
    hk.expand(rotation_id.as_bytes(), &mut seed)
        .map_err(|e| LicensingError::Encode(format!("hkdf expand: {e}")))?;

    let signing_key = SigningKey::from_bytes(&seed);
    Ok((kid, signing_key))
}

// --- Key manager ---

/// One signing key entry, paired with its kid.
struct KeyEntry {
    kid: String,
    signing_key: SigningKey,
}

/// Active-key + verifier registry for CoMP quote signatures.
///
/// The manager holds at most one **active** key (used for signing)
/// plus a JWKS-style map of **previous** keys still trusted for
/// verification during a rotation window. Adding a new active key
/// rolls the previous active key into the verifier-only set; removing
/// an entry retires it from verification.
///
/// Both locks are recovered with
/// [`PoisonError::into_inner`](std::sync::PoisonError::into_inner)
/// rather than unwrapped. The guarded state is a plain map and a plain
/// `Option`, and every writer replaces a whole entry rather than
/// mutating one in place, so a panic in another thread cannot leave a
/// half-written key behind for a later reader to trust. Ending the
/// process instead would take a running proxy down for a fault in one
/// request, which is the trade the unwrap ratchet exists to refuse.
pub struct KeyManager {
    master: MasterKey,
    active: RwLock<Option<KeyEntry>>,
    verifiers: RwLock<HashMap<String, VerifyingKey>>,
}

impl std::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kids: Vec<String> = self
            .verifiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        f.debug_struct("KeyManager")
            .field("verifier_kids", &kids)
            .finish()
    }
}

impl KeyManager {
    /// Build a key manager seeded with the supplied master key. No
    /// active key is derived yet; call [`Self::set_active`] at
    /// startup.
    pub fn new(master: MasterKey) -> Arc<Self> {
        Arc::new(Self {
            master,
            active: RwLock::new(None),
            verifiers: RwLock::new(HashMap::new()),
        })
    }

    /// Set (or rotate) the active signing key to `rotation_id`. The
    /// prior active key, if any, is retained in the verifier map so
    /// quotes already in flight remain verifiable until the operator
    /// explicitly retires them.
    pub fn set_active(&self, rotation_id: &str) -> Result<String, LicensingError> {
        let (kid, signing_key) = derive_key(&self.master, rotation_id)?;
        let verifying_key = signing_key.verifying_key();
        // Insert into the verifier map first so a verifier running
        // concurrently with the rotation always sees a resolvable kid.
        self.verifiers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(kid.clone(), verifying_key);
        *self.active.write().unwrap_or_else(PoisonError::into_inner) = Some(KeyEntry {
            kid: kid.clone(),
            signing_key,
        });
        Ok(kid)
    }

    /// Retire a kid from the verifier map. The active key cannot be
    /// retired; rotate it via [`Self::set_active`] first.
    pub fn retire_kid(&self, kid: &str) -> Result<(), LicensingError> {
        if let Some(active) = self
            .active
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            if active.kid == kid {
                return Err(LicensingError::Encode(format!(
                    "cannot retire active kid {kid}; rotate first"
                )));
            }
        }
        self.verifiers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(kid);
        Ok(())
    }

    /// Sign `signing_input` with the active key. Returns `(kid,
    /// signature_bytes)`. Caller is responsible for encoding the
    /// signature into the wire form (base64url for a CoMP quote).
    pub fn sign(&self, signing_input: &[u8]) -> Result<(String, [u8; 64]), LicensingError> {
        let active = self.active.read().unwrap_or_else(PoisonError::into_inner);
        let entry = active.as_ref().ok_or_else(|| {
            LicensingError::Encode("no active signing key; call set_active first".into())
        })?;
        let signature = ed25519_dalek::Signer::sign(&entry.signing_key, signing_input);
        Ok((entry.kid.clone(), signature.to_bytes()))
    }

    /// Resolve a kid to a verifying key. Returns
    /// [`LicensingError::UnknownKey`] if the kid is not in the
    /// verifier map.
    pub fn lookup(&self, kid: &str) -> Result<VerifyingKey, LicensingError> {
        self.verifiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(kid)
            .copied()
            .ok_or_else(|| LicensingError::UnknownKey(kid.to_string()))
    }

    /// Active kid, for stamping into a newly-signed quote. Returns
    /// `None` if [`Self::set_active`] has not been called yet.
    pub fn active_kid(&self) -> Option<String> {
        self.active
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|e| e.kid.clone())
    }

    /// All currently-trusted `(kid, verifying_key)` pairs, suitable
    /// for publishing as a JWKS.
    pub fn jwks(&self) -> Vec<(String, VerifyingKey)> {
        self.verifiers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(kid, key)| (kid.clone(), *key))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::new(vec![0x42u8; 32]).unwrap()
    }

    #[test]
    fn derivation_is_deterministic() {
        let m = master();
        let (k1, s1) = derive_key(&m, "2026-q2-001").unwrap();
        let (k2, s2) = derive_key(&m, "2026-q2-001").unwrap();
        assert_eq!(k1, k2);
        assert_eq!(s1.to_bytes(), s2.to_bytes());
        assert_eq!(k1, "comp-2026-q2-001");
    }

    #[test]
    fn different_rotations_produce_independent_keys() {
        let m = master();
        let (_, a) = derive_key(&m, "2026-q2-001").unwrap();
        let (_, b) = derive_key(&m, "2026-q3-001").unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn rejects_short_master_key() {
        assert!(MasterKey::new(vec![0u8; 16]).is_err());
    }

    #[test]
    fn set_active_returns_kid_and_signs() {
        let mgr = KeyManager::new(master());
        let kid = mgr.set_active("2026-q2-001").unwrap();
        assert_eq!(kid, "comp-2026-q2-001");
        let (signing_kid, _sig) = mgr.sign(b"hello").unwrap();
        assert_eq!(signing_kid, kid);
    }

    #[test]
    fn rotation_keeps_prior_in_verifier_set() {
        let mgr = KeyManager::new(master());
        let k1 = mgr.set_active("2026-q2-001").unwrap();
        let k2 = mgr.set_active("2026-q3-001").unwrap();
        assert_ne!(k1, k2);
        assert!(mgr.lookup(&k1).is_ok());
        assert!(mgr.lookup(&k2).is_ok());
        assert_eq!(mgr.active_kid().unwrap(), k2);
    }

    #[test]
    fn cannot_retire_active_kid() {
        let mgr = KeyManager::new(master());
        let k1 = mgr.set_active("2026-q2-001").unwrap();
        let err = mgr.retire_kid(&k1).unwrap_err();
        assert!(matches!(err, LicensingError::Encode(_)));
    }

    #[test]
    fn retire_removes_non_active_kid() {
        let mgr = KeyManager::new(master());
        let k1 = mgr.set_active("2026-q2-001").unwrap();
        mgr.set_active("2026-q3-001").unwrap();
        mgr.retire_kid(&k1).unwrap();
        assert!(mgr.lookup(&k1).is_err());
    }

    #[test]
    fn lookup_unknown_kid_errors() {
        let mgr = KeyManager::new(master());
        mgr.set_active("2026-q2-001").unwrap();
        let err = mgr.lookup("comp-does-not-exist").unwrap_err();
        assert!(matches!(err, LicensingError::UnknownKey(_)));
    }

    #[test]
    fn jwks_lists_every_trusted_kid() {
        let mgr = KeyManager::new(master());
        mgr.set_active("2026-q2-001").unwrap();
        mgr.set_active("2026-q3-001").unwrap();
        assert_eq!(mgr.jwks().len(), 2);
    }
}
