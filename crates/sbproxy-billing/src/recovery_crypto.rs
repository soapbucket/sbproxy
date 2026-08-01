//! Encrypted write-ahead envelopes for a replayable provider request.
//!
//! Some providers publish an idempotency contract that lets a caller repeat
//! the byte-identical request under the same key purely to recover the
//! original response. That is the one documented way to resolve a dispatch
//! that landed while this process was not around to read the answer. It only
//! works if the exact request bytes survived the crash, so they are sealed
//! here before the write and destroyed as soon as the answer is recorded.
//!
//! What the envelope holds and what it never holds is the point of this
//! module:
//!
//! - Sealed: the request body, its content type, the account context, and the
//!   pinned API version. Enough to reproduce the request byte for byte.
//! - Never sealed, never stored, never logged: the API key, any authorization
//!   header, and any credential the client presented.
//!
//! The ciphertext is bound with additional authenticated data over the rail,
//! the attempt, the operation, the provider idempotency key, and the
//! requirement digest. An envelope therefore cannot be lifted onto a
//! different attempt or a different amount: the open fails closed. A wrong
//! key, a tampered ciphertext, changed request bytes, or an envelope past its
//! hard expiry all fail closed too, and failing closed means the attempt
//! stays in reconciliation. It never falls back to a fresh idempotency key.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::BillingError;
use crate::types::{AttemptOperation, RecoveryEnvelopeRecord, SettlementRail};

/// Domain separator for the additional authenticated data.
const RECOVERY_AAD_DOMAIN: &[u8] = b"sbproxy-payment-recovery-v1";

/// Bytes in an AES-256 key.
const RECOVERY_KEY_LEN: usize = 32;

/// Bytes in an AES-GCM nonce.
const RECOVERY_NONCE_LEN: usize = 12;

/// The hard ceiling on how long an envelope may be replayable.
///
/// Stripe documents a minimum idempotency retention of 24 hours. This sits an
/// hour below it, so a replay this crate is willing to attempt is always one
/// the provider is still documented to deduplicate. Past that, a replay would
/// be a second charge rather than a response recovery.
pub const MAX_RECOVERY_AGE_MS: i64 = 23 * 60 * 60 * 1000;

/// The identity an envelope is cryptographically bound to.
///
/// None of these fields is secret. The idempotency key is designed to show up
/// in a provider dashboard, and the requirement digest is a hash of values the
/// client was already shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBinding {
    /// The rail the write targets.
    pub rail: SettlementRail,
    /// The attempt the envelope belongs to.
    pub attempt_id: String,
    /// The operation the write performs.
    pub operation: AttemptOperation,
    /// The provider idempotency key the write carries.
    pub provider_idempotency_key: String,
    /// Digest of the finalized requirement being settled.
    pub requirement_digest: [u8; 32],
}

impl RecoveryBinding {
    /// Builds a binding.
    pub fn new(
        rail: SettlementRail,
        attempt_id: &str,
        operation: AttemptOperation,
        provider_idempotency_key: &str,
        requirement_digest: [u8; 32],
    ) -> Self {
        Self {
            rail,
            attempt_id: attempt_id.to_string(),
            operation,
            provider_idempotency_key: provider_idempotency_key.to_string(),
            requirement_digest,
        }
    }

    /// Renders the additional authenticated data.
    ///
    /// Every part is length prefixed, so no two different bindings can render
    /// the same bytes by shuffling where one field ends and the next begins.
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(RECOVERY_AAD_DOMAIN);
        aad.push(0);
        for part in [
            self.rail.as_str().as_bytes(),
            self.attempt_id.as_bytes(),
            self.operation.as_str().as_bytes(),
            self.provider_idempotency_key.as_bytes(),
            &self.requirement_digest[..],
        ] {
            aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
            aad.extend_from_slice(part);
        }
        aad
    }

    /// Digests the additional authenticated data.
    ///
    /// The envelope stores this so a mismatched binding is caught before an
    /// AEAD open is attempted, which keeps a wrong-attempt lookup from looking
    /// like a tampering alert.
    pub fn aad_digest(&self) -> [u8; 32] {
        Sha256::digest(self.aad()).into()
    }
}

/// The AES-256-GCM cipher that seals and opens recovery envelopes.
///
/// The key is held in a zeroizing buffer and never leaves this type. There is
/// no accessor for it, no `Debug` that prints it, and no serialization.
pub struct RecoveryCipher {
    key_id: String,
    key: Zeroizing<Vec<u8>>,
}

impl RecoveryCipher {
    /// Builds a cipher from a configured key identifier and 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::RecoveryKeyLength`] unless the key is exactly
    /// 32 bytes, and [`BillingError::RecoveryKeyMissing`] when the key
    /// identifier is empty, because an unnamed key cannot be rotated away
    /// from safely.
    pub fn new(key_id: &str, key: &[u8]) -> Result<Self, BillingError> {
        if key_id.trim().is_empty() {
            return Err(BillingError::RecoveryKeyMissing);
        }
        if key.len() != RECOVERY_KEY_LEN {
            return Err(BillingError::RecoveryKeyLength);
        }
        Ok(Self {
            key_id: key_id.to_string(),
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// Returns the configured key identifier stored beside every ciphertext.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Seals one request into an envelope.
    ///
    /// `ttl_ms` is clamped to [`MAX_RECOVERY_AGE_MS`], so no configuration can
    /// make this crate willing to replay a request the provider has stopped
    /// deduplicating.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::RecoveryEnvelopeAuthFailed`] when the AEAD
    /// refuses to encrypt, and
    /// [`BillingError::InvalidRequirement`] when `ttl_ms` is not positive.
    pub fn seal(
        &self,
        binding: &RecoveryBinding,
        plaintext: &[u8],
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<RecoveryEnvelopeRecord, BillingError> {
        if ttl_ms <= 0 {
            return Err(BillingError::InvalidRequirement("recovery_ttl_ms"));
        }
        let ttl_ms = ttl_ms.min(MAX_RECOVERY_AGE_MS);
        let aad = binding.aad();

        let mut nonce_bytes = [0u8; RECOVERY_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = self.cipher();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BillingError::RecoveryEnvelopeAuthFailed)?;

        Ok(RecoveryEnvelopeRecord {
            attempt_id: binding.attempt_id.clone(),
            key_id: self.key_id.clone(),
            nonce: nonce_bytes,
            ciphertext,
            aad_digest: binding.aad_digest(),
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        })
    }

    /// Opens one envelope back into a zeroizing plaintext buffer.
    ///
    /// Every check here fails closed. The caller that gets an error must
    /// leave the attempt in reconciliation; there is no path from a failed
    /// open to a fresh idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::RecoveryKeyMismatch`] when the envelope was
    /// sealed under a different key identifier,
    /// [`BillingError::RecoveryEnvelopeExpired`] past the hard expiry, and
    /// [`BillingError::RecoveryEnvelopeAuthFailed`] when the binding does not
    /// match or the ciphertext does not authenticate.
    pub fn open(
        &self,
        envelope: &RecoveryEnvelopeRecord,
        binding: &RecoveryBinding,
        now_ms: i64,
    ) -> Result<Zeroizing<Vec<u8>>, BillingError> {
        if envelope.key_id != self.key_id {
            return Err(BillingError::RecoveryKeyMismatch);
        }
        if envelope.is_expired(now_ms) {
            return Err(BillingError::RecoveryEnvelopeExpired);
        }
        if now_ms.saturating_sub(envelope.created_at_ms) >= MAX_RECOVERY_AGE_MS {
            return Err(BillingError::RecoveryEnvelopeExpired);
        }
        if envelope.attempt_id != binding.attempt_id {
            return Err(BillingError::RecoveryEnvelopeAuthFailed);
        }
        let aad = binding.aad();
        if envelope.aad_digest != binding.aad_digest() {
            return Err(BillingError::RecoveryEnvelopeAuthFailed);
        }

        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BillingError::RecoveryEnvelopeAuthFailed)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Reports whether an envelope is still inside the replay window.
    pub fn is_replayable(&self, envelope: &RecoveryEnvelopeRecord, now_ms: i64) -> bool {
        envelope.key_id == self.key_id
            && !envelope.is_expired(now_ms)
            && now_ms.saturating_sub(envelope.created_at_ms) < MAX_RECOVERY_AGE_MS
    }

    /// Builds the AEAD instance for one operation.
    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key))
    }
}

impl std::fmt::Debug for RecoveryCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCipher")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}
