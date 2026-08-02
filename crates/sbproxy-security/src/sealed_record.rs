//! One sealed-record envelope shared by every at-rest surface.
//!
//! The valuable part of at-rest encryption is not the AEAD call, which
//! [`crate::crypto`] already provides. It is everything around it: framing
//! the envelope, tagging it with a key fingerprint so an opener can pick
//! among candidate keys without trial decryption, drawing a per-record salt
//! so no two records share a derived key, assembling associated data that
//! binds the record to where it is stored, and opening under an active key
//! plus a list of retired ones so a rotation does not orphan history.
//!
//! Each of those is easy to get subtly wrong and each was previously
//! written out twice, once for the response cache and once for prompt
//! persistence. This module is the single implementation both now use, and
//! the one a third surface should reach for.
//!
//! # Envelope layout
//!
//! ```text
//! offset  size  field
//! 0       4     magic, per-surface (for example b"SBRC")
//! 4       1     version
//! 5       4     key fingerprint
//! 9       16    per-record HKDF salt
//! 25      12    per-record AES-GCM nonce
//! 37      ..    ciphertext followed by the 16-byte GCM tag
//! ```
//!
//! Every field is fixed-width, so the header is unambiguous and two
//! distinct headers can never flatten to the same bytes.
//!
//! # Associated data
//!
//! The AAD is the 37-byte header followed by a caller-supplied tail. The
//! header is included so salt, nonce, version, and key fingerprint are all
//! authenticated: an attacker who can write to the backing store cannot
//! re-point a record at a different key or swap its salt. The tail is where
//! the caller binds the record to its own notion of identity, which is what
//! stops a sealed record being lifted from one slot and replayed in
//! another. Callers must build the tail from fixed-width fields, or put the
//! single variable-width field last, so that two distinct tuples cannot
//! encode to the same bytes.
//!
//! # Nonces
//!
//! Every record draws a fresh 16-byte salt and derives its own AES key from
//! the operator's master material. The 96-bit nonce is therefore random
//! under a key that seals exactly one message, so the NIST SP 800-38D limit
//! of roughly 2^32 seals per key is never approached regardless of write
//! rate. Both draws come from the OS CSPRNG on every call, with no
//! userspace buffer and no persisted counter, so neither a fork nor a
//! restart nor a snapshot rollback can replay a nonce.
//!
//! # Key rotation
//!
//! [`SealKeyRing`] holds an active key that seals and opens, plus retired
//! keys that only open. Rotating means moving the current reference into
//! the retired list and naming a new one as active; records reseal under
//! the active key as they are rewritten. Dropping a reference out of the
//! retired list retires its records, which then report
//! [`OpenOutcome::NoMatchingKey`] and are evicted by the caller.

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use crate::crypto::{
    aes256gcm_decrypt, aes256gcm_encrypt, hkdf_derive_purpose, random_aes256_key,
    random_aes_gcm_nonce, HkdfPurpose, AES256_KEY_LEN, AES_GCM_NONCE_LEN,
};

/// Bytes of key fingerprint carried in the envelope.
pub const KEY_FP_LEN: usize = 4;
/// Bytes of per-record HKDF salt carried in the envelope.
pub const SALT_LEN: usize = 16;
/// Total envelope header length, in bytes.
pub const HEADER_LEN: usize = 4 + 1 + KEY_FP_LEN + SALT_LEN + AES_GCM_NONCE_LEN;

/// Shortest accepted master key material. Anything shorter is a passphrase
/// too weak to be worth the operator's confidence, and stretching it would
/// only hide that.
pub const MIN_KEY_MATERIAL_BYTES: usize = 16;

/// Immutable description of one at-rest surface's envelope.
///
/// A surface declares its magic, its format version, the HKDF purpose its
/// record keys derive under, and the fixed salt used only to derive public
/// key fingerprints. Two surfaces configured from the same operator secret
/// derive unrelated keys because their purposes differ, which is the whole
/// reason [`HkdfPurpose`] exists.
///
/// `fingerprint_salt` must never be [`SALT_LEN`] bytes long. A fingerprint
/// is printed in logs and written into every envelope; if its salt could
/// collide with a per-record salt, the published fingerprint would be the
/// leading bytes of a live record key. [`SealScheme::new`] is a `const fn`
/// that asserts the difference, so a scheme that would leak key bytes fails
/// to compile rather than shipping.
#[derive(Debug, Clone, Copy)]
pub struct SealScheme {
    magic: [u8; 4],
    version: u8,
    purpose: HkdfPurpose,
    fingerprint_salt: &'static [u8],
}

impl SealScheme {
    /// Declare a surface's envelope.
    ///
    /// # Panics
    ///
    /// Panics at compile time, when called in a `const` context, if
    /// `fingerprint_salt` is [`SALT_LEN`] bytes long. See the type-level
    /// docs for why that separation is load-bearing.
    pub const fn new(
        magic: [u8; 4],
        version: u8,
        purpose: HkdfPurpose,
        fingerprint_salt: &'static [u8],
    ) -> Self {
        assert!(
            fingerprint_salt.len() != SALT_LEN,
            "a fingerprint salt the same length as a per-record salt would make the \
             logged fingerprint the leading bytes of a live record key"
        );
        Self {
            magic,
            version,
            purpose,
            fingerprint_salt,
        }
    }

    /// The four-byte magic that identifies this surface's envelopes.
    pub const fn magic(&self) -> [u8; 4] {
        self.magic
    }

    /// The envelope format version this scheme writes.
    pub const fn version(&self) -> u8 {
        self.version
    }
}

/// Operator-supplied master key material for one at-rest surface, plus the
/// short public fingerprint that tags its envelopes.
///
/// The `Debug` impl prints only the fingerprint, so the material never
/// reaches a log line. The type is deliberately neither `Clone` nor
/// `Serialize`: every copy is another place the secret can escape from, and
/// there is no reason to make one. The material sits in a [`Zeroizing`]
/// wrapper so the heap allocation is scrubbed on drop rather than being
/// left for the next allocation or a core dump to pick up.
pub struct SealKey {
    material: Zeroizing<Vec<u8>>,
    scheme: SealScheme,
    fingerprint: [u8; KEY_FP_LEN],
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealKey")
            .field("key_id", &self.fingerprint_hex())
            .field("material", &"[redacted]")
            .finish()
    }
}

impl SealKey {
    /// Accept resolved key material for `scheme`.
    ///
    /// Returns an error for material shorter than [`MIN_KEY_MATERIAL_BYTES`]
    /// rather than stretching it, because a short passphrase silently
    /// accepted is how a surface ends up encrypted with something
    /// guessable. There is no other constructor, so a [`SealKeyRing`]
    /// cannot be built without material that passed this check.
    pub fn new(scheme: SealScheme, material: Vec<u8>) -> Result<Self> {
        // Wrap before the length check so material we reject is scrubbed
        // too. A passphrase short enough to refuse is still a secret.
        let material = Zeroizing::new(material);
        if material.len() < MIN_KEY_MATERIAL_BYTES {
            return Err(anyhow!(
                "at-rest encryption key must contain at least {MIN_KEY_MATERIAL_BYTES} bytes \
                 of material, got {}",
                material.len()
            ));
        }
        let derived = hkdf_derive_purpose(
            &material,
            scheme.fingerprint_salt,
            scheme.purpose,
            KEY_FP_LEN,
        );
        let mut fingerprint = [0u8; KEY_FP_LEN];
        fingerprint.copy_from_slice(&derived);
        Ok(Self {
            material,
            scheme,
            fingerprint,
        })
    }

    /// Short hex identifier for this key, safe to log.
    ///
    /// Derived through HKDF rather than by hashing the material directly,
    /// so it is not a four-byte preimage oracle on the operator's secret.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// Derive the single-use AES-256 key for a record with this salt.
    ///
    /// Both the HKDF output buffer and the returned key are wrapped so they
    /// are scrubbed on drop. This runs on every read and every write, so
    /// without it a busy gateway leaves a trail of freed 32-byte keys
    /// across the heap at request rate.
    fn record_key(&self, salt: &[u8]) -> Zeroizing<[u8; AES256_KEY_LEN]> {
        let derived = Zeroizing::new(hkdf_derive_purpose(
            &self.material,
            salt,
            self.scheme.purpose,
            AES256_KEY_LEN,
        ));
        let mut key = Zeroizing::new([0u8; AES256_KEY_LEN]);
        key.copy_from_slice(&derived);
        key
    }
}

/// An active key plus the retired keys kept only to open older records.
#[derive(Debug)]
pub struct SealKeyRing {
    scheme: SealScheme,
    active: SealKey,
    previous: Vec<SealKey>,
}

impl SealKeyRing {
    /// Build a ring that seals under `active` and opens under `active`
    /// first, then each entry of `previous` in order.
    ///
    /// Every key must have been built for `scheme`. Mixing schemes would
    /// mean a record sealed under one purpose being opened under another,
    /// so it is refused here rather than producing an authentication
    /// failure at read time that looks like tampering.
    pub fn new(scheme: SealScheme, active: SealKey, previous: Vec<SealKey>) -> Result<Self> {
        for key in std::iter::once(&active).chain(previous.iter()) {
            if key.scheme.magic != scheme.magic || key.scheme.purpose != scheme.purpose {
                return Err(anyhow!(
                    "at-rest key {} was built for a different sealing scheme than the ring it \
                     is being added to",
                    key.fingerprint_hex()
                ));
            }
        }
        Ok(Self {
            scheme,
            active,
            previous,
        })
    }

    /// The active key's public id, safe to log.
    pub fn active_key_id(&self) -> String {
        self.active.fingerprint_hex()
    }

    /// How many retired keys this ring can still open records under.
    pub fn retired_key_count(&self) -> usize {
        self.previous.len()
    }

    /// The scheme this ring seals and opens under.
    pub fn scheme(&self) -> SealScheme {
        self.scheme
    }

    /// Seal `plaintext` under the active key.
    ///
    /// `aad_tail` is appended to the envelope header to form the associated
    /// data. It is authenticated but not encrypted, and the same tail must
    /// be supplied to [`Self::open`] or the record will not authenticate.
    ///
    /// There is no plaintext fallback: a seal failure is returned as `Err`
    /// and the caller must fail the write rather than storing the input.
    pub fn seal(&self, plaintext: &[u8], aad_tail: &[u8]) -> Result<Vec<u8>> {
        let salt = random_salt();
        let nonce = random_aes_gcm_nonce();

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&self.scheme.magic);
        header.push(self.scheme.version);
        header.extend_from_slice(&self.active.fingerprint);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let mut aad = Vec::with_capacity(header.len() + aad_tail.len());
        aad.extend_from_slice(&header);
        aad.extend_from_slice(aad_tail);

        let record_key = self.active.record_key(&salt);
        let ciphertext = aes256gcm_encrypt(&record_key, &nonce, plaintext, &aad)?;

        let mut out = header;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a record previously parsed by [`SealedEnvelope::parse`].
    ///
    /// `aad_tail` must be byte-identical to the tail supplied at seal time.
    /// The three outcomes are meaningfully different and callers are
    /// expected to treat them differently; see [`OpenOutcome`].
    pub fn open(&self, envelope: &SealedEnvelope<'_>, aad_tail: &[u8]) -> OpenOutcome {
        let mut aad = Vec::with_capacity(envelope.header.len() + aad_tail.len());
        aad.extend_from_slice(envelope.header);
        aad.extend_from_slice(aad_tail);

        // Try every configured key whose fingerprint matches, active
        // first. Four bytes can in principle collide across two masters;
        // trying each match keeps a collision from turning a perfectly
        // readable record into a spurious authentication failure.
        let mut matched_a_key = false;
        for key in std::iter::once(&self.active).chain(self.previous.iter()) {
            if key.fingerprint != envelope.fingerprint {
                continue;
            }
            matched_a_key = true;
            let record_key = key.record_key(envelope.salt);
            if let Ok(plaintext) =
                aes256gcm_decrypt(&record_key, &envelope.nonce, envelope.ciphertext, &aad)
            {
                return OpenOutcome::Opened(plaintext);
            }
        }
        if matched_a_key {
            OpenOutcome::AuthFailed
        } else {
            OpenOutcome::NoMatchingKey
        }
    }
}

/// What happened when a ring was asked to open a record.
///
/// The distinction matters and callers should not collapse it. A record no
/// configured key claims is usually history: written before encryption was
/// enabled, or under a key that has since been dropped from the retired
/// list. A record whose fingerprint a ring does hold and which then fails
/// to authenticate is tampering or corruption, and deserves a louder
/// response than a miss.
#[derive(Debug)]
pub enum OpenOutcome {
    /// Authenticated plaintext.
    Opened(Vec<u8>),
    /// No configured key claims this envelope's fingerprint.
    NoMatchingKey,
    /// A configured key claimed the envelope and the tag did not verify.
    AuthFailed,
}

/// A parsed envelope header plus a borrow of its ciphertext.
///
/// Parsing is separate from opening so a caller can read the key
/// fingerprint, decide what associated data applies, and report a
/// structurally invalid record differently from an unopenable one.
#[derive(Debug)]
pub struct SealedEnvelope<'a> {
    /// Envelope format version, already checked against the scheme.
    pub version: u8,
    /// Key fingerprint this record was sealed under.
    pub fingerprint: &'a [u8],
    header: &'a [u8],
    salt: &'a [u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    ciphertext: &'a [u8],
}

impl<'a> SealedEnvelope<'a> {
    /// Parse `stored` as an envelope for `scheme`.
    ///
    /// Returns `Ok(None)` when the bytes are not this surface's envelope at
    /// all: wrong magic, too short to hold a header, or a version the
    /// scheme does not write. Those are not errors, because a store that
    /// used to run unencrypted is full of exactly such records and the
    /// caller's job is to heal rather than to fail.
    ///
    /// `accepts_version` decides which versions this build can read, which
    /// is what lets a surface introduce a new envelope version while
    /// continuing to open the old one.
    pub fn parse(
        scheme: SealScheme,
        stored: &'a [u8],
        accepts_version: impl Fn(u8) -> bool,
    ) -> Option<Self> {
        if stored.len() < HEADER_LEN || stored[..4] != scheme.magic {
            return None;
        }
        let version = stored[4];
        if !accepts_version(version) {
            return None;
        }
        let fp_start = 5;
        let salt_start = fp_start + KEY_FP_LEN;
        let nonce_start = salt_start + SALT_LEN;
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&stored[nonce_start..HEADER_LEN]);
        Some(Self {
            version,
            fingerprint: &stored[fp_start..salt_start],
            header: &stored[..HEADER_LEN],
            salt: &stored[salt_start..nonce_start],
            nonce,
            ciphertext: &stored[HEADER_LEN..],
        })
    }

    /// The key fingerprint as hex, safe to log.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

/// Draw a per-record salt.
///
/// Reuses the audited 32-byte CSPRNG helper and truncates, so this module
/// does not open a second path to the random number generator.
fn random_salt() -> [u8; SALT_LEN] {
    let full = random_aes256_key();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&full[..SALT_LEN]);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCHEME: SealScheme = SealScheme::new(
        *b"SBTS",
        1,
        HkdfPurpose::ResponseCacheAtRest,
        b"sbproxy.test.key-id.v1",
    );

    const OTHER_SCHEME: SealScheme = SealScheme::new(
        *b"SBTO",
        1,
        HkdfPurpose::PromptPersistenceAtRest,
        b"sbproxy.test-other.key-id.v1",
    );

    fn ring(scheme: SealScheme, active: u8, previous: &[u8]) -> SealKeyRing {
        SealKeyRing::new(
            scheme,
            SealKey::new(scheme, vec![active; 32]).unwrap(),
            previous
                .iter()
                .map(|seed| SealKey::new(scheme, vec![*seed; 32]).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn parse<'a>(scheme: SealScheme, bytes: &'a [u8]) -> SealedEnvelope<'a> {
        SealedEnvelope::parse(scheme, bytes, |v| v == scheme.version()).expect("parses")
    }

    #[test]
    fn seals_and_opens_under_the_active_key() {
        let ring = ring(TEST_SCHEME, 1, &[]);
        let sealed = ring.seal(b"payload", b"tail").unwrap();
        assert_eq!(&sealed[..4], b"SBTS");
        assert_eq!(sealed[4], 1);
        match ring.open(&parse(TEST_SCHEME, &sealed), b"tail") {
            OpenOutcome::Opened(plain) => assert_eq!(plain, b"payload"),
            other => panic!("expected Opened, got {other:?}"),
        }
    }

    #[test]
    fn a_different_aad_tail_fails_authentication() {
        // This is the property every caller relies on to keep a record
        // from being lifted out of one slot and replayed in another.
        let ring = ring(TEST_SCHEME, 1, &[]);
        let sealed = ring.seal(b"payload", b"slot-a").unwrap();
        assert!(matches!(
            ring.open(&parse(TEST_SCHEME, &sealed), b"slot-b"),
            OpenOutcome::AuthFailed
        ));
    }

    #[test]
    fn a_retired_key_still_opens_records_it_sealed() {
        let old = ring(TEST_SCHEME, 7, &[]);
        let sealed = old.seal(b"written-before-rotation", b"tail").unwrap();
        // Rotate: the old active key moves into the retired list.
        let rotated = ring(TEST_SCHEME, 8, &[7]);
        match rotated.open(&parse(TEST_SCHEME, &sealed), b"tail") {
            OpenOutcome::Opened(plain) => assert_eq!(plain, b"written-before-rotation"),
            other => panic!("expected Opened, got {other:?}"),
        }
        // ... and new writes go out under the new active key.
        let fresh = rotated.seal(b"after", b"tail").unwrap();
        assert_ne!(&fresh[5..9], &sealed[5..9], "fingerprint should have moved");
    }

    #[test]
    fn dropping_a_key_from_the_ring_reports_no_matching_key() {
        let old = ring(TEST_SCHEME, 7, &[]);
        let sealed = old.seal(b"orphaned", b"tail").unwrap();
        let without = ring(TEST_SCHEME, 8, &[]);
        assert!(matches!(
            without.open(&parse(TEST_SCHEME, &sealed), b"tail"),
            OpenOutcome::NoMatchingKey
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_an_auth_failure_not_a_miss() {
        let ring = ring(TEST_SCHEME, 1, &[]);
        let mut sealed = ring.seal(b"payload", b"tail").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            ring.open(&parse(TEST_SCHEME, &sealed), b"tail"),
            OpenOutcome::AuthFailed
        ));
    }

    #[test]
    fn tampering_with_the_header_is_an_auth_failure() {
        // The header is inside the AAD, so flipping a salt byte must not
        // simply derive a different key and report a clean miss.
        let ring = ring(TEST_SCHEME, 1, &[]);
        let mut sealed = ring.seal(b"payload", b"tail").unwrap();
        sealed[10] ^= 0x01;
        assert!(matches!(
            ring.open(&parse(TEST_SCHEME, &sealed), b"tail"),
            OpenOutcome::AuthFailed
        ));
    }

    #[test]
    fn two_seals_of_one_plaintext_differ() {
        let ring = ring(TEST_SCHEME, 1, &[]);
        let a = ring.seal(b"same", b"tail").unwrap();
        let b = ring.seal(b"same", b"tail").unwrap();
        assert_ne!(a, b, "per-record salt and nonce must randomise the output");
    }

    #[test]
    fn foreign_bytes_do_not_parse() {
        assert!(SealedEnvelope::parse(TEST_SCHEME, b"{\"json\":true}", |_| true).is_none());
        assert!(SealedEnvelope::parse(TEST_SCHEME, b"", |_| true).is_none());
        // Right length, wrong magic.
        assert!(SealedEnvelope::parse(TEST_SCHEME, &[0u8; HEADER_LEN + 8], |_| true).is_none());
    }

    #[test]
    fn an_unaccepted_version_does_not_parse() {
        let ring = ring(TEST_SCHEME, 1, &[]);
        let sealed = ring.seal(b"payload", b"tail").unwrap();
        assert!(SealedEnvelope::parse(TEST_SCHEME, &sealed, |v| v == 2).is_none());
    }

    #[test]
    fn short_key_material_is_refused() {
        let err = SealKey::new(TEST_SCHEME, b"too-short".to_vec()).unwrap_err();
        assert!(err.to_string().contains("at least 16 bytes"));
    }

    #[test]
    fn two_schemes_derive_unrelated_keys_from_one_secret() {
        // The point of a per-surface HkdfPurpose: an operator can point
        // two at-rest surfaces at the same secret and neither ring can
        // open the other's records.
        let a = ring(TEST_SCHEME, 3, &[]);
        let b = ring(OTHER_SCHEME, 3, &[]);
        let sealed = a.seal(b"cache-record", b"tail").unwrap();
        // Different magic, so it does not even parse as the other surface.
        assert!(SealedEnvelope::parse(OTHER_SCHEME, &sealed, |_| true).is_none());
        // And the derived keys differ, so the fingerprints do too.
        assert_ne!(a.active_key_id(), b.active_key_id());
    }

    #[test]
    fn mixing_schemes_in_one_ring_is_refused() {
        let err = SealKeyRing::new(
            TEST_SCHEME,
            SealKey::new(TEST_SCHEME, vec![1; 32]).unwrap(),
            vec![SealKey::new(OTHER_SCHEME, vec![2; 32]).unwrap()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("different sealing scheme"));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let key = SealKey::new(TEST_SCHEME, b"master-key-material-here".to_vec()).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("master-key-material-here"));

        let ring = SealKeyRing::new(TEST_SCHEME, key, Vec::new()).unwrap();
        let rendered = format!("{ring:?}");
        assert!(!rendered.contains("master-key-material-here"));
    }

    #[test]
    fn the_fingerprint_is_not_a_prefix_of_a_record_key() {
        // The fingerprint salt differs in length from a per-record salt,
        // so a published fingerprint cannot be the leading bytes of a key
        // that seals a live record.
        let key = SealKey::new(TEST_SCHEME, vec![9; 32]).unwrap();
        let published = hex::decode(key.fingerprint_hex()).unwrap();
        let record_key = key.record_key(&[0u8; SALT_LEN]);
        assert_ne!(&record_key[..KEY_FP_LEN], published.as_slice());
    }
}
