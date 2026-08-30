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

/// Prefix on every token minted by [`mint_key`].
///
/// Chosen so a token is distinguishable from an upstream provider key
/// (`sk-proj-...`, `sk-ant-...`, `sk-or-v1-...`) by prefix and length alone.
/// The inbound header sweep tests a candidate value with no store lookup, so
/// an unrelated header can never become a cache miss or an audit event.
pub const TOKEN_PREFIX: &str = "sbp_";

/// Hex character count of the public key id half of a token.
const KEY_ID_HEX_LEN: usize = KEY_ID_BYTES * 2;

/// Hex character count of the secret half of a token.
const SECRET_HEX_LEN: usize = SECRET_BYTES * 2;

/// Total character length of a minted token: prefix, id, separator, secret.
pub const TOKEN_LEN: usize = TOKEN_PREFIX.len() + KEY_ID_HEX_LEN + 1 + SECRET_HEX_LEN;

/// A minted virtual key: the public id, the one-time plaintext token shown to
/// the operator exactly once, and the at-rest hash that is persisted.
#[derive(Clone)]
pub struct MintedKey {
    /// Stable public identifier, the prefix of the token.
    pub key_id: String,
    /// The full bearer token `sbp_<key_id>_<secret>`. Shown once, never stored.
    pub token: String,
    /// `HMAC-SHA256(secret, pepper)`, hex-encoded. This is what is persisted.
    pub secret_hash: String,
}

/// Redacted `Debug` (WOR-2640). `token` is the one-time bearer token,
/// and it is a working credential from the moment it is minted until it
/// is revoked. `secret_hash` stays: it is the peppered HMAC that is
/// persisted anyway, and it is what correlates a minted key with the
/// record it produced.
impl std::fmt::Debug for MintedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedKey")
            .field("key_id", &self.key_id)
            .field("token", &"[REDACTED]")
            .field("secret_hash", &self.secret_hash)
            .finish()
    }
}

/// A freshly minted secret for an existing key id (rotation): the one-time
/// plaintext token (in the same `sbp_<key_id>_<secret>` shape [`mint_key`]
/// produces, not the legacy `sk-` shape), the plaintext secret half, and the
/// at-rest hash that replaces the record's current hash.
#[derive(Clone)]
pub struct MintedSecret {
    /// The full bearer token `sbp_<key_id>_<secret>`, built from the
    /// existing key id and the freshly minted secret. Shown once, never
    /// stored.
    pub token: String,
    /// The new plaintext secret half of the token. Shown once, never stored.
    pub secret: String,
    /// `HMAC-SHA256(secret, pepper)`, hex-encoded. Persisted as the new hash.
    pub secret_hash: String,
}

/// Redacted `Debug` (WOR-2640). As [`MintedKey`], and the plaintext
/// secret half is here as well as the full token.
impl std::fmt::Debug for MintedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedSecret")
            .field("token", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("secret_hash", &self.secret_hash)
            .finish()
    }
}

/// Mint a brand-new virtual key, returning the public id, the one-time token,
/// and the at-rest hash. `pepper` is the server-wide secret pepper.
pub fn mint_key(pepper: &[u8]) -> MintedKey {
    let key_id = random_hex(KEY_ID_BYTES);
    let secret = random_hex(SECRET_BYTES);
    let secret_hash = hash_secret(&secret, pepper);
    let token = format_token(&key_id, &secret);
    MintedKey {
        key_id,
        token,
        secret_hash,
    }
}

/// Format a token from its id and secret halves: `sbp_<key_id>_<secret>`.
///
/// The single place [`mint_key`] and [`KeyCrypto::mint_secret`] both build
/// the minted shape, so a fresh key and a rotated key cannot drift onto two
/// different token formats.
fn format_token(key_id: &str, secret: &str) -> String {
    format!("{TOKEN_PREFIX}{key_id}_{secret}")
}

/// Parse a bearer token of the form `sk-<key_id>-<secret>` into its public id
/// and secret halves. Returns `None` for any other shape.
///
/// This is the legacy shape, kept for tokens minted before [`TOKEN_PREFIX`] and
/// for config-seeded keys. It is deliberately loose: `sk-proj-abc` parses with
/// a `key_id` of `proj`, which is why callers must not treat a parse as proof
/// the token is ours. Prefer [`parse_minted_token`], and see
/// [`is_conforming_key_id`] for the discriminator the resolver uses.
pub fn parse_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix("sk-")?;
    let (key_id, secret) = rest.split_once('-')?;
    if key_id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((key_id, secret))
}

/// Parse a token minted by [`mint_key`]: `sbp_<16 hex>_<64 hex>`.
///
/// Rejects on length, ASCII-ness, prefix, separator position, and alphabet
/// before any allocation, so testing an unrelated header value costs one
/// length comparison. Returns `None` for the legacy `sk-` shape, which
/// [`parse_token`] still handles on the `authorization` path.
pub fn parse_minted_token(token: &str) -> Option<(&str, &str)> {
    // The ASCII check makes every byte index below a valid char boundary, so a
    // multibyte value of the same byte length cannot panic on a slice.
    if token.len() != TOKEN_LEN || !token.is_ascii() {
        return None;
    }
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    if rest.as_bytes()[KEY_ID_HEX_LEN] != b'_' {
        return None;
    }
    let key_id = &rest[..KEY_ID_HEX_LEN];
    let secret = &rest[KEY_ID_HEX_LEN + 1..];
    if !is_lower_hex(key_id) || !is_lower_hex(secret) {
        return None;
    }
    Some((key_id, secret))
}

/// Whether `key_id` has the exact shape [`mint_key`] produces.
///
/// The legacy [`parse_token`] rule is loose enough to swallow a genuine
/// provider key, so an unknown id only denies when it could plausibly have
/// been minted here. A non-conforming id was never ours and falls through to
/// whichever provider owns it.
pub fn is_conforming_key_id(key_id: &str) -> bool {
    key_id.len() == KEY_ID_HEX_LEN && is_lower_hex(key_id)
}

/// Whether every byte is a lowercase hex digit, the alphabet [`random_hex`]
/// emits.
fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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

/// Generate a random, URL-safe record identifier (24 hex chars). Used for
/// admin-created credential ids that the operator did not name.
pub fn random_id() -> String {
    random_hex(12)
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
    /// Names the external root of trust that wrapped [`Self::wrapped_dek`],
    /// when the DEK was wrapped by a customer-managed KMS rather than by a
    /// key derived from the locally-held master (WOR-2568).
    ///
    /// `None` is the local root: `wrapped_dek` is `wrap_nonce ||
    /// AES-256-GCM(HKDF(master), DEK)` and this process can open the
    /// envelope on its own. `Some(name)` is the customer-managed root:
    /// `wrapped_dek` is the opaque ciphertext the external KMS returned,
    /// and opening the envelope requires that KMS to be reachable and to
    /// still authorize this caller. The two are deliberately distinguished
    /// by a field on the record rather than by which key happens to be
    /// configured at open time, so a customer-managed envelope cannot
    /// silently fall back to a local unwrap when the config changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek: Option<String>,
    /// The data key wrapped (encrypted) under the master key, with its own
    /// nonce prefixed by the wrapping helper. Under a customer-managed root
    /// ([`Self::kek`] is `Some`) this is instead the UTF-8 bytes of the
    /// opaque ciphertext string the external KMS returned.
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
        kek: None,
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
    // A customer-managed envelope never opens on the local path, whatever
    // the process happens to hold. Without this the whole claim collapses
    // to "we prefer the KMS when it is configured": drop the
    // `root_of_trust` block from the config, restart, and every envelope
    // the customer's key wrapped would open again under the local master.
    if let Some(kek) = &env.kek {
        return Err(anyhow!(
            "envelope is wrapped under the customer-managed root of trust '{kek}' and cannot be \
             opened locally; configure key_management.crypto.root_of_trust so the external key \
             service can unwrap it"
        ));
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

/// An opened credential envelope, and how long its plaintext may be held.
///
/// `hold_for` is `None` for a locally-wrapped envelope, which no external
/// service bounds, and `Some(remaining)` for one wrapped under a
/// customer-managed root. A caller that caches the plaintext must clamp its
/// own entry to `hold_for`, measured from now, so the deployment's stated
/// revocation window is the whole of the exposure rather than the first of
/// two consecutive ones.
#[derive(Clone)]
pub struct OpenedEnvelope {
    /// The decrypted credential material.
    pub plaintext: Vec<u8>,
    /// How long the plaintext may be held, when an external root bounds it.
    pub hold_for: Option<std::time::Duration>,
}

/// A data key recovered from the external key service, and how long its
/// plaintext may still be held (WOR-2568).
///
/// `valid_for` is the load-bearing half. It is measured from the *external
/// unwrap that produced this data key*, not from the call that returned it,
/// so a caller that caches the plaintext downstream inherits the deadline
/// rather than starting a fresh one.
///
/// That distinction is the whole of a bug this shipped with once: two caches
/// each clamped to the same window W hold a secret for up to 2W, because the
/// second one starts its clock when the first one hands over. Clamping both
/// to W is what makes the composition invisible. Carrying the remaining time
/// instead makes the published revocation bound true by construction, with no
/// second call site to keep in step.
#[derive(Clone)]
pub struct UnwrappedDek {
    /// The plaintext data key.
    pub dek: Vec<u8>,
    /// How much of the revocation window is left for this data key.
    pub valid_for: std::time::Duration,
}

/// Redacting `Debug`. Unlike the config types in this workspace that carry
/// a secret among several readable fields, these two hold *only* a secret:
/// there is no useful redacted rendering of the payload, so the length is
/// all that crosses. The `RootOfTrust` trait carries a `std::fmt::Debug`
/// bound, which makes deriving `Debug` on things in this neighborhood the
/// habit, and a single `tracing::debug!(?opened)` on the credential path
/// would turn that habit into a decrypted upstream credential in a log
/// line. `CredentialMaterial` in this crate already hand-writes the same
/// treatment for the same reason.
impl std::fmt::Debug for OpenedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedEnvelope")
            .field(
                "plaintext",
                &format_args!("[REDACTED] ({} bytes)", self.plaintext.len()),
            )
            .field("hold_for", &self.hold_for)
            .finish()
    }
}

impl std::fmt::Debug for UnwrappedDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwrappedDek")
            .field(
                "dek",
                &format_args!("[REDACTED] ({} bytes)", self.dek.len()),
            )
            .field("valid_for", &self.valid_for)
            .finish()
    }
}

/// The external key service that wraps and unwraps envelope data keys when
/// `key_management.crypto.root_of_trust` names a customer-managed root
/// (WOR-2568).
///
/// This is deliberately a *service* interface, not a key-fetch interface.
/// There is no `fn root_key(&self) -> Vec<u8>`, because the whole point of
/// a customer-managed root is that sbproxy never holds the key that opens
/// the envelope. The DEK crosses the boundary; the key that wrapped it does
/// not. That is the same shape HashiCorp Vault's Transit engine exposes
/// (`/v1/transit/encrypt` and `/v1/transit/decrypt` return ciphertext and
/// plaintext, never the key) and the same shape AWS KMS `Encrypt`/`Decrypt`
/// take, and it is what makes revoking the customer's grant actually stop
/// sbproxy from decrypting rather than merely inconvenience it.
///
/// Both operations are `async` and are expected to be network calls. A
/// caching layer belongs in the implementation, and its TTL is the
/// deployment's stated revocation latency: however long an implementation
/// caches an unwrap, that is how long a revoked grant keeps working.
#[async_trait::async_trait]
pub trait RootOfTrust: Send + Sync + std::fmt::Debug {
    /// Stable, non-secret name of the external key. Persisted into
    /// [`Envelope::kek`] so an envelope names the key version-family it was
    /// wrapped under and an operator can tell two roots apart in a store.
    fn kek_name(&self) -> &str;

    /// Wrap a freshly generated 32-byte data key, returning the opaque
    /// ciphertext the external service produced.
    ///
    /// # Errors
    ///
    /// Any failure to reach or be authorized by the external service. There
    /// is deliberately no local fallback: a wrap that cannot reach the
    /// customer's key must fail rather than silently produce an envelope
    /// only sbproxy can open.
    async fn wrap_dek(&self, dek: &[u8]) -> Result<String>;

    /// Unwrap a ciphertext previously produced by [`Self::wrap_dek`].
    ///
    /// Returns the data key *and* how long its plaintext may be held, so a
    /// caller that caches downstream inherits this root's deadline instead
    /// of starting a second window of its own. See [`UnwrappedDek`].
    ///
    /// # Errors
    ///
    /// Any failure to reach or be authorized by the external service,
    /// including a revoked grant. Fail-closed: no cached-forever fallback.
    async fn unwrap_dek(&self, wrapped: &str) -> Result<UnwrappedDek>;

    /// How long this implementation may serve an unwrap from its own cache.
    /// This is the deployment's revocation-latency bound and is reported on
    /// the admin surface verbatim.
    fn revocation_window(&self) -> std::time::Duration;

    /// Confirm the external service is reachable and still authorizes this
    /// caller, recording the result for [`Self::last_liveness_ok`].
    ///
    /// On the trait rather than on one implementation because the admin
    /// surface and the background probe both hold a `dyn RootOfTrust` and
    /// neither has any business knowing which concrete root is installed.
    ///
    /// Required, with no default, and that is deliberate. This and the four
    /// methods below shipped once as defaults answering `Ok(())`, `None`,
    /// `false`, `0`, and a no-op. Every runtime caller holds a
    /// `dyn RootOfTrust`, so a root that forgot to forward them inherited
    /// those answers silently: the background probe reported a healthy
    /// service it had never dialed, and `GET /admin/crypto/root-of-trust`
    /// reported a warm cache as empty while an operator waited on a
    /// revocation. A default that reads as an honest "no liveness story"
    /// on paper reads as a healthy root on the admin surface. A test
    /// double is entitled to trivial answers here, but it has to write
    /// them down, so the compiler asks rather than the reviewer.
    ///
    /// # Errors
    ///
    /// Whatever the external service reported. A permission error is the
    /// revoked-grant case.
    async fn probe_liveness(&self) -> Result<()>;

    /// Unix seconds of the last *successful* liveness confirmation, or
    /// `None` when none has succeeded in this process.
    fn last_liveness_unix(&self) -> Option<u64>;

    /// Whether the most recent liveness check succeeded.
    fn last_liveness_ok(&self) -> bool;

    /// How many unwrapped data keys are currently cached and still inside
    /// [`Self::revocation_window`]. This is how much decrypt capability a
    /// revocation still has to age out.
    fn cached_dek_count(&self) -> usize;

    /// Drop every cached data key, so a revocation takes effect now rather
    /// than at the end of each entry's own window.
    fn purge_cache(&self);
}

/// A consolidated crypto handle holding the two server secrets the key plane
/// needs: the `pepper` (inbound-key hashing) and the `master` (upstream-credential
/// envelope). One handle is shared by the auth, admin, and dispatch layers so
/// the secrets live in a single place.
///
/// When `root` is set the credential envelope's data key is wrapped by an
/// external key service instead of by a key derived from `master` (WOR-2568).
/// `pepper` and `master` stay locally held either way: `pepper` hashes
/// inbound virtual keys and `master` derives the key-audit fingerprint key
/// and still opens envelopes sealed before the customer-managed root was
/// turned on. The customer-managed claim covers the upstream-credential
/// envelope and says so in `docs/key-management.md`; it does not cover the
/// inbound-key hashes.
#[derive(Clone)]
pub struct KeyCrypto {
    pepper: Vec<u8>,
    master: Vec<u8>,
    root: Option<std::sync::Arc<dyn RootOfTrust>>,
}

impl KeyCrypto {
    /// Build a handle from the server pepper and master key, with the local
    /// root of trust (the master wraps envelope data keys).
    pub fn new(pepper: impl Into<Vec<u8>>, master: impl Into<Vec<u8>>) -> Self {
        Self {
            pepper: pepper.into(),
            master: master.into(),
            root: None,
        }
    }

    /// Attach a customer-managed root of trust. Every envelope sealed after
    /// this point carries [`Envelope::kek`] and can only be opened while the
    /// external service is reachable and still authorizes this caller.
    pub fn with_root_of_trust(mut self, root: std::sync::Arc<dyn RootOfTrust>) -> Self {
        self.root = Some(root);
        self
    }

    /// The customer-managed root of trust, when one is configured.
    pub fn root_of_trust(&self) -> Option<&std::sync::Arc<dyn RootOfTrust>> {
        self.root.as_ref()
    }

    /// Mint a brand-new inbound key (id, one-time token, at-rest hash).
    pub fn mint_key(&self) -> MintedKey {
        mint_key(&self.pepper)
    }

    /// Mint a fresh secret + hash for an *existing* key id (rotation),
    /// returning the new plaintext token already formed in the same
    /// `sbp_<key_id>_<secret>` shape the free-function `mint_key` produces.
    /// `key_id` is the existing record's id; it is not itself minted here.
    pub fn mint_secret(&self, key_id: &str) -> MintedSecret {
        let secret = random_hex(SECRET_BYTES);
        let secret_hash = hash_secret(&secret, &self.pepper);
        let token = format_token(key_id, &secret);
        MintedSecret {
            token,
            secret,
            secret_hash,
        }
    }

    /// Hash a secret for at-rest storage.
    pub fn hash_secret(&self, secret: &str) -> String {
        hash_secret(secret, &self.pepper)
    }

    /// Constant-time verify a presented secret against a stored hash.
    pub fn verify_secret(&self, secret: &str, expected_hex: &str) -> bool {
        verify_secret(secret, &self.pepper, expected_hex)
    }

    /// Verify a presented secret against a [`KeyRecord`](crate::record::KeyRecord),
    /// honoring a rotation grace window. Keeps the pepper private to this handle.
    pub fn verify_record(
        &self,
        record: &crate::record::KeyRecord,
        secret: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        record.verify_secret(secret, &self.pepper, now)
    }

    /// Seal an upstream secret into an envelope bound to `record_id` under
    /// the *local* root.
    ///
    /// # Errors
    ///
    /// Refuses outright when a customer-managed root is configured. That
    /// refusal is the structural half of WOR-2568: a synchronous seal
    /// cannot reach a network key service, so leaving this path working
    /// under a customer-managed root is exactly how the feature would
    /// regress into "resolve once, hold forever" the next time somebody
    /// adds a call site. Use [`Self::seal_async`], which covers both roots.
    pub fn seal(&self, record_id: &str, plaintext: &[u8]) -> Result<Envelope> {
        if let Some(root) = &self.root {
            return Err(anyhow!(
                "a customer-managed root of trust ('{}') is configured, so an envelope cannot be \
                 sealed on the synchronous local path; call seal_async",
                root.kek_name()
            ));
        }
        seal_envelope(&self.master, record_id, plaintext)
    }

    /// Open an envelope sealed under the local root.
    ///
    /// # Errors
    ///
    /// A customer-managed envelope ([`Envelope::kek`] is `Some`) is refused
    /// here whatever this process holds; use [`Self::open_async`].
    pub fn open(&self, record_id: &str, env: &Envelope) -> Result<Vec<u8>> {
        open_envelope(&self.master, record_id, env).context("open credential envelope")
    }

    /// Seal an upstream secret into an envelope bound to `record_id`, under
    /// whichever root of trust is configured.
    ///
    /// With no customer-managed root this is [`Self::seal`]. With one, a
    /// fresh DEK encrypts the payload locally (AES-256-GCM, `record_id` as
    /// AAD, exactly as before) and the external service wraps the DEK. The
    /// AAD stays on the local payload step rather than being pushed into
    /// the KMS call, because associated-data support is not uniform across
    /// KMS products and the binding it provides (this ciphertext belongs to
    /// this record) is already load bearing where it is.
    ///
    /// # Errors
    ///
    /// Propagates the external service's failure. No local fallback.
    pub async fn seal_async(&self, record_id: &str, plaintext: &[u8]) -> Result<Envelope> {
        let Some(root) = &self.root else {
            return seal_envelope(&self.master, record_id, plaintext);
        };
        let aad = record_id.as_bytes();
        let dek = random_aes256_key();
        let nonce = random_aes_gcm_nonce();
        let ciphertext = aes256gcm_encrypt(&dek, &nonce, plaintext, aad)?;
        let wrapped = root
            .wrap_dek(&dek)
            .await
            .context("wrap the credential data key under the customer-managed root of trust")?;
        Ok(Envelope {
            alg: ENVELOPE_ALG_V1.to_string(),
            kek: Some(root.kek_name().to_string()),
            wrapped_dek: wrapped.into_bytes(),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Open an envelope under whichever root wrapped it.
    ///
    /// The envelope decides, not the config: a `kek`-less envelope opens
    /// locally even when a customer-managed root is configured (so turning
    /// the feature on does not brick credentials sealed before it), and a
    /// `kek`-bearing envelope needs the external service even if a local
    /// master is also present.
    ///
    /// # Errors
    ///
    /// A customer-managed envelope with no configured root, a `kek`
    /// mismatch against the configured root, or any failure of the external
    /// service including a revoked grant.
    pub async fn open_async(&self, record_id: &str, env: &Envelope) -> Result<OpenedEnvelope> {
        let Some(kek) = env.kek.as_deref() else {
            return Ok(OpenedEnvelope {
                plaintext: self.open(record_id, env)?,
                hold_for: None,
            });
        };
        let Some(root) = &self.root else {
            return Err(anyhow!(
                "envelope is wrapped under the customer-managed root of trust '{kek}' but no \
                 key_management.crypto.root_of_trust is configured to unwrap it"
            ));
        };
        if root.kek_name() != kek {
            return Err(anyhow!(
                "envelope names the root of trust '{kek}' but the configured root is '{}'",
                root.kek_name()
            ));
        }
        if env.alg != ENVELOPE_ALG_V1 {
            return Err(anyhow!("unsupported envelope alg '{}'", env.alg));
        }
        let wrapped = std::str::from_utf8(&env.wrapped_dek)
            .context("customer-managed wrapped DEK is not utf-8 ciphertext")?;
        let unwrapped = root
            .unwrap_dek(wrapped)
            .await
            .context("unwrap the credential data key under the customer-managed root of trust")?;
        let dek: [u8; AES256_KEY_LEN] = unwrapped
            .dek
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("unwrapped DEK is not {AES256_KEY_LEN} bytes"))?;
        let nonce: [u8; AES_GCM_NONCE_LEN] = env
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("envelope nonce is not {AES_GCM_NONCE_LEN} bytes"))?;
        let plaintext = aes256gcm_decrypt(&dek, &nonce, &env.ciphertext, record_id.as_bytes())
            .context("open credential envelope")?;
        Ok(OpenedEnvelope {
            plaintext,
            // The remaining window on the data key, not a fresh one. A
            // caller caching this plaintext must not outlive the unwrap
            // that produced it.
            hold_for: Some(unwrapped.valid_for),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_verify_roundtrips() {
        let pepper = b"server-pepper";
        let minted = mint_key(pepper);
        let (key_id, secret) = parse_minted_token(&minted.token).expect("token parses");
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
        let (_, secret) = parse_minted_token(&minted.token).unwrap();
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
            kek: None,
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
        let (_, secret) = parse_minted_token(&minted.token).unwrap();
        assert!(kc.verify_secret(secret, &minted.secret_hash));
        assert!(!kc.verify_secret("wrong", &minted.secret_hash));

        let env = kc.seal("cred-1", b"api-key").unwrap();
        assert_eq!(kc.open("cred-1", &env).unwrap(), b"api-key");
    }

    #[test]
    fn minted_token_round_trips_through_the_strict_parser() {
        let minted = mint_key(b"pepper");
        assert_eq!(minted.token.len(), TOKEN_LEN);
        assert!(minted.token.starts_with(TOKEN_PREFIX));
        let (key_id, secret) = parse_minted_token(&minted.token).expect("minted token parses");
        assert_eq!(key_id, minted.key_id);
        assert_eq!(secret.len(), 64);
        assert_eq!(minted.secret_hash, hash_secret(secret, b"pepper"));
        assert!(is_conforming_key_id(key_id));
    }

    #[test]
    fn rotated_secret_mints_the_same_shape_token_as_a_fresh_key() {
        // WOR-2537: rotate_key used to hand-build a legacy `sk-<id>-<secret>`
        // token instead of reusing the `sbp_<id>_<secret>` shape mint_key
        // produces. Pin the two callers of KeyCrypto to the same format so
        // they cannot drift apart again.
        let kc = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let created = kc.mint_key();
        let rotated = kc.mint_secret(&created.key_id);

        assert_eq!(rotated.token.len(), TOKEN_LEN);
        assert!(rotated.token.starts_with(TOKEN_PREFIX));
        let (key_id, secret) = parse_minted_token(&rotated.token)
            .expect("a rotated token must round-trip through the strict parser");
        assert_eq!(key_id, created.key_id, "rotation keeps the same key id");
        assert_eq!(secret.len(), 64);
        assert_eq!(rotated.secret_hash, hash_secret(secret, b"pepper"));
        assert!(kc.verify_secret(secret, &rotated.secret_hash));
    }

    #[test]
    fn strict_parser_rejects_provider_keys() {
        // The bug this closes: under the loose legacy rule a genuine OpenAI
        // project key parses with a key_id of "proj", so the resolver treated
        // it as one of ours and returned 401 instead of passing it through.
        for provider in [
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
            "sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
        ] {
            assert!(parse_minted_token(provider).is_none(), "{provider}");
            // The legacy rule still parses these, which is exactly why the
            // resolver needs the conformance check rather than the parse alone.
            let (key_id, _) = parse_token(provider).expect("legacy rule is loose");
            assert!(!is_conforming_key_id(key_id), "{provider} -> {key_id}");
        }
    }

    #[test]
    fn strict_parser_rejects_malformed_shapes() {
        let good = mint_key(b"pepper").token;

        // Wrong length, one either side.
        assert!(parse_minted_token(&good[..good.len() - 1]).is_none());
        assert!(parse_minted_token(&format!("{good}a")).is_none());
        // Right length, wrong prefix.
        assert!(parse_minted_token(&good.replacen(TOKEN_PREFIX, "sbx_", 1)).is_none());
        // Uppercase is not the minted alphabet.
        assert!(parse_minted_token(&good.to_uppercase()).is_none());
        // Separator moved off its fixed offset.
        let mut moved = good.clone();
        moved.replace_range(
            TOKEN_PREFIX.len() + KEY_ID_HEX_LEN..TOKEN_PREFIX.len() + KEY_ID_HEX_LEN + 1,
            "a",
        );
        moved.replace_range(TOKEN_PREFIX.len()..TOKEN_PREFIX.len() + 1, "_");
        assert!(parse_minted_token(&moved).is_none());
        // Non-ASCII of the same BYTE length must be rejected, not panic. The
        // body is 81 bytes, which is odd, so it is 40 two-byte chars plus one
        // ASCII byte. Without the is_ascii guard this slices mid-codepoint.
        let body_bytes = TOKEN_LEN - TOKEN_PREFIX.len();
        let multibyte = format!("{TOKEN_PREFIX}{}a", "é".repeat((body_bytes - 1) / 2));
        assert_eq!(
            multibyte.len(),
            TOKEN_LEN,
            "same byte length as a real token"
        );
        assert!(
            multibyte.chars().count() < TOKEN_LEN,
            "fewer chars than bytes"
        );
        assert!(parse_minted_token(&multibyte).is_none());
    }

    #[test]
    fn legacy_parse_cannot_resolve_a_seeded_key_id_containing_a_dash() {
        // `parse_token` splits on the FIRST dash, so a config-seeded key_id
        // with a dash in it can never round-trip. The shipped examples now
        // seed a conforming id, so nothing in the tree depends on the loose
        // shape; pinned so a dashed id stays a refusal rather than becoming a
        // silent auth failure later. `rotate_key` refuses a non-conforming id
        // outright, for the same reason on the minting side.
        let (key_id, secret) = parse_token("sk-team-alpha-secretvalue").unwrap();
        assert_eq!(key_id, "team", "splits on the first dash, not the last");
        assert_eq!(secret, "alpha-secretvalue");
        assert!(!is_conforming_key_id("team-alpha"));
    }

    /// WOR-2640: a minted token is a working credential the moment it
    /// exists. A `{:?}` of the mint result, in an admin handler or a
    /// test failure, used to print it in full.
    #[test]
    fn debug_never_renders_a_minted_token() {
        let minted = mint_key(b"pepper");
        let rendered = format!("{minted:?}");
        assert!(
            !rendered.contains(&minted.token),
            "the minted token reached Debug: {rendered}"
        );
        assert!(
            rendered.contains(&minted.key_id),
            "the key id must survive so a mint stays traceable: {rendered}"
        );

        let rotated =
            KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec()).mint_secret(&minted.key_id);
        let rendered = format!("{rotated:?}");
        assert!(
            !rendered.contains(&rotated.token) && !rendered.contains(&rotated.secret),
            "the rotated secret reached Debug: {rendered}"
        );
        assert!(rendered.contains(&rotated.secret_hash));
    }

    // --- WOR-2568: the customer-managed root of trust ---

    /// A stand-in external key service. Wrapping is a reversible encoding
    /// the stub can undo, which is enough to prove the data key crossed the
    /// boundary; what matters is *who* can undo it, and `revoked` is how a
    /// test takes that ability away mid-run the way a customer revoking a
    /// KMS grant does.
    #[derive(Debug)]
    struct StubRoot {
        name: String,
        revoked: std::sync::atomic::AtomicBool,
    }

    impl StubRoot {
        fn new(name: &str) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                name: name.to_string(),
                revoked: std::sync::atomic::AtomicBool::new(false),
            })
        }
        fn revoke(&self) {
            self.revoked
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        fn is_revoked(&self) -> bool {
            self.revoked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl RootOfTrust for StubRoot {
        fn kek_name(&self) -> &str {
            &self.name
        }
        async fn wrap_dek(&self, dek: &[u8]) -> Result<String> {
            if self.is_revoked() {
                return Err(anyhow!("grant revoked"));
            }
            Ok(format!("stub:v1:{}", hex::encode(dek)))
        }
        async fn unwrap_dek(&self, wrapped: &str) -> Result<UnwrappedDek> {
            if self.is_revoked() {
                return Err(anyhow!("grant revoked"));
            }
            let body = wrapped
                .strip_prefix("stub:v1:")
                .ok_or_else(|| anyhow!("not a stub ciphertext"))?;
            Ok(UnwrappedDek {
                dek: hex::decode(body)?,
                valid_for: self.revocation_window(),
            })
        }
        fn revocation_window(&self) -> std::time::Duration {
            std::time::Duration::from_secs(42)
        }
        // Written out rather than inherited: the trait has no defaults for
        // the liveness five, precisely so a root cannot answer "healthy,
        // nothing cached" by accident. This double keeps no cache, and its
        // liveness is its grant, so it says both.
        async fn probe_liveness(&self) -> Result<()> {
            if self.is_revoked() {
                return Err(anyhow!("grant revoked"));
            }
            Ok(())
        }
        fn last_liveness_unix(&self) -> Option<u64> {
            None
        }
        fn last_liveness_ok(&self) -> bool {
            !self.is_revoked()
        }
        fn cached_dek_count(&self) -> usize {
            0
        }
        fn purge_cache(&self) {}
    }

    /// The seam: with a customer-managed root configured, the key that
    /// wraps the envelope's data key is never held by this process. The
    /// proof is negative and has to be, because "we called a KMS" is not
    /// the claim: a process holding the master key that a local seal would
    /// have used still cannot open the envelope.
    #[tokio::test]
    async fn a_customer_managed_envelope_does_not_open_under_the_local_master() {
        let root = StubRoot::new("stub/root-a");
        let crypto =
            KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec()).with_root_of_trust(root.clone());
        let env = crypto
            .seal_async("cred-1", b"upstream-secret")
            .await
            .expect("seal under the customer-managed root");
        assert_eq!(env.kek.as_deref(), Some("stub/root-a"));

        // The same master, on the local path, must not open it.
        let local = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let err = format!(
            "{:#}",
            local
                .open("cred-1", &env)
                .expect_err("a customer-managed envelope must never open locally")
        );
        assert!(
            err.contains("customer-managed root of trust"),
            "the refusal must name why: {err}"
        );

        // And it does open through the external service.
        let opened = crypto
            .open_async("cred-1", &env)
            .await
            .expect("open through the external root");
        assert_eq!(opened.plaintext, b"upstream-secret");
        assert_eq!(
            opened.hold_for,
            Some(std::time::Duration::from_secs(42)),
            "a customer-managed open must hand back the deadline its data key carries, or a \
             downstream cache starts a second window"
        );
    }

    /// Revoking the customer's grant stops decryption, rather than merely
    /// making it slower. This is the whole enterprise claim: the vendor's
    /// copy becomes unreadable.
    #[tokio::test]
    async fn revoking_the_external_grant_stops_the_envelope_opening() {
        let root = StubRoot::new("stub/root-b");
        let crypto =
            KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec()).with_root_of_trust(root.clone());
        let env = crypto.seal_async("cred-2", b"secret").await.expect("seal");
        assert_eq!(
            crypto.open_async("cred-2", &env).await.unwrap().plaintext,
            b"secret"
        );

        root.revoke();
        let err = format!(
            "{:#}",
            crypto
                .open_async("cred-2", &env)
                .await
                .expect_err("a revoked grant must stop decryption")
        );
        assert!(err.contains("revoked"), "{err}");
    }

    /// Turning the feature on must not brick credentials sealed before it,
    /// and turning it off must not un-brick the ones sealed after. The
    /// envelope decides, not the config.
    #[tokio::test]
    async fn the_envelope_names_its_root_and_the_config_does_not_override_it() {
        let local = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let legacy = local.seal("cred-3", b"older-secret").expect("local seal");
        assert!(legacy.kek.is_none());

        let root = StubRoot::new("stub/root-c");
        let cmk =
            KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec()).with_root_of_trust(root.clone());
        // Legacy envelopes keep opening after the switch.
        let legacy_opened = cmk.open_async("cred-3", &legacy).await.unwrap();
        assert_eq!(legacy_opened.plaintext, b"older-secret");
        assert_eq!(
            legacy_opened.hold_for, None,
            "a locally-wrapped envelope is bounded by no external service, so it carries no \
             deadline"
        );
        // The synchronous seal is refused outright under a customer-managed
        // root, so no later call site can quietly produce a locally-wrapped
        // envelope while the config claims a customer-held root.
        let err = format!(
            "{:#}",
            cmk.seal("cred-3", b"nope")
                .expect_err("the sync seal must refuse under a customer-managed root")
        );
        assert!(err.contains("seal_async"), "{err}");

        // An envelope wrapped by a different root is refused, not attempted.
        let other = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec())
            .with_root_of_trust(StubRoot::new("stub/root-d"));
        let sealed = cmk.seal_async("cred-3", b"x").await.expect("seal");
        let err = format!(
            "{:#}",
            other
                .open_async("cred-3", &sealed)
                .await
                .expect_err("a mismatched root must be refused")
        );
        assert!(err.contains("stub/root-c"), "{err}");
    }

    /// Registry sentinel for `OpenedEnvelope` and `UnwrappedDek`
    /// (`scripts/secret-debug-registry.txt`).
    ///
    /// These two hold nothing but key material: the decrypted upstream
    /// credential and the plaintext AES-256 data key. There is no useful
    /// redacted rendering of the payload, so the length is all that may
    /// cross, and the length is what tells an operator the difference
    /// between an empty read and a real one.
    #[test]
    fn debug_never_renders_opened_or_unwrapped_key_material() {
        let opened = OpenedEnvelope {
            plaintext: b"sk-live-must-not-appear".to_vec(),
            hold_for: Some(std::time::Duration::from_secs(7)),
        };
        let rendered = format!("{opened:?}");
        assert!(
            !rendered.contains("sk-live-must-not-appear"),
            "the decrypted credential reached Debug: {rendered}"
        );
        assert!(
            !rendered.contains("115"),
            "the payload must not render as a byte array either: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]") && rendered.contains("23 bytes"),
            "the redaction must still say how much was there: {rendered}"
        );
        assert!(
            rendered.contains("OpenedEnvelope") && rendered.contains("hold_for"),
            "the identifier and the non-secret field survive: {rendered}"
        );

        let unwrapped = UnwrappedDek {
            dek: b"0123456789abcdef0123456789abcdef".to_vec(),
            valid_for: std::time::Duration::from_secs(11),
        };
        let rendered = format!("{unwrapped:?}");
        assert!(
            !rendered.contains("0123456789abcdef"),
            "the plaintext data key reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]") && rendered.contains("32 bytes"),
            "{rendered}"
        );
        assert!(
            rendered.contains("UnwrappedDek") && rendered.contains("valid_for"),
            "{rendered}"
        );
    }
}
