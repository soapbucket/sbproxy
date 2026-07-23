//! At-rest encryption decorator for the response cache.
//!
//! Wraps any [`CacheStore`] and seals the response headers and body of
//! every entry with AES-256-GCM before they reach the backing store.
//! Because it is a decorator rather than a backend, the file, memcached,
//! redis, and memory stores all get encryption from one implementation,
//! and `backend_name` still reports the real backend so the admin API
//! keeps answering correctly about prefix-purge support.
//!
//! # What is sealed and what is not
//!
//! `headers` and `body` are sealed. `status`, `cached_at`, and
//! `ttl_secs` stay in the clear because the backing stores read them:
//! the file store writes the expiry into its 8-byte record header and
//! memcached needs a relative TTL on the `set` command. All three are
//! bound into the AEAD associated data, so they are visible but cannot
//! be altered without failing authentication. Binding `cached_at` and
//! `ttl_secs` matters as much as binding `status`: without it, anyone
//! with write access to the backing store could extend the lifetime of
//! a sealed entry indefinitely without ever touching the ciphertext.
//!
//! # Envelope layout (version 1)
//!
//! ```text
//! offset  size  field
//! 0       4     magic  b"SBRC"
//! 4       1     version, currently 1
//! 5       4     key fingerprint
//! 9       16    per-entry salt
//! 25      12    per-entry nonce
//! 37      ..    ciphertext followed by the 16-byte GCM tag
//! ```
//!
//! The associated data is the 37-byte header, then `status`,
//! `cached_at`, and `ttl_secs` as big-endian bytes, then the cache key.
//! Every field before the key is fixed-width, so the encoding is
//! unambiguous and two different tuples cannot flatten to the same AAD.
//! Binding the cache key means a stored record cannot be lifted from one
//! key to another and replayed.
//!
//! # Nonces
//!
//! Every entry draws a fresh 16-byte salt and derives its own AES key
//! with HKDF-SHA256 from the operator's master material. The 96-bit
//! nonce is then random under a key that seals exactly one message, so
//! the NIST SP 800-38D limit of roughly 2^32 seals per key is never
//! approached regardless of cache write rate. A single long-lived key
//! with random nonces would hit that limit in days on a busy gateway.
//! Both draws come from the OS CSPRNG on every call, with no userspace
//! buffer and no persisted counter, so neither a fork nor a restart nor
//! a snapshot rollback can replay a nonce.
//!
//! # Key rotation
//!
//! The active key seals and opens. Retired keys open only. Each envelope
//! carries a 4-byte fingerprint derived from its master material through
//! HKDF (never a raw hash of the secret), so an open selects the right
//! master directly. Rotating means moving the old reference into
//! `previous_keys` and naming the new one as `key`; entries reseal under
//! the active key as they are rewritten. Dropping a reference out of
//! `previous_keys` retires its entries, which are then evicted on read.
//!
//! # Failure behaviour
//!
//! There is no plaintext write path: `put` seals or returns `Err`. On
//! read, a record with no envelope, an unknown version, or a fingerprint
//! matching no configured key is deleted and reported as a miss, so a
//! cache that used to run unencrypted heals rather than silently serving
//! records this store cannot vouch for. A record whose fingerprint does
//! match but which fails to authenticate is tampering or corruption: it
//! is deleted as well and then reported as `Err`, which the request path
//! logs and treats as a cache bypass. Every unreadable record is
//! evicted, whichever way it is unreadable. Leaving the authentication
//! failures in place would be the worse of the two, because `ttl_secs`
//! is in the clear: a forged record can name its own lifetime, and the
//! bypassing read path never rewrites the key it just refused, so the
//! poisoned entry would sit there driving origin load until an operator
//! purged it. No path returns plaintext that the AEAD did not
//! authenticate, and no path falls back to serving the record unsealed.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sbproxy_security::{
    aes256gcm_decrypt, aes256gcm_encrypt, hkdf_derive_purpose, random_aes256_key,
    random_aes_gcm_nonce, HkdfPurpose, AES256_KEY_LEN, AES_GCM_NONCE_LEN,
};
use zeroize::Zeroizing;

use super::{CacheStore, CachedResponse};

/// Envelope magic, short for SBproxy Response Cache.
const MAGIC: [u8; 4] = *b"SBRC";
/// Envelope format version.
const VERSION: u8 = 1;
/// Bytes of key fingerprint carried in the envelope.
const KEY_FP_LEN: usize = 4;
/// Bytes of per-entry HKDF salt carried in the envelope.
const SALT_LEN: usize = 16;
/// Total envelope header length, in bytes.
const HEADER_LEN: usize = MAGIC.len() + 1 + KEY_FP_LEN + SALT_LEN + AES_GCM_NONCE_LEN;
/// Shortest accepted master key material. Anything shorter is a
/// passphrase too weak to be worth the operator's confidence.
const MIN_KEY_MATERIAL_BYTES: usize = 16;
/// Fixed HKDF salt used only for deriving a key's public fingerprint.
/// Its length differs from [`SALT_LEN`], so it can never collide with a
/// per-entry salt. That separation is what keeps the fingerprint we
/// print in logs from being the leading bytes of a live per-entry key,
/// and the assert below is what enforces it: shrink `KEY_ID_SALT` to 16
/// bytes and the build stops rather than quietly leaking key bytes.
const KEY_ID_SALT: &[u8] = b"sbproxy.response-cache.key-id.v1";
const _: () = assert!(KEY_ID_SALT.len() != SALT_LEN);

/// Emitted once per process when the decorator is asked to encrypt an
/// in-process cache, so a config that moves between backends does not
/// leave an operator believing memory entries are protected at rest.
static MEMORY_BACKEND_ADVISORY: std::sync::Once = std::sync::Once::new();

/// Operator-supplied master key material for response-cache encryption.
///
/// Holds the raw material plus a short public fingerprint used to tag
/// envelopes. The `Debug` impl prints only the fingerprint, so the
/// material never reaches a log line. The type is deliberately neither
/// `Clone` nor `Serialize`: every copy is another place the secret can
/// escape from, and there is no reason to make one. The material sits
/// in a [`Zeroizing`] wrapper so the heap allocation is scrubbed when
/// the key is dropped, rather than being left for the next allocation
/// or a core dump to pick up.
pub struct CacheKeyMaterial {
    material: Zeroizing<Vec<u8>>,
    fingerprint: [u8; KEY_FP_LEN],
}

impl std::fmt::Debug for CacheKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheKeyMaterial")
            .field("key_id", &self.fingerprint_hex())
            .field("material", &"[redacted]")
            .finish()
    }
}

impl CacheKeyMaterial {
    /// Accept resolved key material.
    ///
    /// Returns an error for material shorter than 16 bytes rather than
    /// stretching it, because a short passphrase silently accepted is
    /// how a cache ends up encrypted with something guessable. There is
    /// no other constructor, so an [`EncryptedCacheStore`] cannot be
    /// built without material that passed this check.
    pub fn new(material: Vec<u8>) -> Result<Self> {
        // Wrap before the length check so material we reject is scrubbed
        // too. A passphrase short enough to refuse is still a secret.
        let material = Zeroizing::new(material);
        if material.len() < MIN_KEY_MATERIAL_BYTES {
            return Err(anyhow!(
                "response-cache encryption key must contain at least {MIN_KEY_MATERIAL_BYTES} bytes of material, got {}",
                material.len()
            ));
        }
        let derived = hkdf_derive_purpose(
            &material,
            KEY_ID_SALT,
            HkdfPurpose::ResponseCacheAtRest,
            KEY_FP_LEN,
        );
        let mut fingerprint = [0u8; KEY_FP_LEN];
        fingerprint.copy_from_slice(&derived);
        Ok(Self {
            material,
            fingerprint,
        })
    }

    /// Short hex identifier for this key, safe to log. Derived through
    /// HKDF rather than hashed directly, so it reveals nothing usable
    /// about the material.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// Derive the single-use AES-256 key for an entry with this salt.
    ///
    /// Both the HKDF output buffer and the returned key are wrapped so
    /// they are scrubbed on drop. This runs on every cache read and
    /// every cache write, so without it a busy gateway leaves a trail of
    /// freed 32-byte keys across the heap at request rate.
    fn entry_key(&self, salt: &[u8]) -> Zeroizing<[u8; AES256_KEY_LEN]> {
        let derived = Zeroizing::new(hkdf_derive_purpose(
            &self.material,
            salt,
            HkdfPurpose::ResponseCacheAtRest,
            AES256_KEY_LEN,
        ));
        let mut key = Zeroizing::new([0u8; AES256_KEY_LEN]);
        key.copy_from_slice(&derived);
        key
    }
}

/// Draw a 16-byte per-entry salt.
///
/// Reuses the audited 32-byte CSPRNG helper and truncates, so this file
/// does not open a second path to the random number generator.
fn random_salt() -> [u8; SALT_LEN] {
    let full = random_aes256_key();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&full[..SALT_LEN]);
    salt
}

/// Append a big-endian `u32` length prefix followed by `bytes`.
///
/// Errors rather than truncating the cast: a silently wrapped length
/// would frame a payload that reparses into the wrong headers.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| anyhow!("response header field is too large to frame for the cache"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Flatten headers and body into the byte string that gets sealed.
///
/// Layout: a big-endian `u32` header count, then for each header a
/// big-endian `u32` name length, the name, a big-endian `u32` value
/// length, and the value. Everything after the last header is the body.
fn frame_payload(entry: &CachedResponse) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(entry.body.len() + 64);
    let count = u32::try_from(entry.headers.len())
        .map_err(|_| anyhow!("response has too many headers to frame for the cache"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in &entry.headers {
        push_len_prefixed(&mut out, name.as_bytes())?;
        push_len_prefixed(&mut out, value.as_bytes())?;
    }
    out.extend_from_slice(&entry.body);
    Ok(out)
}

/// Read a big-endian `u32` and advance `cursor`.
fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| anyhow!("sealed cache payload length overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("sealed cache payload truncated"))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    *cursor = end;
    Ok(u32::from_be_bytes(buf))
}

/// Read a length-prefixed UTF-8 string and advance `cursor`.
fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let len = read_u32(bytes, cursor)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| anyhow!("sealed cache payload length overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("sealed cache payload truncated"))?;
    *cursor = end;
    String::from_utf8(slice.to_vec()).context("sealed cache payload header is not UTF-8")
}

/// Headers and body recovered from an authenticated payload. Named so
/// the `unframe_payload` signature stays under clippy's
/// `type_complexity` threshold.
type UnframedPayload = (Vec<(String, String)>, Vec<u8>);

/// Inverse of [`frame_payload`].
///
/// The payload is authenticated before it reaches here, so a malformed
/// input is effectively impossible. The parse is still bounds-checked,
/// because "effectively impossible" is not a reason to index blindly
/// into a buffer. A parse error propagates as `Err`; it never yields a
/// partially decoded entry.
fn unframe_payload(bytes: &[u8]) -> Result<UnframedPayload> {
    let mut cursor = 0usize;
    let count = read_u32(bytes, &mut cursor)? as usize;
    // Cap the pre-allocation: a corrupt count cannot make us reserve
    // gigabytes before the first truncation check fires.
    let mut headers = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let name = read_string(bytes, &mut cursor)?;
        let value = read_string(bytes, &mut cursor)?;
        headers.push((name, value));
    }
    // `cursor` is bounded by every `get` above, so this slice is in range.
    Ok((headers, bytes[cursor..].to_vec()))
}

/// Associated data for one entry: envelope header, the clear-text TTL
/// metadata, then the cache key.
///
/// Everything before the key is fixed-width, so the concatenation is an
/// injective encoding and no two distinct tuples share an AAD.
fn associated_data(
    header: &[u8],
    status: u16,
    cached_at: u64,
    ttl_secs: u64,
    key: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 2 + 8 + 8 + key.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&status.to_be_bytes());
    aad.extend_from_slice(&cached_at.to_be_bytes());
    aad.extend_from_slice(&ttl_secs.to_be_bytes());
    aad.extend_from_slice(key.as_bytes());
    aad
}

/// A [`CacheStore`] that seals every payload before it reaches the
/// wrapped store.
pub struct EncryptedCacheStore {
    inner: Arc<dyn CacheStore>,
    active: CacheKeyMaterial,
    /// Retired keys, used for opening only. Ordered as configured.
    previous: Vec<CacheKeyMaterial>,
}

impl std::fmt::Debug for EncryptedCacheStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedCacheStore")
            .field("backend", &self.inner.backend_name())
            .field("key_id", &self.active.fingerprint_hex())
            .field(
                "previous_key_ids",
                &self
                    .previous
                    .iter()
                    .map(CacheKeyMaterial::fingerprint_hex)
                    .collect::<Vec<_>>(),
            )
            .field("key_material", &"[redacted]")
            .finish()
    }
}

impl EncryptedCacheStore {
    /// Wrap `inner`, sealing with `active` and opening with `active`
    /// first and then each entry in `previous`.
    ///
    /// Infallible by construction: a [`CacheKeyMaterial`] cannot exist
    /// without having passed [`CacheKeyMaterial::new`], so there is no
    /// state in which this store comes up without a usable key. It has
    /// no unencrypted mode to fall back to.
    pub fn new(
        inner: Arc<dyn CacheStore>,
        active: CacheKeyMaterial,
        previous: Vec<CacheKeyMaterial>,
    ) -> Self {
        if inner.backend_name() == "memory" {
            // Allowed on purpose so a config can move between backends
            // without editing the encryption block, but say plainly that
            // it buys nothing: the plaintext lives in this process
            // either way, and there is no disk or wire to protect.
            MEMORY_BACKEND_ADVISORY.call_once(|| {
                tracing::warn!(
                    backend = "memory",
                    "response-cache encryption is enabled over the in-process memory backend; \
                     entries never leave this process, so this protects nothing at rest"
                );
            });
        }
        Self {
            inner,
            active,
            previous,
        }
    }

    /// Seal an entry under the active key.
    fn seal(&self, key: &str, entry: &CachedResponse) -> Result<CachedResponse> {
        let salt = random_salt();
        let nonce = random_aes_gcm_nonce();

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&self.active.fingerprint);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let aad = associated_data(&header, entry.status, entry.cached_at, entry.ttl_secs, key);
        let entry_key = self.active.entry_key(&salt);
        let ciphertext = aes256gcm_encrypt(&entry_key, &nonce, &frame_payload(entry)?, &aad)
            .context("seal response-cache entry")?;

        let mut body = header;
        body.extend_from_slice(&ciphertext);
        Ok(CachedResponse {
            status: entry.status,
            headers: Vec::new(),
            body,
            cached_at: entry.cached_at,
            ttl_secs: entry.ttl_secs,
        })
    }

    /// Open a stored record.
    ///
    /// `Ok(None)` means "this store cannot read this record under any
    /// configured key", which the caller turns into an eviction and a
    /// miss. `Err` means the record claimed a key we hold and then
    /// failed to authenticate, which is tampering or corruption; that
    /// record is evicted here before the error is returned, so a forged
    /// entry cannot pin itself in the cache behind a cleartext TTL.
    fn open(&self, key: &str, stored: &CachedResponse) -> Result<Option<CachedResponse>> {
        let body = &stored.body;
        if body.len() < HEADER_LEN || body[..MAGIC.len()] != MAGIC {
            return Ok(None);
        }
        if body[MAGIC.len()] != VERSION {
            return Ok(None);
        }
        let fp_start = MAGIC.len() + 1;
        let salt_start = fp_start + KEY_FP_LEN;
        let nonce_start = salt_start + SALT_LEN;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&body[salt_start..nonce_start]);
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        nonce.copy_from_slice(&body[nonce_start..HEADER_LEN]);

        let aad = associated_data(
            &body[..HEADER_LEN],
            stored.status,
            stored.cached_at,
            stored.ttl_secs,
            key,
        );

        // Try every configured key whose fingerprint matches, active
        // first. A 4-byte fingerprint can in principle collide across
        // two masters; trying each match keeps a collision from turning
        // a perfectly readable entry into a spurious auth failure.
        let fp = &body[fp_start..salt_start];
        let mut matched_a_key = false;
        let mut opened: Option<Vec<u8>> = None;
        for material in std::iter::once(&self.active).chain(self.previous.iter()) {
            if material.fingerprint != fp {
                continue;
            }
            matched_a_key = true;
            let entry_key = material.entry_key(&salt);
            if let Ok(plaintext) = aes256gcm_decrypt(&entry_key, &nonce, &body[HEADER_LEN..], &aad)
            {
                opened = Some(plaintext);
                break;
            }
        }
        if !matched_a_key {
            // No configured key claims this envelope. Not a decryption
            // failure, so the caller evicts and reports a miss.
            return Ok(None);
        }
        // A fingerprint we hold that will not authenticate is tampering
        // or corruption, never a miss. The message names only the public
        // fingerprint, never the material behind it.
        let Some(plaintext) = opened else {
            // Evict before reporting. `ttl_secs` rides in the clear, so
            // a forged record can name a lifetime measured in years and
            // the backing store will honour it: the entry never ages
            // out, and the read path logs the error and bypasses the
            // cache without recording a key to repopulate, so the
            // response phase never overwrites it either. One tampered
            // write per hot key would otherwise buy indefinite origin
            // load until an operator purges by hand. Deleting concedes
            // nothing, because whoever forged the record already holds
            // the write access needed to delete it. Note the asymmetry
            // this closes: the `Ok(None)` arm below self-heals only
            // because it evicts, and the stronger failure signal should
            // not be the one that persists. The `Err` still surfaces,
            // so the security event is not swallowed.
            let _ = self.inner.delete(key);
            return Err(anyhow!(
                "response-cache entry sealed under key {} failed authentication; entry evicted",
                hex::encode(fp)
            ));
        };

        let (headers, plain_body) = unframe_payload(&plaintext)?;
        Ok(Some(CachedResponse {
            status: stored.status,
            headers,
            body: plain_body,
            cached_at: stored.cached_at,
            ttl_secs: stored.ttl_secs,
        }))
    }

    /// Turn a raw lookup result into a decrypted one, evicting anything
    /// this store cannot open.
    fn decode(&self, key: &str, stored: Option<CachedResponse>) -> Result<Option<CachedResponse>> {
        let Some(stored) = stored else {
            return Ok(None);
        };
        match self.open(key, &stored)? {
            Some(entry) => Ok(Some(entry)),
            None => {
                // Written before encryption was turned on, or under a
                // key that is no longer listed. Dropping it is the only
                // honest move: this store cannot vouch for the bytes, and
                // leaving it means the same warning on every read until
                // the TTL runs out. The next write reseals under the
                // active key.
                let _ = self.inner.delete(key);
                tracing::warn!(
                    backend = self.inner.backend_name(),
                    key_id = %self.active.fingerprint_hex(),
                    "response-cache entry is not readable under any configured encryption key; evicted"
                );
                Ok(None)
            }
        }
    }
}

impl CacheStore for EncryptedCacheStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        self.decode(key, self.inner.get(key)?)
    }

    fn get_including_expired(&self, key: &str) -> Result<Option<CachedResponse>> {
        self.decode(key, self.inner.get_including_expired(key)?)
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        // No plaintext fallback. A seal failure fails the write.
        let sealed = self.seal(key, value)?;
        self.inner.put(key, &sealed)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }

    fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        // Cache keys are not encrypted, so prefix semantics are
        // unchanged and this delegates directly.
        self.inner.delete_prefix(prefix)
    }

    fn clear(&self) -> Result<()> {
        self.inner.clear()
    }

    fn backend_name(&self) -> &'static str {
        // Report the wrapped backend, not "encrypted". The admin API
        // reads this to decide whether prefix purge is available, and
        // that answer belongs to the real backend.
        self.inner.backend_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryCacheStore;
    use std::sync::Arc;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn entry() -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("set-cookie".into(), "session=super-secret-value".into()),
            ],
            body: br#"{"account":"acct_1234","balance":9000}"#.to_vec(),
            cached_at: now_secs(),
            ttl_secs: 300,
        }
    }

    fn material(seed: u8) -> CacheKeyMaterial {
        CacheKeyMaterial::new(vec![seed; 32]).expect("32 bytes is enough key material")
    }

    fn wrap(
        inner: Arc<dyn CacheStore>,
        active: CacheKeyMaterial,
        previous: Vec<CacheKeyMaterial>,
    ) -> EncryptedCacheStore {
        EncryptedCacheStore::new(inner, active, previous)
    }

    #[test]
    fn roundtrips_status_headers_and_body() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(1), Vec::new());

        let original = entry();
        store.put("k", &original).unwrap();
        let got = store.get("k").unwrap().expect("should hit");

        assert_eq!(got.status, original.status);
        assert_eq!(got.headers, original.headers);
        assert_eq!(got.body, original.body);
        assert_eq!(got.cached_at, original.cached_at);
        assert_eq!(got.ttl_secs, original.ttl_secs);
    }

    #[test]
    fn stored_bytes_contain_neither_body_nor_headers_in_the_clear() {
        // The whole point: what lands in the backing store must not
        // carry the response body or the response headers verbatim.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(2), Vec::new());
        store.put("k", &entry()).unwrap();

        let raw = inner.get("k").unwrap().expect("inner should hold a record");
        let haystack = raw.body.clone();
        for needle in [
            b"acct_1234".as_slice(),
            b"super-secret-value".as_slice(),
            b"set-cookie".as_slice(),
        ] {
            assert!(
                !haystack.windows(needle.len()).any(|w| w == needle),
                "plaintext {:?} found in the stored record",
                String::from_utf8_lossy(needle)
            );
        }
        assert!(
            raw.headers.is_empty(),
            "headers must be sealed into the payload, not stored alongside it"
        );
        assert_eq!(raw.body[..4], *b"SBRC", "envelope magic missing");
    }

    #[test]
    fn ttl_metadata_stays_readable_by_the_backing_store() {
        // The file and memcached backends compute expiry from
        // cached_at and ttl_secs, so those must not be sealed.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(3), Vec::new());
        let original = entry();
        store.put("k", &original).unwrap();

        let raw = inner.get("k").unwrap().expect("inner should hold a record");
        assert_eq!(raw.cached_at, original.cached_at);
        assert_eq!(raw.ttl_secs, original.ttl_secs);
        assert_eq!(raw.status, original.status);
    }

    #[test]
    fn two_seals_of_the_same_entry_produce_different_ciphertext() {
        // Per-entry salt plus per-entry nonce. Identical plaintext must
        // not produce identical bytes, otherwise the store leaks which
        // two URLs returned the same response.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(4), Vec::new());
        let original = entry();

        store.put("a", &original).unwrap();
        store.put("b", &original).unwrap();

        let a = inner.get("a").unwrap().unwrap().body;
        let b = inner.get("b").unwrap().unwrap().body;
        assert_ne!(a, b, "two seals of one plaintext must differ");
    }

    #[test]
    fn each_seal_draws_a_fresh_salt_and_nonce() {
        // Nonce reuse under one key is the one failure AES-GCM cannot
        // survive, so pin the two random fields directly rather than
        // inferring them from the ciphertext differing.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(23), Vec::new());
        let original = entry();

        let mut salts = std::collections::HashSet::new();
        let mut nonces = std::collections::HashSet::new();
        for i in 0..32 {
            let key = format!("k{i}");
            store.put(&key, &original).unwrap();
            let raw = inner.get(&key).unwrap().unwrap();
            // Salt occupies bytes 9..25, nonce 25..37.
            salts.insert(raw.body[9..25].to_vec());
            nonces.insert(raw.body[25..37].to_vec());
        }
        assert_eq!(salts.len(), 32, "every seal must draw a fresh salt");
        assert_eq!(nonces.len(), 32, "every seal must draw a fresh nonce");
    }

    #[test]
    fn a_ciphertext_cannot_be_replayed_under_another_cache_key() {
        // The cache key is bound into the AAD, so lifting a stored
        // record from one key to another must fail authentication
        // rather than serve the wrong response.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(5), Vec::new());
        store.put("victim", &entry()).unwrap();

        let lifted = inner.get("victim").unwrap().unwrap();
        inner.put("attacker", &lifted).unwrap();

        assert!(
            store.get("attacker").is_err(),
            "a relocated ciphertext must fail to authenticate"
        );
    }

    #[test]
    fn a_tampered_status_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(6), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.status = 500;
        inner.put("k", &stored).unwrap();

        assert!(
            store.get("k").is_err(),
            "status is bound into the AAD and must not be swappable"
        );
    }

    #[test]
    fn a_tampered_ttl_fails_authentication() {
        // ttl_secs rides in the clear so the backing stores can read it,
        // but it is AAD-bound: an attacker with write access to the
        // store must not be able to keep a sealed entry alive forever.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(24), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.ttl_secs = 86_400 * 365;
        inner.put("k", &stored).unwrap();

        assert!(store.get("k").is_err(), "ttl_secs must be AAD-bound");
    }

    #[test]
    fn a_tampered_cached_at_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(25), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.cached_at = stored.cached_at.saturating_add(10_000);
        inner.put("k", &stored).unwrap();

        assert!(store.get("k").is_err(), "cached_at must be AAD-bound");
    }

    #[test]
    fn a_tampered_body_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(7), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        let last = stored.body.len() - 1;
        stored.body[last] ^= 0xff;
        inner.put("k", &stored).unwrap();

        assert!(store.get("k").is_err(), "a flipped bit must be detected");
    }

    #[test]
    fn an_authentication_failure_evicts_the_poisoned_entry() {
        // The exact shared-store attack this decorator exists for: flip
        // one ciphertext byte and set the cleartext ttl_secs to a decade.
        // ttl_secs is AAD-bound, so every read fails to authenticate,
        // but the backing store honours the cleartext value, so nothing
        // ages the record out. The read path logs the error and bypasses
        // the cache without recording a key to repopulate, so the
        // response phase never overwrites it either. Unless the failed
        // read evicts, one forged write pins that key on origin fetches
        // until an operator purges by hand.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(27), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut poisoned = inner.get("k").unwrap().unwrap();
        let last = poisoned.body.len() - 1;
        poisoned.body[last] ^= 0xff;
        poisoned.ttl_secs = 86_400 * 365 * 10;
        inner.put("k", &poisoned).unwrap();

        assert!(
            store.get("k").is_err(),
            "the security event must still reach the caller"
        );
        assert!(
            inner.get("k").unwrap().is_none(),
            "the poisoned record must be gone from the backing store"
        );

        // With the record gone the next write repopulates the key, which
        // is the whole point: the cache heals instead of staying poisoned.
        store.put("k", &entry()).unwrap();
        let got = store
            .get("k")
            .unwrap()
            .expect("the key must be cacheable again after eviction");
        assert_eq!(got.body, entry().body);
    }

    #[test]
    fn an_unknown_envelope_version_is_a_miss_and_evicts() {
        // The version byte is the forward-compatibility hinge: a future
        // sbproxy writes version 2, an older binary reads it back and
        // must treat it as unreadable rather than guessing at the
        // layout. Same handling as any other envelope this store cannot
        // vouch for, eviction included.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(28), Vec::new());
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.body[MAGIC.len()] = VERSION + 1;
        inner.put("k", &stored).unwrap();

        assert!(
            store.get("k").unwrap().is_none(),
            "an unknown envelope version must be a miss, never a hit"
        );
        assert!(
            inner.get("k").unwrap().is_none(),
            "an unreadable version must be evicted like any other unreadable record"
        );
    }

    #[test]
    fn a_truncated_envelope_never_yields_plaintext() {
        // Two truncation shapes: shorter than the header (no envelope
        // this store can even parse) and a header with a stub of
        // ciphertext (parses, cannot authenticate). Neither may produce
        // a usable entry.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(26), Vec::new());

        store.put("stub", &entry()).unwrap();
        let mut stub = inner.get("stub").unwrap().unwrap();
        stub.body.truncate(HEADER_LEN + 3);
        inner.put("stub", &stub).unwrap();
        assert!(
            store.get("stub").is_err(),
            "a truncated ciphertext must fail authentication"
        );

        store.put("runt", &entry()).unwrap();
        let mut runt = inner.get("runt").unwrap().unwrap();
        runt.body.truncate(HEADER_LEN - 1);
        inner.put("runt", &runt).unwrap();
        assert!(
            store.get("runt").unwrap().is_none(),
            "a record too short to hold an envelope is a miss, never a hit"
        );
    }

    #[test]
    fn a_plaintext_record_is_evicted_not_served() {
        // The store was running unencrypted and encryption was just
        // turned on. Serving the legacy record would mask the fact that
        // this entry was never protected; the entry is dropped and the
        // next write reseals it.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        inner.put("legacy", &entry()).unwrap();

        let store = wrap(Arc::clone(&inner), material(8), Vec::new());
        assert!(store.get("legacy").unwrap().is_none());
        assert!(
            inner.get("legacy").unwrap().is_none(),
            "the unreadable record must be evicted so the next write reseals it"
        );
    }

    #[test]
    fn a_retired_key_still_opens_entries_it_sealed() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), material(9), Vec::new());
        old.put("k", &entry()).unwrap();

        // Rotate: the old key moves to previous_keys.
        let rotated = wrap(Arc::clone(&inner), material(10), vec![material(9)]);
        let got = rotated
            .get("k")
            .unwrap()
            .expect("retired key must still open");
        assert_eq!(got.body, entry().body);
    }

    #[test]
    fn dropping_a_key_from_the_rotation_list_retires_its_entries() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), material(11), Vec::new());
        old.put("k", &entry()).unwrap();

        // Second rotation: key 11 is no longer listed at all.
        let current = wrap(Arc::clone(&inner), material(12), vec![material(13)]);
        assert!(current.get("k").unwrap().is_none());
        assert!(
            inner.get("k").unwrap().is_none(),
            "an entry under an unlisted key must be evicted, not left to rot"
        );
    }

    #[test]
    fn a_write_reseals_under_the_active_key() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), material(14), Vec::new());
        old.put("k", &entry()).unwrap();

        let rotated = wrap(Arc::clone(&inner), material(15), vec![material(14)]);
        rotated.put("k", &entry()).unwrap();

        // Drop key 14 entirely: the resealed entry must still open.
        let narrowed = wrap(Arc::clone(&inner), material(15), Vec::new());
        assert!(narrowed.get("k").unwrap().is_some());
    }

    #[test]
    fn get_including_expired_decrypts_too() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(16), Vec::new());
        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(500),
            ttl_secs: 60,
        };
        store.put("k", &stale).unwrap();

        let got = store
            .get_including_expired("k")
            .unwrap()
            .expect("SWR read must decrypt");
        assert_eq!(got.body, b"stale");
    }

    #[test]
    fn an_empty_body_and_no_headers_roundtrip() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(17), Vec::new());
        let empty = CachedResponse {
            status: 204,
            headers: vec![],
            body: vec![],
            cached_at: now_secs(),
            ttl_secs: 60,
        };
        store.put("k", &empty).unwrap();
        let got = store.get("k").unwrap().expect("should hit");
        assert_eq!(got.status, 204);
        assert!(got.headers.is_empty());
        assert!(got.body.is_empty());
    }

    #[test]
    fn backend_name_reports_the_wrapped_backend() {
        // The admin API decides whether prefix purge is supported from
        // this string, so the decorator must be transparent here.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(inner, material(18), Vec::new());
        assert_eq!(store.backend_name(), "memory");
    }

    #[test]
    fn delete_and_clear_pass_through() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(19), Vec::new());
        store.put("a", &entry()).unwrap();
        store.put("b", &entry()).unwrap();

        store.delete("a").unwrap();
        assert!(inner.get("a").unwrap().is_none());

        store.clear().unwrap();
        assert!(inner.get("b").unwrap().is_none());
    }

    #[test]
    fn delete_prefix_passes_through_and_reports_the_count() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), material(20), Vec::new());
        store.put("ws:host:GET:/x:a:fp", &entry()).unwrap();
        store.put("ws:host:GET:/x::fp2", &entry()).unwrap();
        store.put("ws:host:GET:/y::fp", &entry()).unwrap();

        assert_eq!(store.delete_prefix("ws:host:GET:/x:").unwrap(), 2);
        assert!(store.get("ws:host:GET:/y::fp").unwrap().is_some());
    }

    #[test]
    fn short_key_material_is_rejected() {
        let err = CacheKeyMaterial::new(b"too-short".to_vec())
            .expect_err("15 bytes or fewer must be refused");
        assert!(
            err.to_string().contains("at least 16 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn distinct_material_yields_distinct_fingerprints() {
        assert_ne!(
            material(21).fingerprint_hex(),
            material(22).fingerprint_hex()
        );
        assert_eq!(material(21).fingerprint_hex().len(), 8);
    }

    /// How a `#[derive(Debug)]` regression would actually render key
    /// material: as a decimal byte list, not as hex. Checking only the
    /// hex form would let exactly the regression this test guards
    /// against walk straight past it.
    fn decimal_bytes(raw: &[u8]) -> String {
        format!("{raw:?}")
    }

    #[test]
    fn debug_output_never_carries_key_material() {
        // Key material must not reach a log line through Debug, on the
        // material itself or on the store that holds it. Both encodings
        // are checked: hex is how this file would leak it deliberately,
        // decimal is how a lost manual impl would leak it by accident.
        let raw = vec![0xABu8; 32];
        let raw_hex = hex::encode(&raw);
        let raw_decimal = decimal_bytes(&raw);
        let key = CacheKeyMaterial::new(raw).expect("32 bytes is enough");
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains(&raw_hex),
            "material leaked through Debug as hex: {rendered}"
        );
        assert!(
            !rendered.contains(&raw_decimal),
            "material leaked through Debug as bytes: {rendered}"
        );
        assert!(rendered.contains("[redacted]"), "unexpected: {rendered}");
        assert!(rendered.contains(&key.fingerprint_hex()));

        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(
            inner,
            CacheKeyMaterial::new(vec![0xCDu8; 32]).expect("32 bytes is enough"),
            vec![CacheKeyMaterial::new(vec![0xEFu8; 32]).expect("32 bytes is enough")],
        );
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(&hex::encode([0xCDu8; 32])));
        assert!(!rendered.contains(&hex::encode([0xEFu8; 32])));
        assert!(!rendered.contains(&decimal_bytes(&[0xCDu8; 32])));
        assert!(!rendered.contains(&decimal_bytes(&[0xEFu8; 32])));
        assert!(rendered.contains("[redacted]"), "unexpected: {rendered}");
    }
}
