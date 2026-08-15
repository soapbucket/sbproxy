//! At-rest encryption decorator for the response cache.
//!
//! Wraps any [`CacheStore`] and seals the response headers and body of
//! every entry with AES-256-GCM before they reach the backing store.
//! Because it is a decorator rather than a backend, the file, memcached,
//! redis, and memory stores all get encryption from one implementation,
//! and `backend_name` still reports the real backend so the admin API
//! keeps answering correctly about prefix-purge support.
//!
//! The envelope framing, key fingerprinting, per-entry salt and nonce,
//! and active-plus-retired rotation all live in
//! [`sbproxy_security::sealed_record`], which prompt persistence uses
//! too. What stays here is what is specific to a response cache: which
//! fields are sealed, what goes into the associated data, and how an
//! unreadable record is handled.
//!
//! # What is sealed and what is not
//!
//! `headers` and `body` are sealed. `generation`, `status`, `cached_at`, and
//! `ttl_secs` stay in the clear because the backing stores read them:
//! the file store writes the expiry into its 8-byte record header and
//! memcached needs a relative TTL on the `set` command. All four are
//! bound into the AEAD associated data, so they are visible but cannot
//! be altered without failing authentication. Binding `cached_at` and
//! `ttl_secs` matters as much as binding `status`: without it, anyone
//! with write access to the backing store could extend the lifetime of
//! a sealed entry indefinitely without ever touching the ciphertext.
//!
//! # Associated data, and the two envelope versions
//!
//! The AAD is the 37-byte envelope header (see
//! [`sbproxy_security::sealed_record`]) followed by a tail this module
//! builds. Version 2, which every new write uses, binds the origin:
//!
//! ```text
//! generation (8) | status (2) | cached_at (8) | ttl_secs (8)
//!                | origin length (4) | origin | cache key
//! ```
//!
//! Version 1, still read but no longer written, omits the origin and
//! omits `generation` when it is zero:
//!
//! ```text
//! [generation (8), when non-zero] | status (2) | cached_at (8)
//!                                 | ttl_secs (8) | cache key
//! ```
//!
//! Both are injective encodings: every field before the trailing
//! variable-width one is fixed-width, so two distinct tuples cannot
//! flatten to the same AAD. Binding the cache key means a stored record
//! cannot be lifted from one key to another and replayed. Binding the
//! origin means it cannot be lifted from one tenant to another either,
//! which matters precisely because two origins may be sealed under the
//! same master key.
//!
//! Entries written by a build that predates the origin binding keep
//! opening, because version 1 is still accepted on read. They reseal as
//! version 2 the next time they are written. Rolling *back* to a build
//! that only knows version 1 is safe in the other direction too: an
//! unknown version is treated as unreadable, so those entries are
//! evicted and refetched rather than misinterpreted.
//!
//! # Per-origin keys
//!
//! [`CacheKeyDirectory`] maps an origin to the key ring that seals and
//! opens its entries. An origin with no ring of its own uses the
//! store-wide one, which is the default and matches every config written
//! before per-origin keys existed. Cross-origin isolation does not depend
//! on that choice: the origin is authenticated either way, so an entry
//! sealed for one origin fails to open as another even when both inherit
//! the same master key. What per-origin keys add is key separation, so
//! one leaked key does not open every tenant's entries.
//!
//! A handle is bound to one origin at construction. The unbound handle
//! returned for the admin API supports `delete`, `delete_prefix`,
//! `clear`, and `backend_name` and refuses `get` / `put` /
//! `compare_and_swap`, because sealing without knowing the origin would
//! either omit the binding or guess at it. Purge therefore keeps working
//! unchanged: it is prefix-driven and never touches a key ring.
//!
//! # Nonces
//!
//! Every entry draws a fresh 16-byte salt and derives its own AES key
//! with HKDF-SHA256 from the operator's master material. The 96-bit
//! nonce is then random under a key that seals exactly one message, so
//! the NIST SP 800-38D limit of roughly 2^32 seals per key is never
//! approached regardless of cache write rate. A single long-lived key
//! with random nonces would hit that limit in days on a busy gateway.
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
//! Rotation is per ring, so one origin can rotate without touching any
//! other.
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

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sbproxy_security::sealed_record::{
    OpenOutcome, SealKey, SealKeyRing, SealScheme, SealedEnvelope,
};
use sbproxy_security::HkdfPurpose;

use super::{CacheStore, CachedResponse};

/// The response cache's envelope: magic `SBRC`, short for SBproxy
/// Response Cache.
///
/// The declared version is what new writes carry. Reads accept every
/// version this build knows, which today is 1 and 2.
///
/// `fingerprint_salt` is pinned to the exact bytes the pre-extraction
/// implementation used, so key ids and therefore stored envelopes stay
/// byte-identical across the refactor.
pub const SBRC_SCHEME: SealScheme = SealScheme::new(
    *b"SBRC",
    2,
    HkdfPurpose::ResponseCacheAtRest,
    b"sbproxy.response-cache.key-id.v1",
);

/// Envelope versions this build can read. Version 1 predates the origin
/// binding in the associated data; version 2 carries it.
const ACCEPTED_VERSIONS: [u8; 2] = [1, 2];

/// Origin binding used by a handle that is not scoped to any origin.
///
/// Never sealed with: an unscoped handle refuses to seal or open at all.
/// The constant exists so the refusal message can name the situation.
const UNSCOPED: &str = "<unscoped>";

/// Emitted once per process when the decorator is asked to encrypt an
/// in-process cache, so a config that moves between backends does not
/// leave an operator believing memory entries are protected at rest.
static MEMORY_BACKEND_ADVISORY: std::sync::Once = std::sync::Once::new();

/// Build a key ring for the response cache from resolved key material.
///
/// `active` seals and opens; each entry of `previous` opens only.
/// Material shorter than 16 bytes is refused rather than stretched.
pub fn cache_key_ring(active: Vec<u8>, previous: Vec<Vec<u8>>) -> Result<SealKeyRing> {
    let active = SealKey::new(SBRC_SCHEME, active)?;
    let previous = previous
        .into_iter()
        .map(|material| SealKey::new(SBRC_SCHEME, material))
        .collect::<Result<Vec<_>>>()?;
    SealKeyRing::new(SBRC_SCHEME, active, previous)
}

/// Which key ring seals and opens each origin's entries.
///
/// The store-wide ring is the fallback. An origin listed in `per_origin`
/// uses its own instead, which is what turns cross-tenant cache
/// isolation from a key-namespacing property into a key-separation one.
#[derive(Debug)]
pub struct CacheKeyDirectory {
    /// Ring for origins with none of their own. `None` when the operator
    /// set `per_origin_keys: required`, in which case every caching
    /// origin was made to declare a key at boot and there is nothing to
    /// fall back to.
    default: Option<Arc<SealKeyRing>>,
    per_origin: HashMap<String, Arc<SealKeyRing>>,
}

impl CacheKeyDirectory {
    /// A directory with one store-wide ring and no per-origin overrides.
    pub fn single(ring: SealKeyRing) -> Self {
        Self {
            default: Some(Arc::new(ring)),
            per_origin: HashMap::new(),
        }
    }

    /// A directory with an optional store-wide ring plus per-origin
    /// overrides keyed by origin id.
    pub fn new(default: Option<SealKeyRing>, per_origin: HashMap<String, SealKeyRing>) -> Self {
        Self {
            default: default.map(Arc::new),
            per_origin: per_origin
                .into_iter()
                .map(|(origin, ring)| (origin, Arc::new(ring)))
                .collect(),
        }
    }

    /// The ring that seals and opens `origin`'s entries.
    fn ring_for(&self, origin: &str) -> Option<&Arc<SealKeyRing>> {
        self.per_origin.get(origin).or(self.default.as_ref())
    }
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

/// The associated-data tail for one entry, for the given envelope
/// version. The envelope header is prepended by the sealing helper.
///
/// Version 2 always binds the generation and the origin. Version 1,
/// which this build reads but never writes, reproduces the historical
/// shape exactly, including omitting a zero generation: envelopes
/// written before cache generations existed deserialize with generation
/// zero and used the shorter tail.
fn aad_tail(
    version: u8,
    origin: &str,
    generation: u64,
    status: u16,
    cached_at: u64,
    ttl_secs: u64,
    key: &str,
) -> Vec<u8> {
    let mut tail = Vec::with_capacity(8 + 2 + 8 + 8 + 4 + origin.len() + key.len());
    if version >= 2 || generation != 0 {
        tail.extend_from_slice(&generation.to_be_bytes());
    }
    tail.extend_from_slice(&status.to_be_bytes());
    tail.extend_from_slice(&cached_at.to_be_bytes());
    tail.extend_from_slice(&ttl_secs.to_be_bytes());
    if version >= 2 {
        // Length-prefixed so the origin and the cache key that follows
        // it cannot be re-split at a different boundary.
        let len = u32::try_from(origin.len()).unwrap_or(u32::MAX);
        tail.extend_from_slice(&len.to_be_bytes());
        tail.extend_from_slice(origin.as_bytes());
    }
    tail.extend_from_slice(key.as_bytes());
    tail
}

/// A [`CacheStore`] that seals every payload before it reaches the
/// wrapped store.
///
/// A handle is bound to one origin, or to none. Use
/// [`EncryptedCacheStore::scoped`] on the data path and
/// [`EncryptedCacheStore::unscoped`] for the admin purge path.
pub struct EncryptedCacheStore {
    inner: Arc<dyn CacheStore>,
    keys: Arc<CacheKeyDirectory>,
    /// `None` on the admin handle, which never seals or opens.
    origin: Option<Arc<str>>,
}

impl std::fmt::Debug for EncryptedCacheStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedCacheStore")
            .field("backend", &self.inner.backend_name())
            .field(
                "origin",
                &self.origin.as_deref().unwrap_or(UNSCOPED).to_string(),
            )
            .field(
                "key_id",
                &self
                    .ring()
                    .map(|ring| ring.active_key_id())
                    .unwrap_or_else(|| "none".to_string()),
            )
            .field("key_material", &"[redacted]")
            .finish()
    }
}

impl EncryptedCacheStore {
    /// Wrap `inner` with a handle bound to `origin`.
    ///
    /// Infallible by construction: a [`SealKeyRing`] cannot exist without
    /// key material that passed the length check, so there is no state in
    /// which this store comes up without a usable key. It has no
    /// unencrypted mode to fall back to.
    pub fn scoped(inner: Arc<dyn CacheStore>, keys: Arc<CacheKeyDirectory>, origin: &str) -> Self {
        advise_if_memory(&inner);
        Self {
            inner,
            keys,
            origin: Some(Arc::from(origin)),
        }
    }

    /// Wrap `inner` with a handle that can purge but not read or write.
    ///
    /// This is what the admin cache API holds. Purge is prefix-driven and
    /// independent of which key sealed a value, so it needs no origin;
    /// sealing without one would either omit the origin binding or invent
    /// a value for it, and both are worse than refusing.
    pub fn unscoped(inner: Arc<dyn CacheStore>, keys: Arc<CacheKeyDirectory>) -> Self {
        advise_if_memory(&inner);
        Self {
            inner,
            keys,
            origin: None,
        }
    }

    /// The origin this handle is bound to, or an error naming the misuse.
    fn origin(&self) -> Result<&str> {
        self.origin.as_deref().ok_or_else(|| {
            anyhow!(
                "response-cache read/write attempted through the unscoped store handle; \
                 the data path must use the per-origin handle so the entry is bound to \
                 its origin"
            )
        })
    }

    /// The key ring for this handle's origin.
    fn ring(&self) -> Option<&Arc<SealKeyRing>> {
        self.keys
            .ring_for(self.origin.as_deref().unwrap_or(UNSCOPED))
    }

    /// The key ring for this handle's origin, or an error naming the
    /// origin that has none.
    fn require_ring(&self, origin: &str) -> Result<&Arc<SealKeyRing>> {
        self.keys.ring_for(origin).ok_or_else(|| {
            anyhow!(
                "no response-cache encryption key is configured for origin '{origin}'; \
                 declare one under origins.{origin}.response_cache.encryption.key or set \
                 proxy.response_cache_store.encryption.per_origin_keys to inherit"
            )
        })
    }

    /// Seal an entry under the active key of this origin's ring.
    fn seal(&self, key: &str, entry: &CachedResponse) -> Result<CachedResponse> {
        let origin = self.origin()?;
        let ring = self.require_ring(origin)?;
        let tail = aad_tail(
            SBRC_SCHEME.version(),
            origin,
            entry.generation,
            entry.status,
            entry.cached_at,
            entry.ttl_secs,
            key,
        );
        let body = ring
            .seal(&frame_payload(entry)?, &tail)
            .context("seal response-cache entry")?;
        Ok(CachedResponse {
            generation: entry.generation,
            status: entry.status,
            headers: Vec::new(),
            body,
            cached_at: entry.cached_at,
            ttl_secs: entry.ttl_secs,
            swr_secs: None,
            config_fp: entry.config_fp.clone(),
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
        let origin = self.origin()?;
        let Some(envelope) = SealedEnvelope::parse(SBRC_SCHEME, &stored.body, |v| {
            ACCEPTED_VERSIONS.contains(&v)
        }) else {
            // No envelope, or a version this build does not know. Not a
            // decryption failure, so the caller evicts and reports a miss.
            return Ok(None);
        };
        let ring = self.require_ring(origin)?;
        let tail = aad_tail(
            envelope.version,
            origin,
            stored.generation,
            stored.status,
            stored.cached_at,
            stored.ttl_secs,
            key,
        );

        let plaintext = match ring.open(&envelope, &tail) {
            OpenOutcome::Opened(plaintext) => plaintext,
            OpenOutcome::NoMatchingKey => return Ok(None),
            OpenOutcome::AuthFailed => {
                // Evict before reporting. `ttl_secs` rides in the clear,
                // so a forged record can name a lifetime measured in
                // years and the backing store will honour it: the entry
                // never ages out, and the read path logs the error and
                // bypasses the cache without recording a key to
                // repopulate, so the response phase never overwrites it
                // either. One tampered write per hot key would otherwise
                // buy indefinite origin load until an operator purges by
                // hand. Deleting concedes nothing, because whoever forged
                // the record already holds the write access needed to
                // delete it. Note the asymmetry this closes: the
                // `Ok(None)` arms above self-heal only because the caller
                // evicts, and the stronger failure signal should not be
                // the one that persists. The `Err` still surfaces, so the
                // security event is not swallowed.
                //
                // The message names only the public fingerprint, never
                // the material behind it.
                let fingerprint = envelope.fingerprint_hex();
                let _ = self.inner.delete(key);
                return Err(anyhow!(
                    "response-cache entry for origin '{origin}' sealed under key {fingerprint} \
                     failed authentication; entry evicted"
                ));
            }
        };

        let (headers, plain_body) = unframe_payload(&plaintext)?;
        Ok(Some(CachedResponse {
            generation: stored.generation,
            status: stored.status,
            headers,
            body: plain_body,
            cached_at: stored.cached_at,
            ttl_secs: stored.ttl_secs,
            swr_secs: None,
            config_fp: stored.config_fp.clone(),
        }))
    }

    /// Turn a raw lookup result into a decrypted one, evicting anything
    /// this store cannot open.
    fn decode(&self, key: &str, stored: Option<CachedResponse>) -> Result<Option<CachedResponse>> {
        // Check the binding before the miss short-circuit, so an unscoped
        // read reports the misuse whether or not the key happens to be
        // populated. A misuse that only surfaces on a hit is a misuse
        // that ships.
        self.origin()?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        match self.open(key, &stored)? {
            Some(entry) => Ok(Some(entry)),
            None => {
                // Written before encryption was turned on, under a key
                // that is no longer listed, or by a newer build using an
                // envelope version this one does not know. Dropping it is
                // the only honest move: this store cannot vouch for the
                // bytes, and leaving it means the same warning on every
                // read until the TTL runs out. The next write reseals
                // under the active key.
                let _ = self.inner.delete(key);
                tracing::warn!(
                    backend = self.inner.backend_name(),
                    origin = self.origin.as_deref().unwrap_or(UNSCOPED),
                    "response-cache entry is not readable under any configured encryption key; evicted"
                );
                Ok(None)
            }
        }
    }
}

/// Warn once when encryption is layered over the in-process backend.
///
/// Allowed on purpose so a config can move between backends without
/// editing the encryption block, but say plainly that it buys nothing:
/// the plaintext lives in this process either way, and there is no disk
/// or wire to protect.
fn advise_if_memory(inner: &Arc<dyn CacheStore>) {
    if inner.backend_name() == "memory" {
        MEMORY_BACKEND_ADVISORY.call_once(|| {
            tracing::warn!(
                backend = "memory",
                "response-cache encryption is enabled over the in-process memory backend; \
                 entries never leave this process, so this protects nothing at rest"
            );
        });
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

    fn compare_and_swap(
        &self,
        key: &str,
        expected: &CachedResponse,
        replacement: &CachedResponse,
    ) -> Result<bool> {
        let Some(raw_expected) = self.inner.get_including_expired(key)? else {
            return Ok(false);
        };
        let Some(current) = self.open(key, &raw_expected)? else {
            return Ok(false);
        };
        if current != *expected {
            return Ok(false);
        }
        let sealed = self.seal(key, replacement)?;
        self.inner.compare_and_swap(key, &raw_expected, &sealed)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }

    fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        // Cache keys are not encrypted, so prefix semantics are
        // unchanged and this delegates directly. This is what keeps
        // origin-scoped purge working regardless of which key sealed
        // each value.
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

    fn durability(&self) -> crate::at_rest::CacheDurability {
        // The decorator changes what the backend stores, not where.
        self.inner.durability()
    }

    fn encrypts_at_rest(&self) -> bool {
        // Unconditionally true: there is no plaintext write path, and a
        // handle cannot exist without a key directory behind it.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryCacheStore;
    use sbproxy_security::sealed_record::HEADER_LEN;
    use std::sync::Arc;

    /// Origin every single-tenant test seals under. Any non-empty string
    /// works; naming it keeps the per-origin tests below legible.
    const ORIGIN: &str = "api.example.com";

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn entry() -> CachedResponse {
        CachedResponse {
            generation: crate::store::new_cache_generation(),
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("set-cookie".into(), "session=super-secret-value".into()),
                ("etag".into(), r#"W/"encrypted-v1""#.into()),
                (
                    "last-modified".into(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".into(),
                ),
            ],
            body: br#"{"account":"acct_1234","balance":9000}"#.to_vec(),
            cached_at: now_secs(),
            ttl_secs: 300,
            swr_secs: None,
            config_fp: String::new(),
        }
    }

    fn ring(seed: u8, previous: &[u8]) -> SealKeyRing {
        cache_key_ring(
            vec![seed; 32],
            previous.iter().map(|s| vec![*s; 32]).collect(),
        )
        .expect("32 bytes is enough key material")
    }

    /// A store scoped to [`ORIGIN`] with one store-wide ring.
    fn wrap(inner: Arc<dyn CacheStore>, active: u8, previous: &[u8]) -> EncryptedCacheStore {
        EncryptedCacheStore::scoped(
            inner,
            Arc::new(CacheKeyDirectory::single(ring(active, previous))),
            ORIGIN,
        )
    }

    #[test]
    fn roundtrips_status_headers_and_body() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 1, &[]);

        let original = entry();
        store.put("k", &original).unwrap();
        let got = store.get("k").unwrap().expect("should hit");

        assert_eq!(got.status, original.status);
        assert_eq!(got.generation, original.generation);
        assert_eq!(got.headers, original.headers);
        assert_eq!(got.body, original.body);
        assert_eq!(got.cached_at, original.cached_at);
        assert_eq!(got.ttl_secs, original.ttl_secs);
        assert_eq!(got.etag(), Some(r#"W/"encrypted-v1""#));
        assert_eq!(got.last_modified(), Some("Sun, 06 Nov 1994 08:49:37 GMT"));
    }

    #[test]
    fn stored_bytes_contain_neither_body_nor_headers_in_the_clear() {
        // The whole point: what lands in the backing store must not
        // carry the response body or the response headers verbatim.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 2, &[]);
        store.put("k", &entry()).unwrap();

        let raw = inner.get("k").unwrap().expect("inner should hold a record");
        let haystack = raw.body.clone();
        for needle in [
            b"acct_1234".as_slice(),
            b"super-secret-value".as_slice(),
            b"set-cookie".as_slice(),
            b"encrypted-v1".as_slice(),
            b"last-modified".as_slice(),
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
        assert_eq!(raw.body[4], 2, "new writes must carry envelope version 2");
    }

    #[test]
    fn the_origin_is_not_written_in_the_clear() {
        // The origin is authenticated, not encrypted, but it still lives
        // only in the AAD: it must not be appended to the stored bytes.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 30, &[]);
        store.put("k", &entry()).unwrap();
        let raw = inner.get("k").unwrap().unwrap();
        let needle = ORIGIN.as_bytes();
        assert!(!raw.body.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn ttl_metadata_stays_readable_by_the_backing_store() {
        // The file and memcached backends compute expiry from
        // cached_at and ttl_secs, so those must not be sealed.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 3, &[]);
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
        let store = wrap(Arc::clone(&inner), 4, &[]);
        let original = entry();

        store.put("a", &original).unwrap();
        store.put("b", &original).unwrap();

        let a = inner.get("a").unwrap().unwrap().body;
        let b = inner.get("b").unwrap().unwrap().body;
        assert_ne!(a, b, "two seals of one plaintext must differ");
    }

    #[test]
    fn conditional_replace_preserves_a_newer_encrypted_entry() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 12, &[]);
        let mut stale = entry();
        stale.generation = 1;
        store.put("k", &stale).unwrap();

        let mut foreground = entry();
        foreground.generation = 2;
        foreground.body = b"foreground".to_vec();
        store.put("k", &foreground).unwrap();

        let mut background = entry();
        background.generation = 3;
        background.body = b"background".to_vec();
        assert!(!store.compare_and_swap("k", &stale, &background).unwrap());
        assert_eq!(
            store.get("k").unwrap().expect("foreground entry").body,
            b"foreground"
        );
    }

    #[test]
    fn each_seal_draws_a_fresh_salt_and_nonce() {
        // Nonce reuse under one key is the one failure AES-GCM cannot
        // survive, so pin the two random fields directly rather than
        // inferring them from the ciphertext differing.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 23, &[]);
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
        let store = wrap(Arc::clone(&inner), 5, &[]);
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
        let store = wrap(Arc::clone(&inner), 6, &[]);
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
    fn a_tampered_generation_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 31, &[]);
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.generation = stored.generation.wrapping_add(2);
        inner.put("k", &stored).unwrap();

        assert!(
            store.get("k").is_err(),
            "generation is bound into the AAD and must not be swappable"
        );
    }

    #[test]
    fn a_tampered_ttl_fails_authentication() {
        // ttl_secs rides in the clear so the backing stores can read it,
        // but it is AAD-bound: an attacker with write access to the
        // store must not be able to keep a sealed entry alive forever.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 24, &[]);
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.ttl_secs = 86_400 * 365;
        inner.put("k", &stored).unwrap();

        assert!(store.get("k").is_err(), "ttl_secs must be AAD-bound");
    }

    #[test]
    fn a_tampered_cached_at_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 25, &[]);
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.cached_at = stored.cached_at.saturating_add(10_000);
        inner.put("k", &stored).unwrap();

        assert!(store.get("k").is_err(), "cached_at must be AAD-bound");
    }

    #[test]
    fn a_tampered_body_fails_authentication() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 7, &[]);
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
        let store = wrap(Arc::clone(&inner), 27, &[]);
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
        // sbproxy writes version 3, an older binary reads it back and
        // must treat it as unreadable rather than guessing at the
        // layout. Same handling as any other envelope this store cannot
        // vouch for, eviction included.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 28, &[]);
        store.put("k", &entry()).unwrap();

        let mut stored = inner.get("k").unwrap().unwrap();
        stored.body[4] = SBRC_SCHEME.version() + 1;
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
        let store = wrap(Arc::clone(&inner), 26, &[]);

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

        let store = wrap(Arc::clone(&inner), 8, &[]);
        assert!(store.get("legacy").unwrap().is_none());
        assert!(
            inner.get("legacy").unwrap().is_none(),
            "the unreadable record must be evicted so the next write reseals it"
        );
    }

    #[test]
    fn a_retired_key_still_opens_entries_it_sealed() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), 9, &[]);
        old.put("k", &entry()).unwrap();

        // Rotate: the old key moves to previous_keys.
        let rotated = wrap(Arc::clone(&inner), 10, &[9]);
        let got = rotated
            .get("k")
            .unwrap()
            .expect("retired key must still open");
        assert_eq!(got.body, entry().body);
    }

    #[test]
    fn dropping_a_key_from_the_rotation_list_retires_its_entries() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), 11, &[]);
        old.put("k", &entry()).unwrap();

        // Second rotation: key 11 is no longer listed at all.
        let current = wrap(Arc::clone(&inner), 12, &[13]);
        assert!(current.get("k").unwrap().is_none());
        assert!(
            inner.get("k").unwrap().is_none(),
            "an entry under an unlisted key must be evicted, not left to rot"
        );
    }

    #[test]
    fn a_write_reseals_under_the_active_key() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let old = wrap(Arc::clone(&inner), 14, &[]);
        old.put("k", &entry()).unwrap();

        let rotated = wrap(Arc::clone(&inner), 15, &[14]);
        rotated.put("k", &entry()).unwrap();

        // Drop key 14 entirely: the resealed entry must still open.
        let narrowed = wrap(Arc::clone(&inner), 15, &[]);
        assert!(narrowed.get("k").unwrap().is_some());
    }

    #[test]
    fn get_including_expired_decrypts_too() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 16, &[]);
        let stale = CachedResponse {
            generation: 0,
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(500),
            ttl_secs: 60,
            swr_secs: None,
            config_fp: String::new(),
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
        let store = wrap(Arc::clone(&inner), 17, &[]);
        let empty = CachedResponse {
            generation: 0,
            status: 204,
            headers: vec![],
            body: vec![],
            cached_at: now_secs(),
            ttl_secs: 60,
            swr_secs: None,
            config_fp: String::new(),
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
        let store = wrap(inner, 18, &[]);
        assert_eq!(store.backend_name(), "memory");
    }

    #[test]
    fn delete_and_clear_pass_through() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = wrap(Arc::clone(&inner), 19, &[]);
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
        let store = wrap(Arc::clone(&inner), 20, &[]);
        store.put("ws:host:GET:/x:a:fp", &entry()).unwrap();
        store.put("ws:host:GET:/x::fp2", &entry()).unwrap();
        store.put("ws:host:GET:/y::fp", &entry()).unwrap();

        assert_eq!(store.delete_prefix("ws:host:GET:/x:").unwrap(), 2);
        assert!(store.get("ws:host:GET:/y::fp").unwrap().is_some());
    }

    #[test]
    fn short_key_material_is_rejected() {
        let err = cache_key_ring(b"too-short".to_vec(), Vec::new())
            .expect_err("15 bytes must be refused");
        assert!(
            err.to_string().contains("at least 16 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn distinct_material_yields_distinct_fingerprints() {
        assert_ne!(ring(21, &[]).active_key_id(), ring(22, &[]).active_key_id());
        assert_eq!(ring(21, &[]).active_key_id().len(), 8);
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
        // Key material must not reach a log line through Debug on the
        // store that holds it. Both encodings are checked: hex is how
        // this file would leak it deliberately, decimal is how a lost
        // manual impl would leak it by accident.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = EncryptedCacheStore::scoped(
            inner,
            Arc::new(CacheKeyDirectory::single(
                cache_key_ring(vec![0xCDu8; 32], vec![vec![0xEFu8; 32]]).unwrap(),
            )),
            ORIGIN,
        );
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(&hex::encode([0xCDu8; 32])));
        assert!(!rendered.contains(&hex::encode([0xEFu8; 32])));
        assert!(!rendered.contains(&decimal_bytes(&[0xCDu8; 32])));
        assert!(!rendered.contains(&decimal_bytes(&[0xEFu8; 32])));
        assert!(rendered.contains("[redacted]"), "unexpected: {rendered}");
    }

    // --- Per-origin keys ---

    fn directory(default: Option<u8>, per_origin: &[(&str, u8, &[u8])]) -> Arc<CacheKeyDirectory> {
        Arc::new(CacheKeyDirectory::new(
            default.map(|seed| ring(seed, &[])),
            per_origin
                .iter()
                .map(|(origin, seed, prev)| ((*origin).to_string(), ring(*seed, prev)))
                .collect(),
        ))
    }

    #[test]
    fn an_entry_sealed_for_one_origin_does_not_open_as_another() {
        // The multi-tenant property the whole per-origin story exists
        // for. Both origins hold their own key here, so the failure is
        // over-determined; the inherit case below is the sharper test.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(None, &[("tenant-a", 40, &[]), ("tenant-b", 41, &[])]);
        let a = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-a");
        let b = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-b");

        a.put("shared-key", &entry()).unwrap();
        // B holds a different master, so it cannot even claim the
        // envelope: a miss, and the record is evicted.
        assert!(b.get("shared-key").unwrap().is_none());
    }

    #[test]
    fn two_origins_inheriting_one_key_still_cannot_read_each_other() {
        // This is the property that makes `inherit` a safe default. Both
        // origins derive from the same master, so the fingerprint matches
        // and the ring does attempt the open. Only the origin binding in
        // the AAD stops it, which is why the outcome is an authentication
        // failure rather than a miss.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(Some(42), &[]);
        let a = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-a");
        let b = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-b");

        a.put("shared-key", &entry()).unwrap();
        let err = b
            .get("shared-key")
            .expect_err("a cross-origin read must not return plaintext");
        assert!(
            err.to_string().contains("tenant-b"),
            "the error should name the origin that tried to read: {err}"
        );
        // And A's own read still works before the eviction fires... which
        // it does not, because the failed read evicted. That is the
        // documented trade: an unauthenticated record is always dropped.
        assert!(inner.get("shared-key").unwrap().is_none());
    }

    #[test]
    fn an_origin_key_overrides_the_store_wide_one() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(Some(43), &[("tenant-a", 44, &[])]);
        let scoped = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-a");
        scoped.put("k", &entry()).unwrap();

        let raw = inner.get("k").unwrap().unwrap();
        let fingerprint = hex::encode(&raw.body[5..9]);
        assert_eq!(fingerprint, ring(44, &[]).active_key_id());
        assert_ne!(fingerprint, ring(43, &[]).active_key_id());
    }

    #[test]
    fn an_origin_without_its_own_key_inherits_the_store_wide_one() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(Some(45), &[("tenant-a", 46, &[])]);
        let other = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-z");
        other.put("k", &entry()).unwrap();

        let raw = inner.get("k").unwrap().unwrap();
        assert_eq!(hex::encode(&raw.body[5..9]), ring(45, &[]).active_key_id());
        assert_eq!(other.get("k").unwrap().unwrap().body, entry().body);
    }

    #[test]
    fn an_origin_with_no_key_and_no_store_wide_key_fails_loud() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(None, &[("tenant-a", 47, &[])]);
        let orphan = EncryptedCacheStore::scoped(inner, keys, "tenant-z");
        let err = orphan
            .put("k", &entry())
            .expect_err("there is no key that could seal this");
        assert!(err.to_string().contains("tenant-z"), "unexpected: {err}");
    }

    #[test]
    fn per_origin_rotation_opens_entries_sealed_under_that_origins_previous_key() {
        // Rotating one origin must not disturb any other, and the
        // origin's own retired key must keep opening what it sealed.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let before = directory(Some(50), &[("tenant-a", 51, &[]), ("tenant-b", 52, &[])]);
        let a_before =
            EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&before), "tenant-a");
        let b_before =
            EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&before), "tenant-b");
        a_before.put("a-key", &entry()).unwrap();
        b_before.put("b-key", &entry()).unwrap();

        // Only tenant-a rotates: 53 becomes active, 51 retires.
        let after = directory(Some(50), &[("tenant-a", 53, &[51]), ("tenant-b", 52, &[])]);
        let a_after =
            EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&after), "tenant-a");
        let b_after =
            EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&after), "tenant-b");

        assert_eq!(
            a_after
                .get("a-key")
                .unwrap()
                .expect("retired key opens")
                .body,
            entry().body,
        );
        assert_eq!(
            b_after.get("b-key").unwrap().expect("untouched").body,
            entry().body,
        );

        // New writes for tenant-a carry the new fingerprint.
        a_after.put("a-key", &entry()).unwrap();
        let raw = inner.get("a-key").unwrap().unwrap();
        assert_eq!(hex::encode(&raw.body[5..9]), ring(53, &[]).active_key_id());
    }

    #[test]
    fn purge_works_across_origins_without_any_key() {
        // Purge is prefix-driven and never opens a value, so the admin
        // handle can clear entries sealed under keys it holds and keys
        // it does not.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(None, &[("tenant-a", 60, &[]), ("tenant-b", 61, &[])]);
        let a = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-a");
        let b = EncryptedCacheStore::scoped(Arc::clone(&inner), Arc::clone(&keys), "tenant-b");
        a.put(":a.example:GET:/x::fp", &entry()).unwrap();
        b.put(":b.example:GET:/x::fp", &entry()).unwrap();

        let admin = EncryptedCacheStore::unscoped(Arc::clone(&inner), Arc::clone(&keys));
        assert_eq!(admin.delete_prefix(":a.example:").unwrap(), 1);
        assert!(inner.get(":a.example:GET:/x::fp").unwrap().is_none());
        assert!(inner.get(":b.example:GET:/x::fp").unwrap().is_some());

        admin.clear().unwrap();
        assert!(inner.get(":b.example:GET:/x::fp").unwrap().is_none());
    }

    #[test]
    fn the_unscoped_handle_refuses_to_read_or_write() {
        // Sealing without an origin would either omit the binding or
        // invent a value for it. Both are worse than an error naming the
        // misuse, because either would produce entries that the scoped
        // handles cannot read.
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let keys = directory(Some(62), &[]);
        let admin = EncryptedCacheStore::unscoped(inner, keys);

        for err in [
            admin.put("k", &entry()).unwrap_err(),
            admin.get("k").unwrap_err(),
            admin.get_including_expired("k").unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("per-origin handle"),
                "unexpected: {err}"
            );
        }
    }

    // --- Wire-format compatibility ---

    /// Master key material behind the fixtures below. The fixtures were
    /// produced by the pre-extraction implementation, before the
    /// sealed-record helper existed and before the origin was bound into
    /// the associated data.
    const FIXTURE_MATERIAL: &[u8] = b"sbproxy-fixture-master-key-0001";

    fn fixture_entry() -> CachedResponse {
        CachedResponse {
            generation: 7,
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("x-fixture".into(), "sbrc-v1".into()),
            ],
            body: br#"{"fixture":"sbrc-v1","ok":true}"#.to_vec(),
            cached_at: 1_700_000_000,
            ttl_secs: 300,
            swr_secs: None,
            config_fp: String::new(),
        }
    }

    fn fixture_store(inner: Arc<dyn CacheStore>) -> EncryptedCacheStore {
        EncryptedCacheStore::scoped(
            inner,
            Arc::new(CacheKeyDirectory::single(
                cache_key_ring(FIXTURE_MATERIAL.to_vec(), Vec::new()).unwrap(),
            )),
            ORIGIN,
        )
    }

    /// Load a hex fixture into the backing store under `key` and read it
    /// back through the decorator.
    fn open_fixture(
        hex_bytes: &str,
        key: &str,
        mut stored: CachedResponse,
    ) -> Option<CachedResponse> {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        stored.body = hex::decode(hex_bytes).expect("fixture is valid hex");
        stored.headers = Vec::new();
        inner.put(key, &stored).unwrap();
        fixture_store(inner).get_including_expired(key).unwrap()
    }

    #[test]
    fn a_version_1_entry_written_before_the_refactor_still_opens() {
        // The compatibility promise in one test. These bytes were sealed
        // by the implementation that predates both the sealed-record
        // extraction and the origin binding; they must still open, and
        // must yield exactly the headers and body that went in.
        const SBRC_V1: &str = "5342524301def11a206cefff729c160b221b122c7e468648a18686e7a364e291\
                               25a11ff770f1253f2048b770fc05f435fce4f789c98da113e0279c07b9046b2a\
                               7f35f552e004333330e2c0a3b0703de86a8e5f1206aaee450bbdfb65f7bd7a46\
                               2901c43bad16a53802b5700f7209440dd2f31033df4c484208314b3bad6ed670\
                               c123f17ce2c4a0d043bc71902c6a3f21b825b9d9";
        let opened = open_fixture(
            SBRC_V1,
            ":fixture.example:GET:/v1/thing::deadbeef",
            fixture_entry(),
        )
        .expect("a version-1 entry must still open");
        assert_eq!(opened.headers, fixture_entry().headers);
        assert_eq!(opened.body, fixture_entry().body);
        assert_eq!(opened.status, 200);
        assert_eq!(opened.generation, 7);
    }

    #[test]
    fn a_version_1_entry_with_generation_zero_still_opens() {
        // Envelopes written before cache generations existed use a
        // shorter associated-data tail that omits the generation
        // entirely. That shape has to survive the refactor too.
        const SBRC_V1_GEN0: &str =
            "5342524301def11a20d13b2e2bc17b16f44a55255ec2806ce50fb713292c42fe\
                                    7f14442cd838163e93dae7ade487684e470dcf0c1faca7a1bf5aafd8fec8108\
                                    e622944e70ef94042e64e12b112da5388365ccf1a407e44e9d5e254e5115d36\
                                    ba203907c96eda6867877b4c1b1504ec34b6f34162b6aa3f7df1ab920fbff50\
                                    c396e0e43f81e57f82d841258e0b1569715ea8eb6f4";
        let mut stored = fixture_entry();
        stored.generation = 0;
        let opened = open_fixture(SBRC_V1_GEN0, ":legacy.example:GET:/old::cafe", stored)
            .expect("a generation-zero version-1 entry must still open");
        assert_eq!(opened.headers, fixture_entry().headers);
        assert_eq!(opened.body, fixture_entry().body);
        assert_eq!(opened.generation, 0);
    }

    #[test]
    fn the_fixture_key_fingerprint_is_unchanged_by_the_refactor() {
        // The fingerprint is derived from the master material and is
        // written into every envelope. If the extraction had changed how
        // it is derived, every stored entry would stop being claimable
        // by its own key. The four bytes at offset 5 of the fixture are
        // the assertion.
        let ring = cache_key_ring(FIXTURE_MATERIAL.to_vec(), Vec::new()).unwrap();
        assert_eq!(ring.active_key_id(), "def11a20");
    }

    #[test]
    fn a_version_1_entry_reseals_as_version_2_on_the_next_write() {
        let inner: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(0));
        let store = fixture_store(Arc::clone(&inner));
        store.put("k", &entry()).unwrap();
        assert_eq!(inner.get("k").unwrap().unwrap().body[4], 2);
    }
}
