//! WOR-2673: object-storage [`CacheReserveBackend`].
//!
//! A cold tier on S3, Google Cloud Storage, Azure Blob Storage, or a
//! local directory, for the long tail the hot cache evicts. This is the
//! reserve backend to reach for when the working set is larger than a
//! Redis instance you want to pay for, and when the entries should
//! survive a replica's disk.
//!
//! # Why one backend rather than three
//!
//! The `object_store` crate is already in this workspace, driving the
//! `storage` action, the ACME certificate store, and the AI usage sink,
//! and it speaks S3, GCS, Azure, and the local filesystem through one
//! trait. Writing three provider-specific backends against three
//! provider SDKs would have meant three code paths to keep in step for
//! a difference operators never see, plus three dependency trees to
//! audit. The config vocabulary here (`backend`, `bucket`, `region`,
//! `endpoint`, `prefix`) is the `storage` action's, so an operator who
//! has configured one already knows this one.
//!
//! Because `endpoint` is passed through, anything S3-compatible works:
//! MinIO, Cloudflare R2, Backblaze B2, Ceph.
//!
//! # Encryption is local, not KMS
//!
//! An entry can be sealed before it leaves the process, with
//! AES-256-GCM through [`sbproxy_security::sealed_record`], the same
//! envelope the response cache's at-rest encryption uses, under its own
//! HKDF purpose so pointing both at one operator secret still yields two
//! unrelated keys. The cache key is bound into the associated data, so a
//! sealed object cannot be copied to another key and replayed.
//!
//! What this deliberately is not is a KMS integration. Wrapping each
//! entry's data key with a cloud KMS call would make a KMS reachable
//! from the proxy a hard requirement for reading the cache, which is the
//! external-store dependency this port exists to avoid, and it would put
//! a network round trip on the read path of a tier whose entire purpose
//! is to be cheaper than the origin. Bucket-level SSE-KMS remains
//! available and is configured on the bucket, where it belongs: it is
//! orthogonal to this setting and the two compose.
//!
//! # Object naming
//!
//! An entry's object is named `hex(sha256(cache key))`, fanned out two
//! levels (`ab/cd/abcdef...`) under the configured prefix. The digest
//! rather than the key because a cache key runs to a couple of hundred
//! bytes and encoding it inline puts the object name past `NAME_MAX` on
//! the `local` backend and eventually past S3's 1,024-byte key limit;
//! the fan-out because a flat prefix with a million entries is a
//! directory listing problem on extN and XFS. The digest is also the
//! associated data an entry is sealed under, so an object copied to
//! another entry's path fails to authenticate, and the eviction sweep
//! can open what it finds by listing without recovering the plaintext
//! key first.
//!
//! # One object per entry
//!
//! Each entry is a single object whose payload is
//!
//! ```text
//! metadata length (4, big-endian) | metadata JSON | body
//! ```
//!
//! sealed as a whole when encryption is on. One object rather than a
//! body object plus a metadata sidecar, because two objects means two
//! round trips and a window in which a reader sees one of them: object
//! stores offer no cross-object atomicity to close it with.
//!
//! # What `evict_expired` costs
//!
//! Expiry lives inside the object, so a sweep has to read each candidate
//! rather than judge it from the listing. The sweep is therefore bounded
//! at `MAX_EVICTION_SCAN` (1,000) objects per call and reports how many
//! it deleted.
//!
//! It also keeps a cursor. A sweep that hits the cap records the last
//! object it examined and the next one resumes after it, wrapping back
//! to the start when a pass reaches the end of the listing. Without
//! that, "bounded" meant the same first thousand objects were re-listed
//! and re-downloaded every tick and nothing past them was ever
//! examined: a recurring bill against a paid store, for no work.
//!
//! The proxy runs it on a timer (every fifteen minutes, from the
//! pipeline's background tasks), so a small reserve does expire without
//! any bucket configuration. That is what the bound is for: one
//! bounded pass per interval whatever the reserve holds, working
//! forward. It is not a substitute for a lifecycle rule at scale, and
//! the sections below and `docs/cache-reserve.md` say so in the same
//! words: a reserve of a million objects takes about ten days of ticks
//! to walk once.
//!
//! An index of empty marker objects named `{expiry}/{key}` would make
//! the sweep a single lexicographically-ordered list with no reads at
//! all. It is not what ships, because it doubles the write and delete
//! operations on every entry of a tier whose whole argument is cost, to
//! optimize a sweep that a bucket lifecycle rule does better and for
//! free. **Configure a lifecycle rule** (S3 lifecycle expiration, GCS
//! object lifecycle management, Azure blob lifecycle) on the reserve's
//! prefix in any deployment large enough for the difference to matter,
//! and treat this sweep as the answer for small ones and for
//! correctness after a TTL change.

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use object_store::{path::Path, ObjectStore, PutPayload};
use sbproxy_security::sealed_record::{OpenOutcome, SealKeyRing, SealScheme, SealedEnvelope};
use sbproxy_security::HkdfPurpose;

use super::{CacheReserveBackend, ReserveMetadata};

/// The reserve's envelope: magic `SBCR`, short for SBproxy Cache
/// Reserve.
///
/// Its own magic and its own HKDF purpose, both distinct from the
/// response cache's `SBRC`, so a response-cache record cannot be opened
/// as a reserve record even when an operator points both at one secret.
pub const SBCR_SCHEME: SealScheme = SealScheme::new(
    *b"SBCR",
    1,
    HkdfPurpose::CacheReserveAtRest,
    b"sbproxy.cache-reserve.key-id.v1",
);

/// Objects one `evict_expired` call will examine.
///
/// The sweep reads each candidate, so an unbounded pass over a large
/// bucket is a long stall and a real bill. Bounded, it makes progress
/// every time it runs and finishes the backlog across calls.
const MAX_EVICTION_SCAN: usize = 1_000;

/// Largest entry the backend will accept or return.
///
/// The reserve's own admission control already caps entry size
/// (`cache_reserve.max_size_bytes`), so this is the second line: a
/// bucket an operator shares with something else, or an object rewritten
/// out of band, cannot make the proxy allocate without limit on a read.
const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;

/// An object-storage cold tier.
pub struct ObjectStoreReserve {
    store: Arc<dyn ObjectStore>,
    /// Prefix every key is written under, so the reserve can share a
    /// bucket with other data.
    prefix: String,
    /// Operator-facing backend name, for `Debug` and diagnostics.
    backend: String,
    /// Key ring sealing new entries and opening existing ones. `None`
    /// stores payloads as they arrive.
    keys: Option<Arc<SealKeyRing>>,
    /// Largest object this instance will write or read.
    ///
    /// A field rather than [`MAX_ENTRY_BYTES`] read at each site so the
    /// cap can be exercised at a size a test can afford. Every
    /// production constructor sets it to the constant.
    max_entry_bytes: usize,
    /// Where the last eviction sweep stopped, so the next one resumes
    /// there instead of re-listing the same first `MAX_EVICTION_SCAN`
    /// objects forever. `None` means start from the beginning, which is
    /// both the initial state and the wrap-around after a sweep that
    /// reached the end of the listing.
    ///
    /// In memory rather than on the backend on purpose: a restart
    /// resuming from the top costs one extra pass over the first
    /// thousand objects, and persisting a cursor means a write per
    /// sweep against the bucket this feature exists to keep cheap.
    sweep_cursor: parking_lot::Mutex<Option<Path>>,
}

impl std::fmt::Debug for ObjectStoreReserve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectStoreReserve")
            .field("backend", &self.backend)
            .field("prefix", &self.prefix)
            .field(
                "encryption",
                &self
                    .keys
                    .as_ref()
                    .map(|ring| ring.active_key_id())
                    .unwrap_or_else(|| "off".to_string()),
            )
            .finish()
    }
}

impl ObjectStoreReserve {
    /// Wrap an already-built object store.
    ///
    /// Taking the store rather than building it keeps this crate free of
    /// the credential-discovery question: `sbproxy-core`'s pipeline
    /// constructs the provider client from config, the same way it does
    /// for the `storage` action, and hands it here.
    pub fn new(
        store: Arc<dyn ObjectStore>,
        backend: impl Into<String>,
        prefix: impl Into<String>,
        keys: Option<Arc<SealKeyRing>>,
    ) -> Self {
        let prefix: String = prefix.into();
        Self {
            store,
            // A prefix that does not end in `/` would make
            // `reserve` and `reserveX` share a namespace.
            prefix: match prefix.as_str() {
                "" => String::new(),
                _ if prefix.ends_with('/') => prefix,
                _ => format!("{prefix}/"),
            },
            backend: backend.into(),
            keys,
            max_entry_bytes: MAX_ENTRY_BYTES,
            sweep_cursor: parking_lot::Mutex::new(None),
        }
    }

    /// Shrink the entry cap so a test can reach it without allocating
    /// 64 MiB.
    #[cfg(test)]
    fn with_max_entry_bytes(mut self, cap: usize) -> Self {
        self.max_entry_bytes = cap;
        self
    }

    /// True when entries are sealed before they leave the process.
    pub fn encrypts_at_rest(&self) -> bool {
        self.keys.is_some()
    }

    /// The object name a cache key maps to: `hex(sha256(key))`.
    ///
    /// A digest rather than the key itself, and a digest rather than
    /// `hex(key)`, which is what shipped first and what WOR-2673's
    /// review found. A cache key is
    /// `v2:<workspace>:<tenant>:<hostname>:<method>:<path>:<identity>:<query>:<vary_fp>:<config_fp>`,
    /// which for an ordinary API request runs to roughly 190 bytes.
    /// Hex-encoded that is 380 characters in one path segment, past
    /// `NAME_MAX` (255) on ext4, XFS, and APFS, so every `put` on the
    /// `local` backend returned `ENAMETOOLONG` forever, with the
    /// symptom being `sbproxy_cache_reserve_errors_total` climbing and
    /// hits flat at zero. S3's 1,024-byte key limit is the same wall
    /// further out. A digest is 64 characters whatever the key was.
    ///
    /// It is also the associated data the entry is sealed under, so an
    /// object copied to another entry's path still fails to
    /// authenticate: the digest is derived from the key, and a
    /// different key gives a different digest and a different path.
    /// That is what lets the eviction sweep open an object it found by
    /// listing, without having to recover the plaintext key first.
    fn key_digest(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Object path for a digest, fanned out two levels.
    ///
    /// `ab/cd/abcdef...`, the shape [`super::filesystem::FsReserve`]
    /// uses and for the same reason it gives: without it every entry
    /// lands in one directory, and a directory with a million entries
    /// is a problem on extN and XFS long before it is a problem for the
    /// proxy.
    fn digest_path(&self, digest: &str) -> Path {
        Path::from(format!(
            "{}{}/{}/{}",
            self.prefix,
            &digest[..2],
            &digest[2..4],
            &digest[4..]
        ))
    }

    /// Object path for a cache key.
    fn object_path(&self, key: &str) -> Path {
        self.digest_path(&Self::key_digest(key))
    }

    /// Recover the digest an object path encodes. `None` for anything
    /// under the prefix this backend did not write.
    ///
    /// The comparison is against `Path::from(&self.prefix)` rather than
    /// the raw prefix string. `object_store` percent-encodes a set of
    /// bytes on the way into a `Path` (`%`, `[`, `]`, `{`, `}`, `^`,
    /// backtick, `"`, `<`, `>`, `\\`), so stripping the raw prefix off
    /// an encoded path failed the round trip for every object this
    /// backend wrote under a prefix containing one of them, and the
    /// sweep then skipped its own entries as "somebody else's".
    fn digest_from_path(&self, path: &Path) -> Option<String> {
        let encoded_prefix = Path::from(self.prefix.trim_end_matches('/'));
        let full = path.as_ref();
        let rest = if encoded_prefix.as_ref().is_empty() {
            full
        } else {
            full.strip_prefix(encoded_prefix.as_ref())?
                .strip_prefix('/')?
        };
        let digest: String = rest.split('/').collect();
        // 32 bytes of SHA-256, hex. Anything else is not ours.
        (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
    }

    /// Frame metadata and body into one payload, sealing it when a key
    /// ring is configured.
    fn encode(&self, digest: &str, value: &Bytes, metadata: &ReserveMetadata) -> Result<Vec<u8>> {
        let meta = serde_json::to_vec(metadata).context("encode reserve metadata")?;
        let meta_len = u32::try_from(meta.len())
            .context("reserve metadata is larger than the 4 GiB length prefix allows")?;
        let mut payload = Vec::with_capacity(4 + meta.len() + value.len());
        payload.extend_from_slice(&meta_len.to_be_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(value);
        match self.keys.as_ref() {
            // The key's digest is the associated data, so an object
            // lifted to another entry's path fails to authenticate
            // rather than being served as that entry. The digest and
            // not the key itself because the eviction sweep finds
            // objects by listing and has only the path to work from.
            Some(ring) => ring.seal(&payload, digest.as_bytes()),
            None => Ok(payload),
        }
    }

    /// Reverse [`Self::encode`]. `Ok(None)` means the object is not one
    /// this backend can read, which the caller treats as a miss so the
    /// request falls through to origin rather than failing.
    fn decode(&self, digest: &str, stored: &[u8]) -> Result<Option<(Bytes, ReserveMetadata)>> {
        let plaintext: Vec<u8> = match self.keys.as_ref() {
            Some(ring) => {
                let Some(envelope) =
                    SealedEnvelope::parse(SBCR_SCHEME, stored, |version| version == 1)
                else {
                    // Written before encryption was turned on, or by
                    // something else entirely. Treat as unreadable
                    // rather than as plaintext: a reserve configured to
                    // encrypt must not silently serve what it did not
                    // seal.
                    tracing::warn!(
                        "cache reserve object is not a sealed record; treating as a miss"
                    );
                    return Ok(None);
                };
                match ring.open(&envelope, digest.as_bytes()) {
                    OpenOutcome::Opened(plaintext) => plaintext,
                    OpenOutcome::AuthFailed => {
                        tracing::warn!(
                            key_id = %envelope.fingerprint_hex(),
                            "cache reserve object failed authentication; treating as a miss"
                        );
                        return Ok(None);
                    }
                    OpenOutcome::NoMatchingKey => {
                        tracing::warn!(
                            key_id = %envelope.fingerprint_hex(),
                            "cache reserve object was sealed under a key this build does not \
                             hold; treating as a miss"
                        );
                        return Ok(None);
                    }
                }
            }
            None => stored.to_vec(),
        };

        let Some(meta_len_bytes) = plaintext.get(..4) else {
            return Ok(None);
        };
        let mut length = [0u8; 4];
        length.copy_from_slice(meta_len_bytes);
        let meta_len = u32::from_be_bytes(length) as usize;
        let meta_end = 4usize.saturating_add(meta_len);
        // Checked before slicing rather than after: a corrupt length
        // prefix must not panic a worker.
        let Some(meta_bytes) = plaintext.get(4..meta_end) else {
            return Ok(None);
        };
        let metadata: ReserveMetadata = match serde_json::from_slice(meta_bytes) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(None),
        };
        let body = Bytes::copy_from_slice(&plaintext[meta_end..]);
        Ok(Some((body, metadata)))
    }
}

#[async_trait]
impl CacheReserveBackend for ObjectStoreReserve {
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> Result<()> {
        let digest = Self::key_digest(key);
        let payload = self.encode(&digest, &value, &metadata)?;
        // The cap is on what gets written, not on the body it was
        // framed from. Capping the body meant a response at exactly
        // `max_size_bytes == MAX_ENTRY_BYTES` was accepted by `put`,
        // stored with its metadata frame and seal overhead on top, and
        // then refused by `get` on every subsequent lookup: an entry
        // paid for and unreadable forever.
        if payload.len() > self.max_entry_bytes {
            anyhow::bail!(
                "reserve entry frames to {} bytes, past the {}-byte backend cap",
                payload.len(),
                self.max_entry_bytes
            );
        }
        self.store
            .put(&self.digest_path(&digest), PutPayload::from(payload))
            .await
            .context("cache reserve object put")?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<(Bytes, ReserveMetadata)>> {
        let digest = Self::key_digest(key);
        let path = self.digest_path(&digest);
        let result = match self.store.get(&path).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error).context("cache reserve object get"),
        };
        // Checked from the listing metadata, before the read allocates.
        // The docs recommend sharing a bucket, so anything with write
        // access to the prefix (a backup job, a colleague's `aws s3
        // cp`, a compromised CI credential) can leave a 4 GiB object at
        // a path that happens to look like ours. Checking the length
        // after `bytes()` is a cap the process has already paid for.
        if result.meta.size > self.max_entry_bytes {
            anyhow::bail!(
                "reserve object is {} bytes, past the {}-byte backend cap",
                result.meta.size,
                self.max_entry_bytes
            );
        }
        let stored = result.bytes().await.context("cache reserve object read")?;
        self.decode(&digest, &stored)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match self.store.delete(&self.object_path(key)).await {
            Ok(()) => Ok(()),
            // A missing key is not an error, per the trait's contract.
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(error).context("cache reserve object delete"),
        }
    }

    async fn evict_expired(&self, before: SystemTime) -> Result<u64> {
        self.sweep_at_most(MAX_EVICTION_SCAN, before).await
    }
}

impl ObjectStoreReserve {
    /// One bounded eviction pass, resuming from the last one.
    ///
    /// `cap` is a parameter rather than [`MAX_EVICTION_SCAN`] read
    /// directly so the resume behavior can be exercised at a size a
    /// test can afford; production always passes the constant.
    async fn sweep_at_most(&self, cap: usize, before: SystemTime) -> Result<u64> {
        let prefix = Path::from(self.prefix.trim_end_matches('/'));
        // WOR-2673 re-review N5. The sweep resumes where the last one
        // stopped. Without the cursor, `list` restarted at the
        // lexicographically first object every tick, so on any reserve
        // larger than `MAX_EVICTION_SCAN` the same first thousand
        // objects were re-listed and fully re-downloaded every fifteen
        // minutes and nothing past them was ever examined until they
        // were deleted. "Finishes the backlog across calls" was not
        // merely optimistic; it was the opposite of what happened, and
        // on a paid object store it was a recurring bill for no work.
        let resume_from = self.sweep_cursor.lock().clone();
        let mut listing = match resume_from.as_ref() {
            Some(offset) => self.store.list_with_offset(Some(&prefix), offset),
            None => self.store.list(Some(&prefix)),
        };
        let mut examined = 0usize;
        let mut deleted = 0u64;
        let mut last_examined: Option<Path> = None;
        let mut exhausted = true;
        while let Some(entry) = listing.next().await {
            if examined >= cap {
                // Not exhausted: there is more after this point, and
                // the cursor is what makes the next tick start there.
                exhausted = false;
                tracing::debug!(
                    examined,
                    deleted,
                    "cache reserve eviction sweep hit its per-call scan cap; the next sweep \
                     resumes after the last object this one examined. Configure a bucket \
                     lifecycle rule on the reserve prefix for a reserve this size"
                );
                break;
            }
            let meta = entry.context("cache reserve object listing")?;
            examined += 1;
            last_examined = Some(meta.location.clone());
            let Some(digest) = self.digest_from_path(&meta.location) else {
                // Something else's object under the same prefix. Never
                // delete it: the operator may be sharing the bucket.
                continue;
            };
            // Same cap as the read path, and for the same reason: an
            // oversized object under a shared prefix must not be
            // allocated to decide it is not ours. Skipped rather than
            // deleted, because it is not this backend's to remove.
            if meta.size > self.max_entry_bytes {
                continue;
            }
            let stored = match self.store.get(&meta.location).await {
                Ok(result) => result.bytes().await.context("cache reserve object read")?,
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => return Err(error).context("cache reserve object get"),
            };
            // An object this backend cannot decode is left alone rather
            // than deleted. Deleting it would turn a key-rotation
            // mistake into data loss.
            let Some((_, metadata)) = self.decode(&digest, &stored)? else {
                continue;
            };
            if metadata.is_expired(before) {
                self.store
                    .delete(&meta.location)
                    .await
                    .context("cache reserve object delete")?;
                deleted += 1;
            }
        }
        // Exhausted means the listing ran out, so the next sweep starts
        // over: that is the wrap-around, and it is what makes an object
        // that became expired behind the cursor get collected on the
        // following pass rather than never.
        *self.sweep_cursor.lock() = if exhausted { None } else { last_examined };
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CachedResponse;
    use std::time::Duration;

    fn memory_store() -> Arc<dyn ObjectStore> {
        Arc::new(object_store::memory::InMemory::new())
    }

    fn key_ring() -> Arc<SealKeyRing> {
        use sbproxy_security::sealed_record::SealKey;
        let active = SealKey::new(SBCR_SCHEME, vec![7u8; 32]).expect("key material");
        Arc::new(SealKeyRing::new(SBCR_SCHEME, active, Vec::new()).expect("ring"))
    }

    fn other_key_ring() -> Arc<SealKeyRing> {
        use sbproxy_security::sealed_record::SealKey;
        let active = SealKey::new(SBCR_SCHEME, vec![9u8; 32]).expect("key material");
        Arc::new(SealKeyRing::new(SBCR_SCHEME, active, Vec::new()).expect("ring"))
    }

    fn sample(ttl: Duration) -> (Bytes, ReserveMetadata) {
        let response = CachedResponse {
            generation: 0,
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"long":"tail"}"#.to_vec(),
            cached_at: 10,
            ttl_secs: ttl.as_secs(),
            swr_secs: None,
            config_fp: String::new(),
        };
        let now = SystemTime::now();
        let metadata = ReserveMetadata::from_cached_response(&response, now, now + ttl);
        (Bytes::from(response.body), metadata)
    }

    #[tokio::test]
    async fn an_entry_round_trips_unencrypted() {
        let reserve = ObjectStoreReserve::new(memory_store(), "local", "reserve", None);
        let (body, metadata) = sample(Duration::from_secs(60));
        reserve
            .put("/articles/1?full=1", body.clone(), metadata.clone())
            .await
            .expect("put");

        let (read_body, read_meta) = reserve
            .get("/articles/1?full=1")
            .await
            .expect("get")
            .expect("entry is present");
        assert_eq!(read_body, body);
        assert_eq!(read_meta.status, metadata.status);
        assert_eq!(read_meta.headers, metadata.headers);
    }

    #[tokio::test]
    async fn an_entry_round_trips_sealed() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", Some(key_ring()));
        assert!(reserve.encrypts_at_rest());
        let (body, metadata) = sample(Duration::from_secs(60));
        reserve
            .put("/a", body.clone(), metadata)
            .await
            .expect("put");
        let (read_body, _) = reserve.get("/a").await.expect("get").expect("present");
        assert_eq!(read_body, body);
    }

    #[tokio::test]
    async fn a_sealed_object_does_not_carry_its_body_in_the_clear() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "s3", "reserve", Some(key_ring()));
        let (body, metadata) = sample(Duration::from_secs(60));
        reserve.put("/a", body, metadata).await.expect("put");

        let raw = store
            .get(&reserve.object_path("/a"))
            .await
            .expect("stored object")
            .bytes()
            .await
            .expect("stored bytes");
        assert!(
            !raw.windows(4).any(|window| window == b"long"),
            "the sealed object must not carry the response body in the clear"
        );
        assert!(
            !raw.windows(12).any(|window| window == b"content-type"),
            "the sealed object must not carry the response headers in the clear"
        );
    }

    #[tokio::test]
    async fn an_object_moved_to_another_key_does_not_authenticate() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "s3", "reserve", Some(key_ring()));
        let (body, metadata) = sample(Duration::from_secs(60));
        reserve.put("/cheap", body, metadata).await.expect("put");

        // Copy the object to the path another cache key would read.
        let stolen = store
            .get(&reserve.object_path("/cheap"))
            .await
            .expect("stored")
            .bytes()
            .await
            .expect("bytes");
        store
            .put(
                &reserve.object_path("/expensive"),
                PutPayload::from(stolen.to_vec()),
            )
            .await
            .expect("replay put");

        assert!(
            reserve.get("/expensive").await.expect("get").is_none(),
            "a sealed object replayed under another cache key must not be served"
        );
    }

    #[tokio::test]
    async fn an_object_sealed_under_an_unheld_key_is_a_miss_not_an_error() {
        let store = memory_store();
        let writer = ObjectStoreReserve::new(store.clone(), "s3", "reserve", Some(key_ring()));
        let (body, metadata) = sample(Duration::from_secs(60));
        writer.put("/a", body, metadata).await.expect("put");

        let reader = ObjectStoreReserve::new(store, "s3", "reserve", Some(other_key_ring()));
        assert!(
            reader
                .get("/a")
                .await
                .expect("get is not an error")
                .is_none(),
            "an unopenable entry falls through to origin rather than failing the request"
        );
    }

    #[tokio::test]
    async fn an_encrypting_reserve_refuses_to_serve_an_unsealed_object() {
        let store = memory_store();
        let plain = ObjectStoreReserve::new(store.clone(), "local", "reserve", None);
        let (body, metadata) = sample(Duration::from_secs(60));
        plain.put("/a", body, metadata).await.expect("put");

        let sealing = ObjectStoreReserve::new(store, "local", "reserve", Some(key_ring()));
        assert!(
            sealing.get("/a").await.expect("get").is_none(),
            "a reserve configured to encrypt must not serve what it did not seal"
        );
    }

    #[tokio::test]
    async fn a_missing_key_is_a_miss_and_a_missing_delete_is_not_an_error() {
        let reserve = ObjectStoreReserve::new(memory_store(), "local", "reserve", None);
        assert!(reserve.get("/nothing").await.expect("get").is_none());
        reserve.delete("/nothing").await.expect("delete is lenient");
    }

    #[tokio::test]
    async fn evict_expired_deletes_only_the_expired() {
        let reserve = ObjectStoreReserve::new(memory_store(), "local", "reserve", None);
        let (fresh_body, fresh_meta) = sample(Duration::from_secs(3600));
        let (stale_body, mut stale_meta) = sample(Duration::from_secs(3600));
        stale_meta.expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        reserve
            .put("/fresh", fresh_body, fresh_meta)
            .await
            .expect("put");
        reserve
            .put("/stale", stale_body, stale_meta)
            .await
            .expect("put");

        let deleted = reserve
            .evict_expired(SystemTime::now())
            .await
            .expect("sweep");
        assert_eq!(deleted, 1);
        assert!(reserve.get("/fresh").await.expect("get").is_some());
        assert!(reserve.get("/stale").await.expect("get").is_none());
    }

    /// WOR-2673 re-review N5, red first. The sweep is capped at
    /// `MAX_EVICTION_SCAN` objects per call, and without a cursor
    /// `list` restarted at the lexicographically first object every
    /// tick: the same first thousand were re-examined forever and
    /// everything past them was never reached. Here the cap is one, so
    /// three ticks have to reach three different objects.
    #[tokio::test]
    async fn consecutive_sweeps_resume_instead_of_restarting() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "local", "reserve", None);
        let (body, mut metadata) = sample(Duration::from_secs(3600));
        // All three already expired, so whichever the sweep reaches is
        // the one it deletes, and "which did it reach" is the question.
        metadata.expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        for key in ["/a", "/b", "/c"] {
            reserve
                .put(key, body.clone(), metadata.clone())
                .await
                .expect("put");
        }

        let mut deleted_total = 0u64;
        for _ in 0..3 {
            deleted_total += reserve
                .sweep_at_most(1, SystemTime::now())
                .await
                .expect("sweep");
        }
        assert_eq!(
            deleted_total, 3,
            "three one-object sweeps must reach three different objects, not the same one \
             three times"
        );
        for key in ["/a", "/b", "/c"] {
            assert!(
                reserve.get(key).await.expect("get").is_none(),
                "{key} survived three sweeps"
            );
        }
    }

    /// And the cursor wraps: a sweep that reaches the end starts over,
    /// so an entry that expires behind the cursor is collected on the
    /// next pass rather than never.
    #[tokio::test]
    async fn a_sweep_that_reaches_the_end_starts_over() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "local", "reserve", None);
        let (body, fresh) = sample(Duration::from_secs(3600));
        reserve
            .put("/kept", body.clone(), fresh)
            .await
            .expect("put");

        // A full pass over one fresh object deletes nothing and
        // exhausts the listing.
        assert_eq!(
            reserve
                .evict_expired(SystemTime::now())
                .await
                .expect("sweep"),
            0
        );
        assert!(
            reserve.sweep_cursor.lock().is_none(),
            "an exhausted listing must reset the cursor, or the reserve is swept once and \
             never again"
        );

        // It expires later. The next sweep has to see it again.
        let (body, mut stale) = sample(Duration::from_secs(3600));
        stale.expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        reserve.put("/kept", body, stale).await.expect("re-put");
        assert_eq!(
            reserve
                .evict_expired(SystemTime::now())
                .await
                .expect("sweep"),
            1
        );
    }

    #[tokio::test]
    async fn the_sweep_leaves_objects_it_did_not_write_alone() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "local", "reserve", None);
        // A bucket the operator shares with something else.
        store
            .put(
                &Path::from("reserve/not-ours.json"),
                PutPayload::from_static(b"{}"),
            )
            .await
            .expect("foreign put");

        reserve
            .evict_expired(SystemTime::now())
            .await
            .expect("sweep");
        assert!(
            store
                .get(&Path::from("reserve/not-ours.json"))
                .await
                .is_ok(),
            "the sweep must not delete an object it cannot recognize as its own"
        );
    }

    #[test]
    fn a_prefix_without_a_trailing_slash_still_namespaces() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", None);
        let path = reserve.object_path("/a");
        assert!(
            path.as_ref().starts_with("reserve/"),
            "unexpected path: {path}"
        );
    }

    #[test]
    fn an_empty_prefix_writes_at_the_bucket_root() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "", None);
        let digest = ObjectStoreReserve::key_digest("/a");
        let path = reserve.object_path("/a");
        assert_eq!(
            path.as_ref(),
            format!("{}/{}/{}", &digest[..2], &digest[2..4], &digest[4..])
        );
    }

    #[test]
    fn a_cache_key_with_traversal_segments_cannot_escape_the_prefix() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", None);
        let path = reserve.object_path("/../../etc/passwd?a=../b");
        assert!(
            path.as_ref().starts_with("reserve/"),
            "a cache key must not escape the prefix: {path}"
        );
        assert!(!path.as_ref().contains(".."), "unexpected path: {path}");
    }

    #[test]
    fn a_path_round_trips_back_to_its_digest() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve/", None);
        let key = "/articles/1?full=1";
        let path = reserve.object_path(key);
        assert_eq!(
            reserve.digest_from_path(&path).as_deref(),
            Some(ObjectStoreReserve::key_digest(key).as_str())
        );
    }

    /// WOR-2673 review F22, red first. `object_store` percent-encodes a
    /// set of bytes on the way into a `Path`, so stripping the *raw*
    /// prefix off an *encoded* path failed the round trip for every
    /// object this backend wrote under a prefix containing one of them,
    /// and the sweep then skipped its own entries.
    #[test]
    fn a_prefix_with_an_encoded_byte_still_round_trips() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "sb%reserve/", None);
        let key = "/articles/1";
        let path = reserve.object_path(key);
        assert_eq!(
            reserve.digest_from_path(&path).as_deref(),
            Some(ObjectStoreReserve::key_digest(key).as_str()),
            "the sweep has to recognize objects this backend wrote: {path}"
        );
    }

    #[test]
    fn a_foreign_path_does_not_decode_as_a_digest() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", None);
        assert_eq!(
            reserve.digest_from_path(&Path::from("reserve/not-hex")),
            None
        );
        assert_eq!(
            reserve.digest_from_path(&Path::from("elsewhere/aabb")),
            None
        );
    }

    /// WOR-2673 review F4, red first. Object names used to be
    /// `hex(cache key)` in one flat segment: twice the length of a key
    /// that already runs to a couple of hundred bytes, which is past
    /// `NAME_MAX` on ext4, XFS, and APFS, so every `put` for an
    /// ordinary API path failed forever on the `local` backend the
    /// shipped example uses.
    #[tokio::test]
    async fn a_realistic_cache_key_produces_a_storable_object_name() {
        let reserve = ObjectStoreReserve::new(memory_store(), "local", "sbproxy/reserve/", None);
        let key = format!(
            "v2:acme-workspace:acme-prod:api.acme.com:POST:\
             /v1/organizations/12345/projects/67890/documents/abcdef:\
             {identity}:{query}:{vary}:{config}",
            identity = "a".repeat(40),
            query = "b".repeat(30),
            vary = "c".repeat(16),
            config = "d".repeat(16),
        );
        let path = reserve.object_path(&key);
        for segment in path.as_ref().split('/') {
            assert!(
                segment.len() <= 255,
                "no path segment may exceed NAME_MAX: {segment}"
            );
        }
        assert!(
            path.as_ref().len() <= 1024,
            "and the whole name has to fit S3's key limit: {path}"
        );
        // Fanned out, so one prefix does not hold every entry.
        assert!(
            path.as_ref().starts_with("sbproxy/reserve/"),
            "unexpected path: {path}"
        );
        assert_eq!(
            path.as_ref().split('/').count(),
            5,
            "unexpected path: {path}"
        );

        let (body, metadata) = sample(Duration::from_secs(60));
        reserve
            .put(&key, body.clone(), metadata)
            .await
            .expect("a realistic cache key has to be storable");
        assert_eq!(
            reserve.get(&key).await.expect("get").expect("present").0,
            body
        );
    }

    /// WOR-2673 review F3, as a seam test. The cap used to be checked
    /// after `result.bytes()` had already materialized the whole
    /// object, which is a cap the process has paid for. It is read off
    /// the listing metadata now, so the refusal happens before the
    /// allocation.
    #[tokio::test]
    async fn an_oversized_object_is_refused_from_its_metadata() {
        let store = memory_store();
        let reserve =
            ObjectStoreReserve::new(store.clone(), "s3", "reserve", None).with_max_entry_bytes(64);
        // Written out of band, the way a shared bucket lets anything
        // with write access to the prefix do.
        store
            .put(
                &reserve.object_path("/a"),
                PutPayload::from(vec![0u8; 4096]),
            )
            .await
            .expect("foreign put");
        let error = reserve
            .get("/a")
            .await
            .expect_err("an object past the cap must be refused");
        assert!(format!("{error:#}").contains("4096"), "{error:#}");
    }

    /// WOR-2673 review F19, red first. `put` capped the body and `get`
    /// capped the framed-and-sealed object, so an entry at exactly the
    /// cap was written and then unreadable forever.
    #[tokio::test]
    async fn an_entry_at_the_cap_is_refused_rather_than_written_unreadable() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", Some(key_ring()))
            .with_max_entry_bytes(256);
        let (_, metadata) = sample(Duration::from_secs(60));
        let body = Bytes::from(vec![0u8; 256]);
        reserve
            .put("/a", body, metadata)
            .await
            .expect_err("a body that frames past the cap must be refused at write");
        assert!(
            reserve.get("/a").await.expect("get").is_none(),
            "and nothing must have been written"
        );
    }

    #[test]
    fn a_corrupt_length_prefix_is_a_miss_rather_than_a_panic() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", None);
        // A length prefix claiming far more metadata than the payload
        // holds. Slicing on it without a check would panic a worker.
        let mut corrupt = u32::MAX.to_be_bytes().to_vec();
        corrupt.extend_from_slice(b"{}");
        let digest = ObjectStoreReserve::key_digest("/a");
        assert!(reserve.decode(&digest, &corrupt).expect("decode").is_none());
        assert!(reserve.decode(&digest, b"ab").expect("decode").is_none());
        assert!(reserve.decode(&digest, &[]).expect("decode").is_none());
    }

    /// The same corruption reached through the production entry point,
    /// so the claim is about the surface rather than about `decode`.
    #[tokio::test]
    async fn a_corrupt_object_read_through_get_is_a_miss() {
        let store = memory_store();
        let reserve = ObjectStoreReserve::new(store.clone(), "s3", "reserve", None);
        let mut corrupt = u32::MAX.to_be_bytes().to_vec();
        corrupt.extend_from_slice(b"{}");
        store
            .put(&reserve.object_path("/a"), PutPayload::from(corrupt))
            .await
            .expect("corrupt put");
        assert!(
            reserve
                .get("/a")
                .await
                .expect("get is not an error")
                .is_none(),
            "a corrupt object falls through to origin rather than panicking a worker"
        );
    }

    #[test]
    fn debug_names_the_backend_without_the_key_material() {
        let reserve = ObjectStoreReserve::new(memory_store(), "s3", "reserve", Some(key_ring()));
        let rendered = format!("{reserve:?}");
        assert!(rendered.contains("s3"), "{rendered}");
        assert!(!rendered.contains("777777"), "{rendered}");
        let plain = ObjectStoreReserve::new(memory_store(), "local", "reserve", None);
        assert!(format!("{plain:?}").contains("off"));
    }
}
