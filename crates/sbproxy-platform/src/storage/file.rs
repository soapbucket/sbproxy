//! File-based KVStore backend.
//!
//! Each key-value pair is stored as a file on disk. The key is hex-encoded
//! as the filename; the file contents are the raw value bytes.
//!
//! A directory-level `Mutex` serializes all writes so that concurrent callers
//! cannot race on directory listing or file creation.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use bytes::Bytes;

use super::KVStore;

/// How long a release's exclusive claim may sit before the next writer
/// treats it as a corpse and clears it.
///
/// A release holds its claim for two syscalls, so any claim older than this
/// belongs to a process that died mid-release. `unlock` has no lease TTL of
/// its own to borrow (the lease is being given up, so its remaining time is
/// not a bound on anything), which is why this is stated here rather than
/// threaded through. It only governs corpse reaping; it never extends a
/// lease or delays a takeover.
const DEFAULT_CLAIM_TTL_SECS: u64 = 120;

/// File-backed key-value store. All operations are synchronous and
/// mutex-protected; it is not intended for high-concurrency workloads.
pub struct FileKVStore {
    directory: PathBuf,
    /// Protects all directory-level mutations (writes, deletes).
    _lock: Mutex<()>,
}

impl FileKVStore {
    /// Create (or open) a file store rooted at `directory`.
    ///
    /// The directory is created recursively if it does not already exist.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)
            .with_context(|| format!("create KV directory {:?}", directory))?;
        Ok(Self {
            directory,
            _lock: Mutex::new(()),
        })
    }

    /// Convert a raw key slice to its hex-encoded filename.
    fn key_to_filename(key: &[u8]) -> String {
        hex::encode(key)
    }

    /// Decode a hex filename back to the original key bytes.
    fn filename_to_key(name: &str) -> Option<Vec<u8>> {
        hex::decode(name).ok()
    }

    fn path_for(&self, key: &[u8]) -> PathBuf {
        self.directory.join(Self::key_to_filename(key))
    }

    /// Write `value` to `path` so a concurrent reader sees either the whole
    /// previous file or the whole new one (WOR-2635).
    ///
    /// `fs::write` truncates and then streams, so any reader that arrives
    /// mid-write observes a short file. For a certificate bundle that is a
    /// record which parses as valid and is not. Writing a sibling temp file
    /// and `rename`-ing it into place makes the swap one atomic directory
    /// operation on every POSIX filesystem.
    ///
    /// The temp name carries a '.' so it can never hex-decode back to a key,
    /// which keeps a crashed write out of `scan_prefix` results.
    fn atomic_write(&self, path: &std::path::Path, value: &[u8]) -> Result<()> {
        use std::io::Write as _;
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp.{}.{seq}", std::process::id()));
        let write = (|| -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(value)?;
            file.sync_all()
        })();
        if let Err(e) = write {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("stage write {:?}", tmp));
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("publish write {:?}", path));
        }
        Ok(())
    }

    /// Marker path a contender must atomically create before it may take over
    /// a lease it observed at `generation`.
    fn takeover_marker(path: &std::path::Path, generation: u64) -> PathBuf {
        path.with_extension(format!("take.{generation}"))
    }

    /// Whether `path` has not been touched for longer than `ttl_secs`.
    ///
    /// A missing or unreadable mtime reads as fresh, so an unhelpful
    /// filesystem makes a claim harder to reap rather than easier.
    fn aged_past(path: &std::path::Path, ttl_secs: u64) -> bool {
        fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|age| age.as_secs() > ttl_secs)
            .unwrap_or(false)
    }

    /// Create `claim` exclusively, or say why not.
    ///
    /// `O_CREAT|O_EXCL` is the one primitive a shared filesystem reliably
    /// serializes, so it is what stands in for a cross-node mutex here.
    /// A claim older than the TTL is a corpse left by a process that died
    /// holding it: clear it so the next attempt can claim fresh, and still
    /// report contention for this one.
    fn stake_claim(claim: &std::path::Path, ttl_secs: u64) -> Result<bool> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(claim)
        {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if Self::aged_past(claim, ttl_secs) {
                    let _ = fs::remove_file(claim);
                }
                Ok(false)
            }
            Err(e) => Err(e).with_context(|| format!("stake claim {:?}", claim)),
        }
    }
}

/// Write `staged` into a claim this caller already holds.
fn stage_into_claim(claim: &std::path::Path, staged: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let write = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(claim)?;
        file.write_all(staged)?;
        file.sync_all()
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(claim);
        return Err(e).with_context(|| format!("stage claim {:?}", claim));
    }
    Ok(())
}

/// Publish a staged lock payload by consuming the claim that authorized it.
///
/// This is the compare-and-swap the file backend was missing. The payload
/// lives inside the claim file, so renaming the claim onto the lock path
/// both publishes the payload and destroys the right to publish it again:
///
/// * a claimant whose marker was reaped as a corpse while it stalled has
///   nothing left to rename, so it cannot become a second holder of the
///   generation somebody else has already taken,
/// * a claimant whose marker was reaped and then re-created by the reaper
///   finds bytes it did not write, and refuses before the rename,
/// * and the read-back proves whose payload is actually standing, so a
///   caller never comes away believing it holds a lease that carries a
///   peer's token.
///
/// `rename` is atomic on every POSIX filesystem, so a concurrent reader
/// still sees the whole previous lease or the whole new one.
fn consume_claim(claim: &std::path::Path, path: &std::path::Path, staged: &[u8]) -> Result<bool> {
    match fs::read(claim) {
        Ok(bytes) if bytes == staged => {}
        // Reaped, or reaped and re-claimed by a peer. Not ours to publish.
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("verify claim {:?}", claim)),
    }
    match fs::rename(claim, path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("publish claim {:?}", path)),
    }
    Ok(fs::read(path).map(|bytes| bytes == staged).unwrap_or(false))
}

/// A renewal's critical section, run with the exclusive claim already held.
///
/// Re-read the lease under the claim, refuse unless `renew_cas_decision`
/// says nothing moved, then publish by consuming the claim.
fn renew_under_claim(
    claim: &std::path::Path,
    path: &std::path::Path,
    observed: &[u8],
    want: &str,
    token: &[u8],
    ttl_secs: u64,
) -> Result<bool> {
    let Ok(current) = fs::read(path) else {
        return Ok(false);
    };
    let Some(generation) = renew_cas_decision(observed, &current, want) else {
        return Ok(false);
    };
    let staged = encode_lock(unix_now().saturating_add(ttl_secs), generation, token);
    stage_into_claim(claim, &staged)?;
    consume_claim(claim, path, &staged)
}

/// The compare-and-swap a renewal has to pass before it may write.
///
/// `observed` is the lease as the renewal first read it; `current` is the
/// same lease re-read under the exclusive claim. Both have to agree that
/// this token is the holder *and* that the generation has not moved, which
/// is what makes the write conditional rather than blind.
///
/// Two nodes over a filesystem with attribute caching is the case that
/// forced this. A stalls, its lease expires, B takes over and writes
/// (expiry, generation 6, token B); A's heartbeat reads a stale cached view
/// that still shows token A at generation 5, passes a holder check made
/// against that view alone, and writes generation 5 back over generation 6.
/// The fencing token goes backwards, and the fencing token is the only
/// thing keeping A's certificate out of the store. A renewal never lowers a
/// generation because it only ever writes the one it re-read here, and only
/// when nothing moved.
fn renew_cas_decision(observed: &[u8], current: &[u8], want: &str) -> Option<u64> {
    let (_, observed_generation, observed_holder) = decode_lock(observed);
    let (_, current_generation, current_holder) = decode_lock(current);
    if observed_holder != want || current_holder != want {
        return None;
    }
    if observed_generation != current_generation {
        return None;
    }
    Some(current_generation)
}

/// Lock payload: `<expiry_unix>:<generation>:<hex token>`.
///
/// An empty token with expiry 0 is a released lease. The file stays behind
/// on release rather than being deleted, because the generation in it is a
/// fencing token and a deleted file would restart the count at one.
fn encode_lock(expiry: u64, generation: u64, token: &[u8]) -> Vec<u8> {
    format!("{expiry}:{generation}:{}", hex::encode(token)).into_bytes()
}

/// Parse `(expiry, generation, hex token)`. A payload written before
/// WOR-2633 is the bare token with no separators; it decodes as generation
/// zero with no expiry of its own, so the mtime lease below still governs it.
fn decode_lock(bytes: &[u8]) -> (u64, u64, String) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return (0, 0, hex::encode(bytes));
    };
    let mut parts = text.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(expiry), Some(generation), Some(token)) => {
            match (expiry.parse::<u64>(), generation.parse::<u64>()) {
                (Ok(expiry), Ok(generation)) => (expiry, generation, token.to_string()),
                _ => (0, 0, hex::encode(bytes)),
            }
        }
        _ => (u64::MAX, 0, hex::encode(bytes)),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl KVStore for FileKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let path = self.path_for(key);
        match fs::read(&path) {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {:?}", path)),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        self.atomic_write(&path, value)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("delete {:?}", path)),
        }
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let encoded_prefix = Self::key_to_filename(prefix);

        let mut results = Vec::new();

        let read_dir = fs::read_dir(&self.directory)
            .with_context(|| format!("read_dir {:?}", self.directory))?;

        for entry in read_dir {
            let entry = entry.with_context(|| "read directory entry")?;
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(n) => n,
                None => continue,
            };

            // A hex-encoded key has the prefix iff the original key bytes
            // start with `prefix`. Because hex encoding is prefix-safe (each
            // source byte becomes exactly two hex chars) we can compare the
            // encoded strings directly.
            if !name.starts_with(&encoded_prefix) {
                continue;
            }

            let key_bytes = match Self::filename_to_key(name) {
                Some(k) => k,
                None => continue,
            };

            let path = entry.path();
            let value = fs::read(&path).with_context(|| format!("read entry {:?}", path))?;

            results.push((Bytes::from(key_bytes), Bytes::from(value)));
        }

        Ok(results)
    }

    fn try_lock(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<bool> {
        Ok(self.try_lock_fenced(key, token, ttl_secs)?.is_some())
    }

    fn try_lock_fenced(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<Option<u64>> {
        // WOR-1776 gave this a cross-node lock over a shared filesystem;
        // WOR-2633 gave the takeover of an expired one a fencing generation
        // and made it atomic.
        //
        // First acquisition is `create_new` (O_CREAT|O_EXCL), which is the
        // one primitive a shared filesystem reliably serializes. Taking over
        // an expired lease used to be read-then-overwrite, and two replicas
        // that both read the same stale lease both wrote and both returned
        // success. The takeover now runs through its own `create_new` on a
        // marker named for the generation being superseded, so exactly one
        // contender per generation may proceed, and the generation it
        // publishes fences the holder it replaced out of the bundle store.
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let payload = encode_lock(unix_now().saturating_add(ttl_secs), 1, token);
                f.write_all(&payload)
                    .with_context(|| format!("write lock {:?}", path))?;
                f.sync_all()
                    .with_context(|| format!("sync lock {:?}", path))?;
                Ok(Some(1))
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let existing = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    // Vanished between the create and the read: a peer
                    // released it. Report contention; the caller retries.
                    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e).with_context(|| format!("read lock {:?}", path)),
                };
                let (expiry, generation, _) = decode_lock(&existing);
                // Two independent expiry signals. The payload's own deadline
                // is what a current holder writes; the mtime lease covers a
                // payload written before this format existed and a holder
                // whose clock runs behind the reader's.
                let mtime_aged = Self::aged_past(&path, ttl_secs);
                if unix_now() < expiry && !mtime_aged {
                    return Ok(None);
                }

                // A peer already claiming this generation wins; losing here
                // is the point of the marker. A marker older than the TTL is
                // a corpse left by a claimant that died mid-claim, and
                // `stake_claim` clears it so the next attempt claims fresh.
                //
                // Reaping a corpse used to be the whole story, and it is not
                // enough on its own: a claimant is not dead just because its
                // marker aged out. A stall longer than the TTL between two
                // syscalls is precisely what a lease exists to survive, and
                // a claimant that resumed after being reaped would run the
                // rest of an acquisition the reaper had already completed,
                // leaving two live holders carrying the same fencing
                // generation. So the claim is not just an exclusion token,
                // it is the write: the payload is staged inside it and
                // published by renaming it into place, which consumes it.
                // See [`consume_claim`].
                let marker = Self::takeover_marker(&path, generation);
                if !Self::stake_claim(&marker, ttl_secs)? {
                    return Ok(None);
                }

                // Re-read before publishing: a contender that observed an
                // older generation must not overwrite a newer holder that
                // won its own marker in the meantime.
                let (_, current_generation, _) = fs::read(&path)
                    .map(|bytes| decode_lock(&bytes))
                    .unwrap_or((0, generation, String::new()));
                if current_generation != generation {
                    let _ = fs::remove_file(&marker);
                    return Ok(None);
                }

                let next = generation.saturating_add(1);
                let staged = encode_lock(unix_now().saturating_add(ttl_secs), next, token);
                stage_into_claim(&marker, &staged)?;
                Ok(consume_claim(&marker, &path, &staged)?.then_some(next))
            }
            Err(e) => Err(e).with_context(|| format!("acquire lock {:?}", path)),
        }
    }

    fn renew_lock(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<bool> {
        // Extend our own deadline in place, keeping the generation, as a
        // compare-and-swap rather than a read-modify-write (WOR-2633).
        //
        // The read-modify-write this replaced had no fence in its
        // conditional: it read the lease, checked the holder against what
        // that read said, and then wrote unconditionally. Two nodes over a
        // filesystem with attribute caching is enough to break it. A stalls,
        // its lease expires, B takes over at generation 6; A's heartbeat
        // reads a stale cached view still showing token A at generation 5,
        // passes the holder check, and writes generation 5 over B's 6. The
        // fencing token goes backwards, and the fencing token is the only
        // thing keeping a deposed holder's certificate out of the store.
        //
        // Three things make it a real CAS. The exclusive claim spans the
        // read and the write, so no peer can slip a takeover between them.
        // [`renew_cas_decision`] refuses the write unless the lease re-read
        // under that claim still says exactly what the first read said. And
        // the write itself is the claim, renamed into place by
        // [`consume_claim`], so publishing it consumes the right to publish
        // it, and the read-back proves our bytes are the ones standing.
        //
        // The other two shared backends already did this: Redis compares the
        // token inside the renewal script, and the object store renews under
        // a `PutMode::Update` precondition on the version it read.
        //
        // Poison recovery rather than a panic: a renewal that dies here
        // refuses at worst, and the caller stops publishing, which is the
        // safe direction.
        let _guard = match self._lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path = self.path_for(key);
        let want = hex::encode(token);
        let Ok(observed) = fs::read(&path) else {
            return Ok(false);
        };
        let (_, observed_generation, observed_holder) = decode_lock(&observed);
        if observed_holder != want {
            return Ok(false);
        }

        // Contention on this claim is not routine: only the holder renews,
        // so a claim we did not make means either a second process believes
        // it is the holder, or one died mid-renewal and left a corpse that
        // this attempt has just cleared for the next one.
        //
        // An error, not `Ok(false)`. The two answers are not the same and
        // callers act on the difference: `Ok(false)` means the lease is
        // definitively somebody else's, and `CertStore::renew_issue_lease`
        // marks the lease irrecoverably lost on it. Throwing an in-flight
        // ACME order away because a crashed peer left a stale claim file
        // would be a self-inflicted outage. "Could not prove ownership on
        // this beat" is what the heartbeat's error path already knows how
        // to ride out, up to its own safety deadline.
        // The claim is the generation's marker, the same file a contender
        // taking this lease over would stake, and that shared name is the
        // whole point. A renewal and a takeover both end by renaming their
        // claim onto the lock, so two different claim names would serialize
        // neither: a takeover could publish generation N+1 while a renewal
        // that had already passed its compare-and-swap was mid-stage, and
        // the renewal's rename would then land generation N on top of it.
        // The fence would go backwards and two nodes would mint the same
        // generation, which is exactly the hazard the marker exists to
        // close. One name means one winner.
        let claim = Self::takeover_marker(&path, observed_generation);
        if !Self::stake_claim(&claim, ttl_secs)? {
            anyhow::bail!(
                "another writer holds the exclusive claim {:?}; could not prove \
                 ownership of this lease on this beat",
                claim
            );
        }
        let renewed = renew_under_claim(&claim, &path, &observed, &want, token, ttl_secs);
        // Only clear the claim when nothing was published. A successful
        // publish consumed it by renaming it away, and a peer may already
        // have staked a fresh claim under the same name, which this would
        // delete out from under them and leave two writers unexcluded.
        if matches!(renewed, Ok(false)) {
            let _ = fs::remove_file(&claim);
        }
        renewed
    }

    fn unlock(&self, key: &[u8], token: &[u8]) -> Result<()> {
        // Compare-and-release: rewrite as an expired, unheld lease while it
        // still carries our token, so a node never releases a lock a peer
        // acquired after this one's lease expired. The file survives the
        // release because its generation is a fencing token.
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        let want = hex::encode(token);
        let Ok(existing) = fs::read(&path) else {
            return Ok(());
        };
        let (_, generation, holder) = decode_lock(&existing);
        if holder != want {
            return Ok(());
        }
        // Release under the same claim discipline as a renewal. This used
        // to be a blind write, which could put a stale generation back on
        // top of a peer's newer one and clear its holder along with it, so
        // a release could undo a takeover that had already happened.
        let claim = Self::takeover_marker(&path, generation);
        if !Self::stake_claim(&claim, DEFAULT_CLAIM_TTL_SECS)? {
            // Somebody else is mid-write on this generation. They either
            // take the lease over or renew it; either way this lease is no
            // longer ours to release, and the expiry it already carries is
            // what frees it.
            return Ok(());
        }
        let released = encode_lock(0, generation, b"");
        let still_ours = fs::read(&path)
            .map(|bytes| {
                let (_, current_generation, current_holder) = decode_lock(&bytes);
                current_generation == generation && current_holder == want
            })
            .unwrap_or(false);
        if !still_ours {
            let _ = fs::remove_file(&claim);
            return Ok(());
        }
        stage_into_claim(&claim, &released)?;
        if !consume_claim(&claim, &path, &released)? {
            let _ = fs::remove_file(&claim);
        }
        // Superseded takeover markers cannot be won by anyone now: a
        // contender that observed an older generation fails the re-read
        // check above. Clearing them keeps the directory from accumulating
        // one file per issuance.
        let marker_stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| format!("{n}.take."))
            .unwrap_or_default();
        if let (Some(dir), false) = (path.parent(), marker_stem.is_empty()) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let Some(suffix) = name.strip_prefix(marker_stem.as_str()) else {
                        continue;
                    };
                    if suffix
                        .parse::<u64>()
                        .is_ok_and(|marked| marked < generation)
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_store() -> (FileKVStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = FileKVStore::new(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn file_lock_is_exclusive_and_token_scoped() {
        let (store, _dir) = make_store();
        let key = b"acme:lock:example.com";
        assert!(store.try_lock(key, b"tokenA", 60).unwrap(), "A acquires");
        assert!(
            !store.try_lock(key, b"tokenB", 60).unwrap(),
            "B blocked while held"
        );
        // A non-owner release is a no-op (token mismatch).
        store.unlock(key, b"tokenB").unwrap();
        assert!(
            !store.try_lock(key, b"tokenC", 60).unwrap(),
            "still held after non-owner release"
        );
        // The owner releases; the lock is free again.
        store.unlock(key, b"tokenA").unwrap();
        assert!(
            store.try_lock(key, b"tokenD", 60).unwrap(),
            "free after owner release"
        );
        store.unlock(key, b"tokenD").unwrap();
    }

    #[test]
    fn file_lock_steals_an_expired_lease() {
        let (store, _dir) = make_store();
        let key = b"acme:lock:stale.example";
        // Acquire with a 0s TTL so any later attempt sees it as expired.
        assert!(store.try_lock(key, b"old", 0).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // The taker asks for a real TTL: a lease taken with a zero TTL is
        // expired the instant it is written, and the assertion below is
        // about a lease that is genuinely held.
        assert!(
            store.try_lock(key, b"new", 60).unwrap(),
            "an expired lease is stolen"
        );
        // The stale holder's release must not free the new holder's lock.
        store.unlock(key, b"old").unwrap();
        assert!(
            !store.try_lock(key, b"other", 60).unwrap(),
            "new holder still holds after the stale owner's release"
        );
    }

    #[test]
    fn test_get_put_delete_roundtrip() {
        let (store, _dir) = make_store();

        // Missing key returns None.
        assert!(store.get(b"k1").unwrap().is_none());

        // Put and get.
        store.put(b"k1", b"hello").unwrap();
        assert_eq!(store.get(b"k1").unwrap().unwrap(), &b"hello"[..]);

        // Overwrite.
        store.put(b"k1", b"world").unwrap();
        assert_eq!(store.get(b"k1").unwrap().unwrap(), &b"world"[..]);

        // Delete.
        store.delete(b"k1").unwrap();
        assert!(store.get(b"k1").unwrap().is_none());

        // Delete non-existent is a no-op.
        store.delete(b"k1").unwrap();
    }

    #[test]
    fn test_scan_prefix() {
        let (store, _dir) = make_store();

        store.put(b"app:user:1", b"alice").unwrap();
        store.put(b"app:user:2", b"bob").unwrap();
        store.put(b"app:config:x", b"cfg").unwrap();
        store.put(b"other:key", b"nope").unwrap();

        let mut results = store.scan_prefix(b"app:user:").unwrap();
        results.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(results.len(), 2);

        let results = store.scan_prefix(b"app:").unwrap();
        assert_eq!(results.len(), 3);

        let results = store.scan_prefix(b"missing:").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_binary_keys_and_values() {
        let (store, _dir) = make_store();
        let key = &[0x00, 0xFF, 0xAB, 0x12];
        let value = &[0x01, 0x02, 0x03];
        store.put(key, value).unwrap();
        assert_eq!(store.get(key).unwrap().unwrap(), &value[..]);
    }

    #[test]
    fn takeover_generations_strictly_increase() {
        // WOR-2633: the generation is the fencing token a bundle store uses
        // to refuse a superseded holder, so it has to keep climbing across
        // release-reacquire and across takeover of an expired lease.
        let (store, dir) = make_store();
        let key = b"acme:lock:fenced.example";
        let first = store.try_lock_fenced(key, b"a", 60).unwrap().unwrap();
        store.unlock(key, b"a").unwrap();
        let second = store.try_lock_fenced(key, b"b", 60).unwrap().unwrap();
        assert!(second > first, "{second} must exceed {first} after release");

        // Age the lease out from under B and take it over.
        let path = dir.path().join(hex::encode(key));
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        let third = store.try_lock_fenced(key, b"c", 60).unwrap().unwrap();
        assert!(
            third > second,
            "{third} must exceed {second} after takeover"
        );
    }

    #[test]
    fn a_takeover_claimant_that_died_mid_claim_does_not_wedge_the_lease() {
        // WOR-2633: the marker serializes stealers, but a claimant that
        // crashed between creating the marker and writing the lock must
        // not hold the generation hostage forever. An aged marker is
        // cleared (contention is still reported for that attempt), and
        // the next attempt claims fresh.
        let (store, dir) = make_store();
        let key = b"acme:lock:corpse.example";
        assert!(store.try_lock(key, b"crashed-owner", 60).unwrap());
        let path = dir.path().join(hex::encode(key));
        let lock_file = std::fs::File::options().write(true).open(&path).unwrap();
        lock_file
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();

        // A previous stealer claimed the takeover of generation 1 and died.
        let marker = path.with_extension("take.1");
        std::fs::File::create(&marker).unwrap();
        let marker_file = std::fs::File::options().write(true).open(&marker).unwrap();
        marker_file
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();

        assert!(
            store.try_lock_fenced(key, b"b", 60).unwrap().is_none(),
            "the attempt that finds the corpse reports contention"
        );
        assert!(!marker.exists(), "the corpse marker is cleared");
        assert!(
            store.try_lock_fenced(key, b"b", 60).unwrap().is_some(),
            "the next attempt takes the lease over"
        );
    }

    /// Age `path` well past any TTL these tests use.
    fn age_out(path: &std::path::Path) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open to age");
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .expect("age the file");
    }

    #[test]
    fn a_reaped_takeover_claimant_cannot_still_complete_its_acquisition() {
        // WOR-2633's marker serializes contenders per generation, and the
        // reaping of an aged marker was justified by "a live winner's
        // marker is milliseconds old". A stall longer than the TTL between
        // two syscalls is exactly what a lease exists to survive, so that
        // is not a safe assumption:
        //
        //   X claims take.1 and stalls.
        //   Y finds the marker aged, deletes it, re-creates take.1, re-reads
        //     generation 1, and writes generation 2.
        //   X resumes past its own already-passed re-read and writes
        //     generation 2 as well.
        //
        // Two live holders carrying an identical fencing token, which
        // `published >= lease.generation` cannot tell apart. The claim is
        // now the write itself, so completing an acquisition consumes it and
        // a reaped claimant has nothing left to publish with.
        let (store, dir) = make_store();
        let key = b"acme:lock:stall.example";
        assert!(store.try_lock(key, b"owner", 60).unwrap());
        let path = dir.path().join(hex::encode(key));
        age_out(&path);

        // X's claim, staged and then stalled past the TTL.
        let marker = path.with_extension("take.1");
        let x_staged = encode_lock(unix_now() + 60, 2, b"X");
        std::fs::write(&marker, &x_staged).expect("stage X's claim");
        age_out(&marker);

        // Y reaps the corpse, then takes the lease over.
        assert!(
            store.try_lock_fenced(key, b"Y", 60).unwrap().is_none(),
            "the attempt that finds the corpse reports contention"
        );
        assert_eq!(
            store.try_lock_fenced(key, b"Y", 60).unwrap(),
            Some(2),
            "the next attempt takes the lease over"
        );
        assert!(
            !marker.exists(),
            "a completed takeover must consume the claim that authorized it, \
             or a stalled twin can still use it"
        );

        // X wakes up and finishes the acquisition it started. Nothing on
        // disk backs the claim it staged.
        assert!(
            !consume_claim(&marker, &path, &x_staged).expect("X resumes"),
            "a contender whose claim was reaped must not complete its takeover"
        );
        let (_, generation, holder) = decode_lock(&std::fs::read(&path).expect("read lease"));
        assert_eq!(generation, 2);
        assert_eq!(
            holder,
            hex::encode(b"Y"),
            "the lease still belongs to the contender that actually won it"
        );

        // And the same refusal when the reaper re-created the claim under
        // its own payload: the bytes are not the ones X staged.
        std::fs::write(&marker, encode_lock(unix_now() + 60, 2, b"Y")).expect("reclaim");
        assert!(
            !consume_claim(&marker, &path, &x_staged).expect("X resumes again"),
            "a claim re-created by the reaper is not the claim we made"
        );
    }

    #[test]
    fn a_renewal_refuses_when_the_lease_moved_between_the_read_and_the_write() {
        // The NFS shape the file backend used to lose to. A stalls, its
        // lease expires, B takes over and writes generation 6 under token
        // B; A's heartbeat reads a stale attribute-cached view still
        // showing token A at generation 5, passes a holder check made
        // against that view alone, and blind-writes generation 5 over
        // generation 6. The fence goes backwards, and a superseded holder's
        // certificate is no longer refused at publication.
        let want = hex::encode(b"A");
        let a_view = encode_lock(unix_now() + 60, 5, b"A");
        let b_took_over = encode_lock(unix_now() + 60, 6, b"B");
        assert_eq!(
            renew_cas_decision(&a_view, &b_took_over, &want),
            None,
            "a lease a peer took over must not be renewed out from under it"
        );

        // Same holder, higher generation on disk: still a refusal, because
        // a renewal may never lower a generation.
        let a_regenerated = encode_lock(unix_now() + 60, 6, b"A");
        assert_eq!(
            renew_cas_decision(&a_view, &a_regenerated, &want),
            None,
            "a renewal must never write a generation lower than the one on disk"
        );
        // And a disk view older than the one we read is just as wrong.
        assert_eq!(renew_cas_decision(&a_regenerated, &a_view, &want), None);
        // A lease nobody moved renews at the generation it already carries.
        assert_eq!(renew_cas_decision(&a_view, &a_view, &want), Some(5));
        // A lease that was never ours is refused whichever view says so.
        assert_eq!(renew_cas_decision(&b_took_over, &b_took_over, &want), None);
    }

    #[test]
    fn a_renewal_holds_an_exclusive_claim_across_its_read_and_its_write() {
        // Without the claim the renewal is a read-modify-write with no
        // fence in the conditional, which is how a stale view turns into a
        // regressed generation. The claim is what makes the re-read and the
        // write one critical section across processes; `O_CREAT|O_EXCL` is
        // the primitive a shared filesystem serializes.
        //
        // The claim is the generation's takeover marker, not a name of the
        // renewal's own, and that is load bearing: a renewal and a takeover
        // both finish by renaming their claim onto the lock, so two
        // different names would exclude neither and a renewal mid-stage
        // could land its older generation on top of a takeover that had
        // already published. Planting the marker here is therefore exactly
        // what a contender taking this lease over would do.
        let (store, dir) = make_store();
        let key = b"acme:lock:claim.example";
        assert!(store.try_lock_fenced(key, b"holder", 60).unwrap().is_some());
        let path = dir.path().join(hex::encode(key));
        let (_, generation, _) = decode_lock(&std::fs::read(&path).expect("read lease"));
        let claim = FileKVStore::takeover_marker(&path, generation);

        // A peer is inside the critical section for this same lock.
        std::fs::write(&claim, b"").expect("plant the claim");
        let before = std::fs::read(&path).expect("read lease");
        assert!(
            store.renew_lock(key, b"holder", 60).is_err(),
            "a renewal that cannot take the exclusive claim reports that it could \
             not prove ownership, which is not the same answer as `false` (the \
             lease is somebody else's) and must not be reported as one"
        );
        assert_eq!(
            std::fs::read(&path).expect("read lease"),
            before,
            "and must not have written the lease"
        );

        // An aged claim is a corpse. The beat that finds it clears it and
        // still cannot prove ownership; the next beat renews normally.
        age_out(&claim);
        assert!(store.renew_lock(key, b"holder", 60).is_err());
        assert!(!claim.exists(), "the corpse claim is cleared");
        assert!(
            store.renew_lock(key, b"holder", 60).unwrap(),
            "the next beat renews"
        );
        assert!(
            !claim.exists(),
            "a completed renewal leaves no claim behind to wedge the next one"
        );
        let (_, generation, holder) = decode_lock(&std::fs::read(&path).expect("read lease"));
        assert_eq!(generation, 1, "a renewal keeps the generation");
        assert_eq!(holder, hex::encode(b"holder"));
    }

    #[test]
    fn renewal_holds_a_lease_past_its_original_deadline_and_stops_once_taken() {
        // WOR-2633: an ACME order can outlive any TTL short enough to free a
        // crashed holder promptly, so the holder heartbeats. And once the
        // lease has moved on, renewal has to say so rather than reporting
        // success against a lock somebody else owns.
        let (store, dir) = make_store();
        let key = b"acme:lock:renew.example";
        assert!(store.try_lock_fenced(key, b"holder", 1).unwrap().is_some());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            store.renew_lock(key, b"holder", 60).unwrap(),
            "the holder renews its own lease"
        );
        assert!(
            !store.try_lock(key, b"thief", 60).unwrap(),
            "a renewed lease is not stealable"
        );

        // Age it out and let a peer take it; the old holder must learn.
        let path = dir.path().join(hex::encode(key));
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        assert!(store.try_lock(key, b"successor", 60).unwrap());
        assert!(
            !store.renew_lock(key, b"holder", 60).unwrap(),
            "a superseded holder must not renew"
        );
    }

    #[test]
    fn a_released_lease_is_reacquirable_and_leaves_no_takeover_litter() {
        let (store, dir) = make_store();
        let key = b"acme:lock:litter.example";
        for _ in 0..5 {
            let path = dir.path().join(hex::encode(key));
            assert!(store.try_lock(key, b"holder", 60).unwrap());
            store.unlock(key, b"holder").unwrap();
            let _ = &path;
        }
        let markers = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".take."))
            .count();
        assert!(markers <= 1, "{markers} takeover markers accumulated");
        // The released lease is still invisible to a prefix scan of real keys.
        assert!(store.scan_prefix(b"acme:cert:").unwrap().is_empty());
    }
}
