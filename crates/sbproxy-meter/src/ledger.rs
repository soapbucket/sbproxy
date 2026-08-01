// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Verifiable append log: a tamper-evident, optionally Ed25519-signed
//! chain over whatever a proxy meters.
//!
//! Where a plain usage sink ships events outward best-effort and unsigned,
//! the ledger turns the same event stream into a chain you can prove. Each
//! payload is hash-chained to the previous entry, so mutating any record
//! breaks every link after it, and with a signing seed configured each
//! entry is Ed25519-signed so consumption is attributable to the proxy
//! that recorded it, not merely logged by it.
//!
//! ## Generic over the payload, never an enum
//!
//! The chain is generic over [`LedgerPayload`] rather than over a payload
//! enum, and that is a compatibility decision rather than a stylistic one.
//! [`verify_ledger`] re-serializes the payload it just parsed and requires
//! the bytes to match what was written. A tagged enum would add a tag or a
//! wrapper object, change the digest input, and reject every file an
//! earlier binary produced. Monomorphizing at the concrete payload emits
//! exactly the bytes that payload's own `Serialize` emits, so a file
//! written before this module existed still verifies against it.
//!
//! The consequence is worth stating plainly: a payload's serialized form is
//! on-disk contract. Its field declaration order, every
//! `skip_serializing_if`, and the `event` key that carries it are all
//! inputs to a hash somebody may check years after the fact. Reordering a
//! field is a breaking change to files already on disk, and no test in the
//! payload's own crate will notice unless it verifies a golden file.
//!
//! ## Durability and exactly-once
//!
//! The ledger file is its own write-ahead log: [`UsageLedger::append`]
//! serializes one entry, writes it, and flushes, all under a mutex, before
//! returning. A local append is sub-millisecond, so it stays off the
//! network hot path while never dropping an event under load (the lock is
//! the backpressure). On open, the existing file is replayed to rebuild
//! the chain head and the dedup set, so an at-least-once delivery of a
//! payload carrying a dedup key collapses to exactly-once.
//!
//! ## OSS seam
//!
//! This ships the chain, signing, and local verification. Anchoring
//! receipts to an external transparency log or a portal is an enterprise
//! extension via the plugin trait registry; it consumes the same entries.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};

/// The hex hash that precedes the first real entry.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Last usage-ledger append outcome, for the admin `ledger` health probe
/// (WOR-1741). This tracks the append *outcome* rather than recency: the
/// ledger only appends on traffic, so a freshness clock would report an
/// idle-but-healthy ledger as stale. `0` = never appended, `1` = last
/// append ok, `2` = last append failed.
///
/// Deliberately at module scope rather than inside the generic `impl`
/// block. Rust gives each monomorphization of a generic item its own
/// static, so a per-`impl` counter would leave the probe reading whichever
/// payload's copy the linker happened to pick.
static LEDGER_HEALTH: AtomicU8 = AtomicU8::new(0);

/// The outcome of the most recent usage-ledger append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerHealth {
    /// No append has been attempted yet (ledger idle or not configured).
    NeverAppended,
    /// The last append succeeded (or was a dedup no-op).
    Ok,
    /// The last append failed, e.g. a disk or IO error.
    Failed,
}

/// Read the most recent usage-ledger append outcome, for the admin health
/// probe. Traffic-independent, so an idle ledger reports `NeverAppended`
/// (which the probe maps to `NotConfigured`), not a false failure.
///
/// Process-wide across every payload type, because the probe answers "is
/// this proxy's ledger writing" rather than "is this one chain writing".
pub fn ledger_health() -> LedgerHealth {
    match LEDGER_HEALTH.load(Ordering::Relaxed) {
        1 => LedgerHealth::Ok,
        2 => LedgerHealth::Failed,
        _ => LedgerHealth::NeverAppended,
    }
}

/// What a ledger is allowed to attest to.
///
/// Implement this for the record your proxy meters, then use it as the
/// `P` of [`UsageLedger`], [`LedgerEntry`], and [`verify_ledger`]. The
/// implementing type's `Serialize` output is hashed verbatim, so the impl
/// carries a compatibility promise: once a file exists on disk, the
/// payload's serialized shape can no longer change.
pub trait LedgerPayload: Serialize + DeserializeOwned + Clone {
    /// The exactly-once dedup key for this payload, when it has one.
    ///
    /// The ledger records the key of every entry it writes and replays the
    /// set on open, so a payload delivered twice is recorded once.
    /// Returning `None` opts a payload out of dedup entirely, which is the
    /// right answer when no stable identifier exists: two genuinely
    /// distinct events must never collapse into one.
    fn dedup_key(&self) -> Option<&str>;

    /// What this payload contributes to the meter's own reconciliation:
    /// who it is charged to, and how many units it carries.
    ///
    /// Defaults to `None`, which opts the payload out of
    /// `sbproxy_meter_divergence_total` entirely. That is the right default
    /// rather than a lazy one. Divergence compares units the meter counted
    /// against units that reached the chain, so a payload that answers one
    /// side of that comparison and not the other manufactures a
    /// disagreement instead of detecting one. Implement it only for a
    /// payload whose units are also counted through
    /// [`crate::metrics::observe_settled_event`].
    fn chain_contribution(&self) -> Option<crate::metrics::ChainContribution<'_>> {
        None
    }
}

/// One link in the ledger chain. Serialized as a single JSON line.
///
/// The `P` parameter is the attested payload. It is a type parameter and
/// not an enum on purpose; see the module docs for why the distinction is
/// load-bearing for files already written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry<P> {
    /// Zero-based position in the chain.
    pub seq: u64,
    /// RFC 3339 timestamp at which the entry was recorded. Part of the
    /// hashed material, so it is tamper-evident too.
    pub recorded_at: String,
    /// Hex `entry_hash` of the preceding entry, or the genesis hash for
    /// the first one.
    pub prev_hash: String,
    /// Hex SHA-256 over `prev_hash || seq || recorded_at || event`.
    pub entry_hash: String,
    /// Hex Ed25519 signature over the raw 32-byte digest, when signing is
    /// enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The payload this entry attests to.
    ///
    /// The JSON key is `event` and must stay `event`: it is inside the
    /// hashed bytes of every entry ever written.
    pub event: P,
}

/// Compute the raw SHA-256 digest that binds an entry to its predecessor.
///
/// Frozen. Every byte of this layout is reproduced by anyone verifying a
/// file we wrote, so it cannot change without invalidating history:
///
/// - `prev_hash` as 64 lowercase hex ASCII characters, then `\n`
/// - `seq` as 8 raw little-endian bytes, then `\n`
/// - `recorded_at` as its RFC 3339 ASCII, then `\n`
/// - the serialized payload, with no trailing separator
///
/// Ed25519 signs the raw 32 bytes this returns, not the hex string and not
/// the written line.
fn entry_digest(prev_hash: &str, seq: u64, recorded_at: &str, event_json: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(seq.to_le_bytes());
    hasher.update(b"\n");
    hasher.update(recorded_at.as_bytes());
    hasher.update(b"\n");
    hasher.update(event_json);
    hasher.finalize().into()
}

/// Parse a 32-byte Ed25519 seed from hex into a signing key.
fn signing_key_from_seed_hex(seed_hex: &str) -> anyhow::Result<SigningKey> {
    let bytes = hex::decode(seed_hex.trim())
        .map_err(|e| anyhow::anyhow!("usage ledger: signing seed is not valid hex: {e}"))?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "usage ledger: signing seed must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Derive the public verifying key from a 32-byte seed hex. Useful for
/// verifying a ledger written by a known signer.
pub fn verifying_key_from_seed_hex(seed_hex: &str) -> anyhow::Result<VerifyingKey> {
    Ok(signing_key_from_seed_hex(seed_hex)?.verifying_key())
}

/// Mutable, lock-guarded chain state.
///
/// Deliberately not generic. Nothing here depends on the payload, and
/// keeping it payload-free means one copy of the lock and the file handle
/// per ledger rather than one per monomorphization.
struct LedgerState {
    /// Next sequence number to assign (also the count of entries).
    seq: u64,
    /// Hex `entry_hash` of the most recent entry, or genesis.
    head: String,
    /// Dedup keys already recorded, for exactly-once dedup.
    seen: HashSet<String>,
    /// Append handle to the ledger file.
    file: std::fs::File,
}

/// A tamper-evident append log of metered payloads.
///
/// `P` is the attested payload type. It appears only in the methods, so the
/// struct carries a `PhantomData` marker rather than a field: one ledger
/// writes one payload type for its whole life, and mixing two in a file
/// would break the re-serialize check on verification.
pub struct UsageLedger<P> {
    path: PathBuf,
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
    state: parking_lot::Mutex<LedgerState>,
    payload: PhantomData<fn() -> P>,
}

impl<P> std::fmt::Debug for UsageLedger<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageLedger")
            .field("path", &self.path)
            .field("signed", &self.signing_key.is_some())
            .finish()
    }
}

impl<P: LedgerPayload> UsageLedger<P> {
    /// Open (or create) the ledger at `path`, optionally enabling signing
    /// with a 32-byte Ed25519 seed in hex. An existing file is replayed to
    /// restore the chain head and dedup set.
    ///
    /// Stricter than [`verify_ledger`] on purpose. A file whose last line
    /// is torn cannot be appended to safely, because the next entry would
    /// chain onto a head that was never fully written, so this returns
    /// `Err` and keeps returning it until a person looks. Verification of
    /// the same file reports a broken result instead, because reading a
    /// damaged chain to find out where it broke is exactly what an
    /// investigator wants.
    pub fn open(path: impl AsRef<Path>, signing_seed_hex: Option<&str>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (signing_key, verifying_key) = match signing_seed_hex {
            Some(seed) => {
                let sk = signing_key_from_seed_hex(seed)?;
                let vk = sk.verifying_key();
                (Some(sk), Some(vk))
            }
            None => (None, None),
        };

        // Replay any existing chain to restore head + dedup set.
        let (seq, head, seen) = replay_head::<P>(&path)?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("usage ledger: cannot open {}: {e}", path.display()))?;

        Ok(Self {
            path,
            signing_key,
            verifying_key,
            state: parking_lot::Mutex::new(LedgerState {
                seq,
                head,
                seen,
                file,
            }),
            payload: PhantomData,
        })
    }

    /// The public verifying key, when signing is enabled.
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        self.verifying_key
    }

    /// The ledger file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current `(entry_count, head_hash)`.
    pub fn head(&self) -> (u64, String) {
        let s = self.state.lock();
        (s.seq, s.head.clone())
    }

    /// Append one payload, returning the written entry, or `None` if the
    /// payload's dedup key was already recorded (exactly-once dedup).
    ///
    /// Fallible variant used by tests and the CLI; callers on the request
    /// hot path use [`UsageLedger::append`], which swallows and logs
    /// errors per the sink contract.
    pub fn append_checked(&self, event: &P) -> anyhow::Result<Option<LedgerEntry<P>>> {
        // Started before the lock, not after it. The mutex is the metering
        // path's backpressure, so time spent waiting for it is exactly the
        // time `sbproxy_meter_append_duration_seconds` exists to show; a
        // timer that starts inside the critical section reports a healthy
        // sub-millisecond write while callers queue behind it.
        let started = std::time::Instant::now();
        let mut s = self.state.lock();

        if let Some(rid) = event.dedup_key() {
            if s.seen.contains(rid) {
                return Ok(None);
            }
        }

        let seq = s.seq;
        let prev_hash = s.head.clone();
        let recorded_at = chrono::Utc::now().to_rfc3339();
        let event_json = serde_json::to_vec(event)?;
        let digest = entry_digest(&prev_hash, seq, &recorded_at, &event_json);
        let entry_hash = hex::encode(digest);
        let signature = self
            .signing_key
            .as_ref()
            .map(|sk| hex::encode(sk.sign(&digest).to_bytes()));

        let entry = LedgerEntry {
            seq,
            recorded_at,
            prev_hash,
            entry_hash: entry_hash.clone(),
            signature,
            event: event.clone(),
        };

        let line = serde_json::to_string(&entry)?;
        writeln!(s.file, "{line}")?;
        s.file.flush()?;

        s.seq += 1;
        s.head = entry_hash;
        if let Some(rid) = event.dedup_key() {
            s.seen.insert(rid.to_string());
        }
        let head_seq = s.seq;
        // Released before observing. An observer is somebody else's code
        // running on the metering path, and holding the chain's only lock
        // across it would make every append wait on a metrics backend.
        drop(s);

        crate::metrics::observe_chain_append(
            head_seq,
            started.elapsed().as_secs_f64(),
            event.chain_contribution(),
        );
        Ok(Some(entry))
    }

    /// Best-effort append for the sink hot path: errors are logged and
    /// swallowed so a ledger problem can never fail the request it logs.
    pub fn append(&self, event: &P) {
        match self.append_checked(event) {
            Ok(_) => LEDGER_HEALTH.store(1, Ordering::Relaxed),
            Err(e) => {
                LEDGER_HEALTH.store(2, Ordering::Relaxed);
                // Degraded is not a guess here, it is what this method is.
                // `append` swallows the error and lets the caller carry on,
                // so by the time control reaches this line the request has
                // already been admitted with the guarantee unmade. A caller
                // that wants any other posture has to use `append_checked`
                // and take the branch itself, and report its own gap with
                // the posture it chose.
                let tenant_id = event
                    .chain_contribution()
                    .map(|contribution| contribution.tenant_id)
                    .unwrap_or_default();
                crate::metrics::observe_chain_gap(
                    tenant_id,
                    crate::metrics::FailurePosture::Degraded,
                );
                tracing::warn!(error = %e, path = %self.path.display(), "usage ledger: append failed");
            }
        }
    }
}

/// Replay an existing ledger file to recover `(next_seq, head_hash,
/// seen_dedup_keys)`. A missing file yields a fresh genesis state.
///
/// Intolerant by design: a line that will not parse aborts the replay with
/// an error rather than being skipped, because appending past damage would
/// write a chain that can never be verified end to end.
fn replay_head<P: LedgerPayload>(path: &Path) -> anyhow::Result<(u64, String, HashSet<String>)> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, GENESIS_HASH.to_string(), HashSet::new()));
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "usage ledger: cannot read {}: {e}",
                path.display()
            ))
        }
    };
    let reader = std::io::BufReader::new(file);
    let mut seq = 0u64;
    let mut head = GENESIS_HASH.to_string();
    let mut seen = HashSet::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry<P> = serde_json::from_str(&line)
            .map_err(|e| anyhow::anyhow!("usage ledger: corrupt entry on replay: {e}"))?;
        head = entry.entry_hash;
        seq = entry.seq + 1;
        if let Some(rid) = entry.event.dedup_key() {
            seen.insert(rid.to_string());
        }
    }
    Ok((seq, head, seen))
}

/// Outcome of verifying a ledger file end to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerVerifyResult {
    /// Number of entries read.
    pub entries: u64,
    /// True when every link (and signature, if a key was supplied) checks
    /// out.
    pub ok: bool,
    /// Sequence number of the first broken entry, when `ok` is false.
    pub broken_seq: Option<u64>,
    /// Human-readable failure reason, when `ok` is false.
    pub reason: Option<String>,
}

impl LedgerVerifyResult {
    fn broken(seq: u64, entries: u64, reason: impl Into<String>) -> Self {
        Self {
            entries,
            ok: false,
            broken_seq: Some(seq),
            reason: Some(reason.into()),
        }
    }
}

/// Verify a ledger file: re-derive the hash chain from genesis and, when a
/// `verifying_key` is supplied, check every entry's signature. Reports the
/// first broken link.
///
/// Tolerant where [`UsageLedger::open`] is strict. Damage is reported as a
/// `LedgerVerifyResult` with `ok: false` and the sequence number it stopped
/// at, so an operator learns where the chain broke instead of only that it
/// did. `Err` is reserved for not being able to read the file at all.
pub fn verify_ledger<P: LedgerPayload>(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    let file = std::fs::File::open(path.as_ref()).map_err(|e| {
        anyhow::anyhow!("usage ledger: cannot open {}: {e}", path.as_ref().display())
    })?;
    let reader = std::io::BufReader::new(file);

    let mut expected_seq = 0u64;
    let mut running_head = GENESIS_HASH.to_string();
    let mut count = 0u64;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry<P> = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                return Ok(LedgerVerifyResult::broken(
                    expected_seq,
                    count,
                    format!("unparseable entry: {e}"),
                ))
            }
        };

        if entry.seq != expected_seq {
            return Ok(LedgerVerifyResult::broken(
                entry.seq,
                count,
                format!(
                    "out-of-order seq: expected {expected_seq}, found {}",
                    entry.seq
                ),
            ));
        }
        if entry.prev_hash != running_head {
            return Ok(LedgerVerifyResult::broken(
                entry.seq,
                count,
                "prev_hash does not match the running chain head",
            ));
        }

        let event_json = match serde_json::to_vec(&entry.event) {
            Ok(j) => j,
            Err(e) => {
                return Ok(LedgerVerifyResult::broken(
                    entry.seq,
                    count,
                    format!("event re-serialize failed: {e}"),
                ))
            }
        };
        let digest = entry_digest(&entry.prev_hash, entry.seq, &entry.recorded_at, &event_json);
        let recomputed = hex::encode(digest);
        if recomputed != entry.entry_hash {
            return Ok(LedgerVerifyResult::broken(
                entry.seq,
                count,
                "entry_hash does not match recomputed digest (tampered event)",
            ));
        }

        if let Some(vk) = verifying_key {
            let sig_hex = match entry.signature.as_deref() {
                Some(s) => s,
                None => {
                    return Ok(LedgerVerifyResult::broken(
                        entry.seq,
                        count,
                        "expected a signature but entry is unsigned",
                    ))
                }
            };
            let sig_bytes = match hex::decode(sig_hex) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(LedgerVerifyResult::broken(
                        entry.seq,
                        count,
                        format!("signature is not valid hex: {e}"),
                    ))
                }
            };
            let signature = match Signature::from_slice(&sig_bytes) {
                Ok(s) => s,
                Err(e) => {
                    return Ok(LedgerVerifyResult::broken(
                        entry.seq,
                        count,
                        format!("malformed signature: {e}"),
                    ))
                }
            };
            if vk.verify_strict(&digest, &signature).is_err() {
                return Ok(LedgerVerifyResult::broken(
                    entry.seq,
                    count,
                    "signature does not verify against the supplied key",
                ));
            }
        }

        running_head = entry.entry_hash;
        expected_seq += 1;
        count += 1;
    }

    Ok(LedgerVerifyResult {
        entries: count,
        ok: true,
        broken_seq: None,
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload with the same shape the chain cares about: a dedup key and
    /// a value that changes per entry. Deliberately not the AI gateway's
    /// event, so these tests fail if the chain ever grows a dependency on
    /// one particular payload.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestPayload {
        request_id: Option<String>,
        cost_usd: f64,
    }

    impl LedgerPayload for TestPayload {
        fn dedup_key(&self) -> Option<&str> {
            self.request_id.as_deref()
        }
    }

    fn event(rid: Option<&str>, cost: f64) -> TestPayload {
        TestPayload {
            request_id: rid.map(|s| s.to_string()),
            cost_usd: cost,
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-meter-ledger-{}-{}-{tag}.jsonl",
            std::process::id(),
            // a per-test discriminator without needing a clock
            tag.len()
        ))
    }

    #[test]
    fn unsigned_chain_appends_and_verifies() {
        let path = temp_path("unsigned");
        let _ = std::fs::remove_file(&path);
        let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
        for i in 0..5 {
            ledger.append_checked(&event(None, i as f64)).unwrap();
        }
        let (count, _head) = ledger.head();
        assert_eq!(count, 5);

        let res = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(res.ok, "clean chain verifies: {res:?}");
        assert_eq!(res.entries, 5);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_breaks_verification() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
            for i in 0..4 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        // Mutate the cost in the second entry's payload.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"cost_usd\":1.0", "\"cost_usd\":999.0");
        assert!(lines[1].contains("999.0"), "edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let res = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(!res.ok, "tampered chain must fail");
        assert_eq!(res.broken_seq, Some(1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn signed_entries_verify_and_forgery_is_rejected() {
        let path = temp_path("signed");
        let _ = std::fs::remove_file(&path);
        // 32-byte seed in hex.
        let seed = "1".repeat(64);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, Some(&seed)).unwrap();
            for i in 0..3 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        let vk = verifying_key_from_seed_hex(&seed).unwrap();
        let res = verify_ledger::<TestPayload>(&path, Some(&vk)).unwrap();
        assert!(res.ok, "signed chain verifies against its key: {res:?}");

        // A different key must reject the signatures.
        let other = verifying_key_from_seed_hex(&"2".repeat(64)).unwrap();
        let res2 = verify_ledger::<TestPayload>(&path, Some(&other)).unwrap();
        assert!(!res2.ok, "wrong key must reject");
        assert_eq!(res2.broken_seq, Some(0));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dedup_key_is_exactly_once_across_reopen() {
        let path = temp_path("dedup");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
            assert!(ledger
                .append_checked(&event(Some("r1"), 1.0))
                .unwrap()
                .is_some());
            // Same dedup key again: deduped.
            assert!(ledger
                .append_checked(&event(Some("r1"), 1.0))
                .unwrap()
                .is_none());
        }
        // Reopen: the seen-set is replayed, so r1 is still deduped.
        let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
        assert!(ledger
            .append_checked(&event(Some("r1"), 1.0))
            .unwrap()
            .is_none());
        assert!(ledger
            .append_checked(&event(Some("r2"), 2.0))
            .unwrap()
            .is_some());
        let (count, _) = ledger.head();
        assert_eq!(count, 2, "only r1 and r2 recorded");

        let res = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(res.ok && res.entries == 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_burst_drops_nothing() {
        use std::sync::Arc;
        let path = temp_path("burst");
        let _ = std::fs::remove_file(&path);
        let ledger = Arc::new(UsageLedger::<TestPayload>::open(&path, None).unwrap());
        let mut handles = Vec::new();
        for t in 0..8 {
            let l = ledger.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    l.append(&event(Some(&format!("r-{t}-{i}")), i as f64));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let (count, _) = ledger.head();
        assert_eq!(count, 8 * 50, "every event in the burst landed");
        let res = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(
            res.ok && res.entries == 8 * 50,
            "burst chain verifies: {res:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_torn_final_line_fails_open_but_only_breaks_verify() {
        let path = temp_path("torn");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
            for i in 0..3 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        // Truncate the last line mid-JSON, the way a crash mid-write does.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let last = lines.pop().unwrap();
        lines.push(last[..last.len() / 2].to_string());
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // open() refuses: appending past damage writes a chain nobody can
        // verify end to end.
        assert!(
            UsageLedger::<TestPayload>::open(&path, None).is_err(),
            "a torn tail must keep the ledger closed"
        );
        // verify_ledger() reports instead of refusing, so an operator can
        // see where the damage starts.
        let res = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(!res.ok, "torn tail must not verify");
        assert_eq!(res.broken_seq, Some(2));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_nodes_chains_verify_independently_and_are_never_interleaved() {
        // Chains are per node and are never merged (WOR-2130), because
        // merging means re-linking and a re-linked chain proves only that
        // somebody re-linked it. The two files below are written with
        // identical claim ids on purpose: that is the case a merged chain
        // would silently collapse, and two chains keyed by
        // `crate::segment::ClaimKey` cannot, because the node that minted a
        // claim is part of the claim's identity.
        let dir = std::env::temp_dir().join(format!("sb-meter-nodes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let paths = [dir.join("node-a.jsonl"), dir.join("node-b.jsonl")];
        for path in &paths {
            let _ = std::fs::remove_file(path);
        }

        for (node_id, path) in ["node-a", "node-b"].iter().zip(paths.iter()) {
            let ledger = UsageLedger::<TestPayload>::open(path, None).unwrap();
            for index in 0..5 {
                let claim = crate::segment::ClaimKey::new(*node_id, format!("claim-{index}"));
                let claim_id = claim.to_string();
                ledger
                    .append_checked(&event(Some(&claim_id), index as f64))
                    .unwrap();
            }
            let (count, _head) = ledger.head();
            assert_eq!(count, 5, "{node_id} recorded exactly its own five entries");
        }

        // Each chain verifies against its own genesis, with no reference to
        // the other and no shared state anywhere between them.
        let mut contents = Vec::new();
        for path in &paths {
            let result = verify_ledger::<TestPayload>(path, None).unwrap();
            assert!(result.ok, "each node's chain verifies alone: {result:?}");
            assert_eq!(result.entries, 5);
            contents.push(std::fs::read_to_string(path).unwrap());
        }
        assert_ne!(
            contents[0], contents[1],
            "identical claim ids on two nodes still produce two distinct chains"
        );

        for path in &paths {
            let _ = std::fs::remove_file(path);
        }
    }
}
