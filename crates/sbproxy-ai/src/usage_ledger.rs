//! Verifiable usage ledger: a tamper-evident, optionally Ed25519-signed
//! append log of completed LLM calls.
//!
//! Where a plain usage sink ([`crate::usage_sink`]) ships events outward
//! best-effort and unsigned, the ledger turns the same event stream into
//! a chain you can prove. Each [`LlmUsageEvent`] is hash-chained to the
//! previous entry, so mutating any record breaks every link after it, and
//! with a signing seed configured each entry is Ed25519-signed so spend is
//! attributable to the proxy that recorded it, not merely logged.
//!
//! ## Durability and exactly-once
//!
//! The ledger file is its own write-ahead log: [`UsageLedger::append`]
//! serializes one entry, writes it, and flushes, all under a mutex, before
//! returning. A local append is sub-millisecond, so it stays off the
//! network hot path while never dropping an event under load (the lock is
//! the backpressure). On open, the existing file is replayed to rebuild
//! the chain head and the dedup set, so an at-least-once delivery of an
//! event carrying a `request_id` collapses to exactly-once.
//!
//! ## OSS seam
//!
//! This ships the chain, signing, and local verification. Anchoring
//! receipts to an external transparency log or a portal is an enterprise
//! extension via the plugin trait registry; it consumes the same entries.

use crate::usage_sink::{LlmUsageEvent, UsageSink};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The hex hash that precedes the first real entry.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One link in the ledger chain. Serialized as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Zero-based position in the chain.
    pub seq: u64,
    /// RFC 3339 timestamp at which the entry was recorded. Part of the
    /// hashed material, so it is tamper-evident too.
    pub recorded_at: String,
    /// Hex `entry_hash` of the preceding entry, or [`GENESIS_HASH`] for
    /// the first one.
    pub prev_hash: String,
    /// Hex SHA-256 over `prev_hash || seq || recorded_at || event`.
    pub entry_hash: String,
    /// Hex Ed25519 signature over the raw 32-byte digest, when signing is
    /// enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The completed-call event this entry attests to.
    pub event: LlmUsageEvent,
}

/// Compute the raw SHA-256 digest that binds an entry to its predecessor.
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
struct LedgerState {
    /// Next sequence number to assign (also the count of entries).
    seq: u64,
    /// Hex `entry_hash` of the most recent entry, or genesis.
    head: String,
    /// `request_id`s already recorded, for exactly-once dedup.
    seen: HashSet<String>,
    /// Append handle to the ledger file.
    file: std::fs::File,
}

/// A tamper-evident append log of completed-call usage events.
pub struct UsageLedger {
    path: PathBuf,
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
    state: parking_lot::Mutex<LedgerState>,
}

impl std::fmt::Debug for UsageLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageLedger")
            .field("path", &self.path)
            .field("signed", &self.signing_key.is_some())
            .finish()
    }
}

impl UsageLedger {
    /// Open (or create) the ledger at `path`, optionally enabling signing
    /// with a 32-byte Ed25519 seed in hex. An existing file is replayed to
    /// restore the chain head and dedup set.
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
        let (seq, head, seen) = replay_head(&path)?;

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

    /// Append one event, returning the written entry, or `None` if the
    /// event's `request_id` was already recorded (exactly-once dedup).
    ///
    /// Fallible variant used by tests and the CLI; the [`UsageSink`] impl
    /// swallows and logs errors per the sink contract.
    pub fn append_checked(&self, event: &LlmUsageEvent) -> anyhow::Result<Option<LedgerEntry>> {
        let mut s = self.state.lock();

        if let Some(rid) = event.request_id.as_deref() {
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
        if let Some(rid) = event.request_id.as_deref() {
            s.seen.insert(rid.to_string());
        }
        Ok(Some(entry))
    }

    /// Best-effort append for the sink hot path: errors are logged and
    /// swallowed so a ledger problem can never fail the request it logs.
    pub fn append(&self, event: &LlmUsageEvent) {
        if let Err(e) = self.append_checked(event) {
            tracing::warn!(error = %e, path = %self.path.display(), "usage ledger: append failed");
        }
    }
}

/// Replay an existing ledger file to recover `(next_seq, head_hash,
/// seen_request_ids)`. A missing file yields a fresh genesis state.
fn replay_head(path: &Path) -> anyhow::Result<(u64, String, HashSet<String>)> {
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
        let entry: LedgerEntry = serde_json::from_str(&line)
            .map_err(|e| anyhow::anyhow!("usage ledger: corrupt entry on replay: {e}"))?;
        head = entry.entry_hash;
        seq = entry.seq + 1;
        if let Some(rid) = entry.event.request_id {
            seen.insert(rid);
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
pub fn verify_ledger(
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
        let entry: LedgerEntry = match serde_json::from_str(&line) {
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

/// A [`UsageSink`] that appends every event to a [`UsageLedger`].
#[derive(Debug)]
pub struct LedgerSink {
    /// `None` when the ledger could not be opened; records become no-ops
    /// (the failure was logged once at build time) so a misconfiguration
    /// cannot crash the gateway.
    ledger: Option<Arc<UsageLedger>>,
}

impl LedgerSink {
    /// Build a ledger sink from config, logging and degrading to an inert
    /// sink if the ledger cannot be opened. Returned as a trait object so
    /// it slots into the usage-sink list.
    pub fn build(path: &str, signing_seed_hex: Option<&str>) -> Arc<dyn UsageSink> {
        match Self::try_build(path, signing_seed_hex) {
            Ok(sink) => Arc::new(sink),
            Err(e) => {
                tracing::error!(error = %e, path = %path, "usage ledger: disabled (failed to open); events will not be recorded to this sink");
                Arc::new(LedgerSink { ledger: None })
            }
        }
    }

    /// Fallible constructor used by tests and the CLI verify command.
    pub fn try_build(path: &str, signing_seed_hex: Option<&str>) -> anyhow::Result<Self> {
        let ledger = UsageLedger::open(path, signing_seed_hex)?;
        Ok(Self {
            ledger: Some(Arc::new(ledger)),
        })
    }

    /// The underlying ledger, when active.
    pub fn ledger(&self) -> Option<&Arc<UsageLedger>> {
        self.ledger.as_ref()
    }
}

impl UsageSink for LedgerSink {
    fn record(&self, event: &LlmUsageEvent) {
        if let Some(ledger) = &self.ledger {
            ledger.append(event);
        }
    }

    fn name(&self) -> &str {
        "ledger"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(rid: Option<&str>, cost: f64) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: cost,
            latency_ms: 120,
            status: 200,
            key_id: Some("k1".into()),
            user: None,
            team: None,
            request_id: rid.map(|s| s.to_string()),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-ledger-{}-{}-{tag}.jsonl",
            std::process::id(),
            // a per-test discriminator without needing a clock
            tag.len()
        ))
    }

    #[test]
    fn unsigned_chain_appends_and_verifies() {
        let path = temp_path("unsigned");
        let _ = std::fs::remove_file(&path);
        let ledger = UsageLedger::open(&path, None).unwrap();
        for i in 0..5 {
            ledger.append_checked(&event(None, i as f64)).unwrap();
        }
        let (count, _head) = ledger.head();
        assert_eq!(count, 5);

        let res = verify_ledger(&path, None).unwrap();
        assert!(res.ok, "clean chain verifies: {res:?}");
        assert_eq!(res.entries, 5);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_breaks_verification() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::open(&path, None).unwrap();
            for i in 0..4 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        // Mutate the cost in the second entry's event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"cost_usd\":1.0", "\"cost_usd\":999.0");
        assert!(lines[1].contains("999.0"), "edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let res = verify_ledger(&path, None).unwrap();
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
            let ledger = UsageLedger::open(&path, Some(&seed)).unwrap();
            for i in 0..3 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        let vk = verifying_key_from_seed_hex(&seed).unwrap();
        let res = verify_ledger(&path, Some(&vk)).unwrap();
        assert!(res.ok, "signed chain verifies against its key: {res:?}");

        // A different key must reject the signatures.
        let other = verifying_key_from_seed_hex(&"2".repeat(64)).unwrap();
        let res2 = verify_ledger(&path, Some(&other)).unwrap();
        assert!(!res2.ok, "wrong key must reject");
        assert_eq!(res2.broken_seq, Some(0));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_id_dedup_is_exactly_once_across_reopen() {
        let path = temp_path("dedup");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::open(&path, None).unwrap();
            assert!(ledger
                .append_checked(&event(Some("r1"), 1.0))
                .unwrap()
                .is_some());
            // Same request_id again: deduped.
            assert!(ledger
                .append_checked(&event(Some("r1"), 1.0))
                .unwrap()
                .is_none());
        }
        // Reopen: the seen-set is replayed, so r1 is still deduped.
        let ledger = UsageLedger::open(&path, None).unwrap();
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

        let res = verify_ledger(&path, None).unwrap();
        assert!(res.ok && res.entries == 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_burst_drops_nothing() {
        use std::sync::Arc;
        let path = temp_path("burst");
        let _ = std::fs::remove_file(&path);
        let ledger = Arc::new(UsageLedger::open(&path, None).unwrap());
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
        let res = verify_ledger(&path, None).unwrap();
        assert!(
            res.ok && res.entries == 8 * 50,
            "burst chain verifies: {res:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
