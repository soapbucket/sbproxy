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
//! serializes one entry, writes it and its newline in a single `write`,
//! and `sync_data`s the file, all under a mutex, before
//! returning. Both halves of that are load-bearing. One write means a
//! process that stops mid-entry cannot leave a payload with no terminator
//! for the next append to merge into, and the `fsync` is what makes the
//! word "written" mean the platter rather than the page cache:
//! `Write::flush` on a `std::fs::File` is a documented no-op, so a ledger
//! that only flushed lost every entry the host had not written back when
//! the power went. That matters more here than for an ordinary log,
//! because a truncated hash chain is still a valid hash chain: the missing
//! entries verify clean and leave no marker anywhere.
//!
//! The cost is one `fsync` per metered event, which is the ledger's
//! throughput ceiling on a spinning disk or a network filesystem. It is
//! paid under the same mutex that already serializes appends, and
//! `sbproxy_meter_append_duration_seconds` measures the whole critical
//! section, so the ceiling is visible rather than inferred. A deployment
//! that cannot pay it wants an unsigned usage sink, not a chain it calls a
//! write-ahead log.
//!
//! On open, the existing file is replayed to rebuild the chain head and
//! the dedup set, so an at-least-once delivery of a payload carrying a
//! dedup key collapses to exactly-once. The replay allocates one `String`
//! per historical dedup key, so the resident cost of a ledger is
//! proportional to the number of entries the file has ever carried; rotate
//! it if that matters.
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
use std::io::{BufRead, Read, Write};
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

    /// The first claim this payload makes that cannot be true, if any.
    ///
    /// Every other check in this module answers "did somebody change these
    /// bytes": the hash chain answers it for the file, the signature
    /// answers it for the writer. Neither answers "does the document agree
    /// with itself". A metered receipt whose unit declares one provenance
    /// while carrying the evidence of another passes both and is still not
    /// evidence of anything, because the whole point of shipping the
    /// evidence beside the count is that a buyer can redo the arithmetic,
    /// and they cannot redo arithmetic over a proof of the wrong kind.
    ///
    /// [`verify_ledger`] and the replay behind [`UsageLedger::open`] both
    /// call this on every entry they decode, so a payload that implements
    /// it is checked on every path that turns bytes back into a record. The
    /// default is `None`, which is the honest answer for a payload with no
    /// internal claim to contradict: `sbproxy-ai`'s usage event carries a
    /// cost and a token count and nothing that could disagree with them.
    ///
    /// Implementations must be pure and allocation-free on the healthy
    /// path. This runs once per entry per chain walk.
    fn provenance_conflict(&self) -> Option<crate::metrics::ProvenanceConflict<'_>> {
        None
    }

    /// Whether an append of this payload belongs on the meter's own chain
    /// instruments.
    ///
    /// `sbproxy_meter_chain_head` reports the head sequence of the chain
    /// this proxy meters from, and `sbproxy_meter_append_duration_seconds`
    /// reports that chain's backpressure. Both are process-wide and
    /// single-valued, so a second chain built on this module does not add
    /// a series to them, it overwrites one. A chain of a payload that is
    /// not usage would leave an operator reading a head sequence that
    /// belongs to a different file and an append latency that belongs to a
    /// different write path.
    ///
    /// Defaults to `true` because the payloads that predate this method
    /// are both usage chains, and their appends are exactly what those two
    /// instruments already describe. Return `false` for a chain that
    /// shares the machinery but not the meaning: the security audit trail
    /// is hash-chained and signed by this same code and is not a meter, so
    /// it opts out here and reports its own latency on the audit channel's
    /// existing histogram instead.
    ///
    /// This is deliberately not a per-instance answer. One ledger writes
    /// one payload type for its whole life, so the question is settled by
    /// the type and asking it per append would imply a chain could change
    /// its mind halfway down a file.
    fn meter_observed() -> bool {
        true
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

/// The ledger's append target.
///
/// A trait rather than a bare [`std::fs::File`] because the two properties
/// that make this file a write-ahead log rather than a cache are both
/// invisible against a real file: that one entry costs exactly one `write`,
/// so a process that stops mid-append cannot leave a payload without its
/// terminator, and that the bytes are forced to stable storage before the
/// append returns. Against a recording sink both are plain assertions, and
/// this module's tests make them, driving the same
/// [`UsageLedger::append_checked`] production takes.
///
/// Boxed rather than a type parameter on [`UsageLedger`] so no caller has to
/// name it. One virtual call per entry is not measurable next to the `fsync`
/// on the next line.
trait LedgerSink: Write {
    /// Forces the bytes already written to stable storage.
    ///
    /// Not named `sync_data`: that is an inherent method on `std::fs::File`
    /// and would win method resolution, which would make a call site that
    /// looks like the trait silently bypass it.
    fn sync_to_disk(&mut self) -> std::io::Result<()>;
}

impl LedgerSink for std::fs::File {
    fn sync_to_disk(&mut self) -> std::io::Result<()> {
        // `sync_data` rather than `sync_all`: a replay reads the file's
        // bytes and its length, and a data sync carries the length.
        self.sync_data()
    }
}

/// Writes one whole line, reporting whether any of it landed.
///
/// [`Write::write_all`] is the obvious call and the wrong one here. It
/// collapses "the device was full and moved nothing" and "half the line is on
/// disk" into one `io::Error`, and only the second leaves an entry the next
/// append would merge into. Treating both as a tear would let a full disk,
/// which is transient and clears on its own, refuse every later append for
/// the life of the process, and the ledger would stay dead long after the
/// space came back.
///
/// One `write` call in the ordinary case, which is the property the append
/// path needs: the entry and its terminator reach the file together, so a
/// process that stops mid-append cannot leave a payload without its newline.
/// The loop only runs again on a short write, which is already the torn case.
fn write_whole_line(
    sink: &mut (dyn LedgerSink + Send),
    mut bytes: &[u8],
) -> std::result::Result<(), (std::io::Error, bool)> {
    let mut landed = false;
    while !bytes.is_empty() {
        match sink.write(bytes) {
            Ok(0) => {
                return Err((
                    std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ledger sink accepted no bytes",
                    ),
                    landed,
                ));
            }
            Ok(written) => {
                landed = true;
                // `Write::write` may not claim more than it was given, but
                // this is a trait object: clamping rather than slicing keeps
                // a sink that breaks that contract from panicking the
                // metering path.
                bytes = bytes.get(written..).unwrap_or(&[]);
            }
            // A signal arrived before the kernel did anything. Not a
            // failure, and not a tear.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err((error, landed)),
        }
    }
    Ok(())
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
    file: Box<dyn LedgerSink + Send>,
    /// Whether a write moved some of an entry's bytes and then failed.
    ///
    /// The bytes that did land have no terminating newline, so the next
    /// append would be concatenated onto them and produce one merged line
    /// that no reader can parse. Refusing every later append keeps the
    /// damage to the one entry that failed.
    ///
    /// Set only when bytes actually landed, which is why the append path
    /// hand-rolls its write loop instead of calling `write_all` (see
    /// [`write_whole_line`]). A write that failed having moved nothing, the
    /// shape a full disk takes, leaves the file intact and this flag clear,
    /// so metering resumes when the space does.
    ///
    /// This only sees a tear this process caused. A tear from a hard kill
    /// mid-write is invisible here, because there is no later append in
    /// this process to refuse; that case is caught by the replay check in
    /// [`UsageLedger::open`] on the next start.
    torn: bool,
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
        let result = (|| {
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

            // Owner-only (`0o600`). The chain is the billing record:
            // per-tenant counts, the signature over them, and enough
            // structure that a reader who can also write could learn
            // where to forge. A file that already exists at a looser
            // mode is tightened rather than inherited, and the open
            // fails if it cannot be, because a ledger nobody else can
            // read is the whole point of signing it.
            let file = sbproxy_util::secure_fs::open_append_owner_only(&path).map_err(|e| {
                anyhow::anyhow!("usage ledger: cannot open {}: {e}", path.display())
            })?;

            Ok(Self {
                path,
                signing_key,
                verifying_key,
                state: parking_lot::Mutex::new(LedgerState {
                    seq,
                    head,
                    seen,
                    file: Box::new(file),
                    torn: false,
                }),
                payload: PhantomData,
            })
        })();
        if result.is_err() && P::meter_observed() {
            LEDGER_HEALTH.store(2, Ordering::Relaxed);
        }
        result
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

        if s.torn {
            anyhow::bail!(
                "usage ledger: {} holds a partially written entry from an earlier failed \
                 append; appending again would merge into it. Verify the file, \
                 truncate the trailing partial line, and restart",
                self.path.display(),
            );
        }

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

        // The entry and its terminator in one buffer, then one write.
        // `writeln!` lowers to two writes, and a process that stops between
        // them leaves a payload with no newline that the next append is
        // concatenated onto; `open` then refuses that file permanently,
        // which under `failure_mode: closed` refuses traffic until somebody
        // edits it by hand.
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        if let Err((error, partial)) = write_whole_line(s.file.as_mut(), line.as_bytes()) {
            if partial {
                // Bytes landed and then the write failed, so the file now
                // ends mid-entry. Nothing in this process may append after
                // that.
                s.torn = true;
                anyhow::bail!(
                    "usage ledger: writing entry {seq} to {} failed partway and left a \
                     partial line; later appends are refused until the file is \
                     truncated and the process restarted: {error}",
                    self.path.display(),
                );
            }
            anyhow::bail!(
                "usage ledger: writing entry {seq} to {} failed before any of it landed, \
                 so the file is intact and a later append can still succeed: {error}",
                self.path.display(),
            );
        }

        // Advanced before the entry is known to be durable, and that order is
        // deliberate. The line is in the file whatever `sync_data` says; a
        // head that did not advance would hand the same sequence number to
        // the next append and put two `seq` values in the chain, which is a
        // worse failure than an entry that is written but not yet on the
        // platter.
        s.seq += 1;
        s.head = entry_hash;
        if let Some(rid) = event.dedup_key() {
            s.seen.insert(rid.to_string());
        }

        // The durability the module doc promises. What used to be here was
        // `Write::flush`, which `std::fs::File` documents as a no-op:
        // `File` writes are unbuffered in userspace, so it moves nothing
        // out of the page cache and every entry a caller was told was
        // written survived only until the host lost power.
        if let Err(error) = s.file.sync_to_disk() {
            anyhow::bail!(
                "usage ledger: entry {seq} was written to {} but could not be forced to \
                 disk: {error}",
                self.path.display(),
            );
        }

        let head_seq = s.seq;
        // Released before observing. An observer is somebody else's code
        // running on the metering path, and holding the chain's only lock
        // across it would make every append wait on a metrics backend.
        drop(s);

        // Gated rather than unconditional: see
        // [`LedgerPayload::meter_observed`]. The two instruments behind
        // this call are single-valued and process-wide, so a non-usage
        // chain reporting into them overwrites the meter's numbers rather
        // than adding its own.
        if P::meter_observed() {
            crate::metrics::observe_chain_append(
                head_seq,
                started.elapsed().as_secs_f64(),
                event.chain_contribution(),
            );
        }
        Ok(Some(entry))
    }

    /// Best-effort append for the sink hot path: errors are logged and
    /// swallowed so a ledger problem can never fail the request it logs.
    ///
    /// The health flag and the gap counter are both meter-scoped, so both
    /// are gated on [`LedgerPayload::meter_observed`] for the same reason
    /// the append instruments are: a chain that is not a meter reporting
    /// into them answers "is this proxy metering" with a fact about some
    /// other file. The warning line is not gated, because a chain that
    /// could not be written to is worth saying out loud whatever the chain
    /// is for.
    pub fn append(&self, event: &P) {
        match self.append_checked(event) {
            Ok(_) => {
                if P::meter_observed() {
                    LEDGER_HEALTH.store(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                if P::meter_observed() {
                    LEDGER_HEALTH.store(2, Ordering::Relaxed);
                }
                // Degraded is not a guess here, it is what this method is.
                // `append` swallows the error and lets the caller carry on,
                // so by the time control reaches this line the request has
                // already been admitted with the guarantee unmade. A caller
                // that wants any other posture has to use `append_checked`
                // and take the branch itself, and report its own gap with
                // the posture it chose.
                if P::meter_observed() {
                    let tenant_id = event
                        .chain_contribution()
                        .map(|contribution| contribution.tenant_id)
                        .unwrap_or_default();
                    crate::metrics::observe_chain_gap(
                        tenant_id,
                        crate::metrics::FailurePosture::Degraded,
                    );
                }
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
///
/// A line that parses and then contradicts itself is treated the same way,
/// through [`LedgerPayload::provenance_conflict`]. That is the deliberate
/// call: an incoherent record is a corrupt record, not a policy question,
/// and chaining more entries onto a chain that already carries one would
/// extend a document nobody can settle from. The refusal is unconditional
/// here; what it does to traffic is the caller's configured posture, which
/// already has to answer for a chain that would not open.
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
        if let Some(conflict) = entry.event.provenance_conflict() {
            crate::metrics::observe_incoherent_receipt(conflict.tenant_id);
            tracing::warn!(
                seq = entry.seq,
                tenant_id = %conflict.tenant_id,
                unit = %conflict.unit,
                declared_source = %conflict.declared_source,
                evidence_source = %conflict.evidence_source,
                path = %path.display(),
                "usage ledger: a chained record contradicts its own provenance"
            );
            return Err(anyhow::anyhow!(
                "usage ledger: entry {} declares source `{}` for unit `{}` while carrying \
                 evidence for `{}`; a record that disagrees with itself is not evidence of \
                 anything",
                entry.seq,
                conflict.declared_source,
                conflict.unit,
                conflict.evidence_source
            ));
        }
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
/// Integrity is not the whole of it. An entry that survives the chain and
/// the signature is then asked, through
/// [`LedgerPayload::provenance_conflict`], whether it agrees with itself,
/// and one that does not is reported as broken with the contradiction
/// spelled out. A verifier that returned `ok` for a record nobody can
/// settle from would be answering a narrower question than the one its
/// caller asked.
///
/// Tolerant where [`UsageLedger::open`] is strict. Damage is reported as a
/// `LedgerVerifyResult` with `ok: false` and the sequence number it stopped
/// at, so an operator learns where the chain broke instead of only that it
/// did. `Err` is reserved for not being able to read the file at all.
pub fn verify_ledger<P: LedgerPayload>(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    verify_ledger_visiting::<P>(path, verifying_key, None, &mut |_| {})
}

/// The walk [`verify_ledger`] is, with two things added for a reader that
/// wants the records as well as the verdict: `visit` is handed every entry
/// that has just passed every check, and `max_record_bytes` caps how much
/// of one record the reader will pull into memory.
///
/// One walk, not two, and that is the point rather than an economy.
/// A reader that verified a file and then re-read it to display it would
/// be showing records it never actually checked, and any writer appending
/// between the two passes would make the verdict describe a different file
/// than the page. Here the entry handed to `visit` is the same value the
/// hash chain, the signature, and the coherence check just passed, so
/// "these records" and "this chain verified" are one statement.
///
/// `max_record_bytes` of `None` is unbounded, which is what
/// [`verify_ledger`] and therefore `sbproxy audit verify` use: an auditor
/// pointed at a damaged file wants the whole answer whatever it costs.
/// A caller serving an HTTP response wants a bound instead, and passes
/// one; a record longer than it stops the walk and is reported as a
/// verification failure rather than being skipped, because a reader that
/// cannot see a record cannot claim the chain across it.
pub fn verify_ledger_visiting<P: LedgerPayload>(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
    max_record_bytes: Option<usize>,
    visit: &mut dyn FnMut(&LedgerEntry<P>),
) -> anyhow::Result<LedgerVerifyResult> {
    let file = std::fs::File::open(path.as_ref()).map_err(|e| {
        anyhow::anyhow!("usage ledger: cannot open {}: {e}", path.as_ref().display())
    })?;
    let mut reader = std::io::BufReader::new(file);
    let cap = max_record_bytes.map_or(u64::MAX, |bytes| bytes as u64);

    let mut expected_seq = 0u64;
    let mut running_head = GENESIS_HASH.to_string();
    let mut count = 0u64;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        // `take` in front of `read_until` is what makes the bound real.
        // `read_until` on its own grows its buffer to the next newline
        // however far away that is, so a file with no newline in it is
        // read whole before anyone gets to check a length.
        let read = (&mut reader)
            .take(cap.saturating_add(1))
            .read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
        }
        if read as u64 > cap {
            let bound = max_record_bytes.unwrap_or(usize::MAX);
            return Ok(LedgerVerifyResult::broken(
                expected_seq,
                count,
                format!(
                    "record at seq {expected_seq} is longer than this reader's {bound}-byte \
                     record bound; verify the file with the CLI, which reads it unbounded"
                ),
            ));
        }
        let line = std::str::from_utf8(&buf).map_err(|e| {
            anyhow::anyhow!("usage ledger: record at seq {expected_seq} is not UTF-8: {e}")
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: LedgerEntry<P> = match serde_json::from_str(line) {
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

        // Last, and after the signature deliberately. Everything above
        // answers "did anybody change these bytes"; this answers "can the
        // bytes be true at all", and reporting it before the integrity
        // checks would tell an operator their receipt is incoherent when
        // the real story is that somebody rewrote it. Reaching this line
        // means the entry is exactly what the writer signed, which is what
        // makes an incoherent one worth alerting on rather than shrugging
        // at: nobody tampered, and it still cannot be settled from.
        if let Some(conflict) = entry.event.provenance_conflict() {
            crate::metrics::observe_incoherent_receipt(conflict.tenant_id);
            tracing::warn!(
                seq = entry.seq,
                tenant_id = %conflict.tenant_id,
                unit = %conflict.unit,
                declared_source = %conflict.declared_source,
                evidence_source = %conflict.evidence_source,
                "usage ledger: a signed, unmodified record contradicts its own provenance"
            );
            let reason = format!(
                "unit `{}` declares source `{}` while carrying evidence for `{}` (the entry is \
                 authentic; it is the claim that cannot be true)",
                conflict.unit, conflict.declared_source, conflict.evidence_source
            );
            return Ok(LedgerVerifyResult::broken(entry.seq, count, reason));
        }

        // Only now, past every check above: what a visitor is handed has
        // been proved unmodified since it was written, which is the whole
        // reason a caller reads records through this function rather than
        // parsing the file itself.
        visit(&entry);

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
    fn a_metered_ledger_open_failure_marks_the_probe_failed() {
        LEDGER_HEALTH.store(0, Ordering::Relaxed);
        let directory = temp_path("open-dir");
        let _ = std::fs::remove_file(&directory);
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temporary directory");

        let result = UsageLedger::<TestPayload>::open(&directory, None);

        assert!(
            result.is_err(),
            "a directory cannot be opened as a ledger file"
        );
        assert_eq!(ledger_health(), LedgerHealth::Failed);
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
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

    // --- WOR-2579: the visiting walk a bounded reader uses ---

    /// The visitor is handed entries only after they pass every check,
    /// and stops being handed them at the first break. A viewer that
    /// rendered a record past the break would be rendering a record no
    /// walk had proved.
    #[test]
    fn a_visiting_walk_stops_handing_over_entries_at_the_break() {
        let path = temp_path("visit-break");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
            for i in 0..4 {
                ledger.append_checked(&event(None, i as f64)).unwrap();
            }
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines[2] = lines[2].replace("\"cost_usd\":2.0", "\"cost_usd\":999.0");
        assert!(lines[2].contains("999.0"), "edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let mut seen: Vec<u64> = Vec::new();
        let res = verify_ledger_visiting::<TestPayload>(&path, None, None, &mut |entry| {
            seen.push(entry.seq);
        })
        .unwrap();

        assert!(!res.ok, "a tampered chain must fail: {res:?}");
        assert_eq!(res.broken_seq, Some(2));
        assert_eq!(seen, vec![0, 1], "only the verified prefix is visited");
        let _ = std::fs::remove_file(&path);
    }

    /// A record longer than the caller's bound stops the walk and is
    /// reported as a verification failure rather than skipped, and the
    /// visitor never sees it. Unbounded, the same file reads clean,
    /// which is what `sbproxy audit verify` does with it.
    #[test]
    fn a_record_over_the_readers_bound_fails_the_walk_rather_than_being_skipped() {
        let path = temp_path("visit-bounded");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<TestPayload>::open(&path, None).unwrap();
            ledger.append_checked(&event(Some("small"), 1.0)).unwrap();
            ledger
                .append_checked(&event(Some(&"x".repeat(4096)), 2.0))
                .unwrap();
        }

        let mut seen: Vec<u64> = Vec::new();
        let bounded = verify_ledger_visiting::<TestPayload>(&path, None, Some(512), &mut |entry| {
            seen.push(entry.seq);
        })
        .unwrap();

        assert!(
            !bounded.ok,
            "a record the reader cannot see is not a verified one: {bounded:?}"
        );
        assert_eq!(bounded.broken_seq, Some(1));
        assert!(
            bounded
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("512-byte record bound"),
            "the verdict names the bound it hit: {bounded:?}"
        );
        assert_eq!(seen, vec![0], "the oversized record is never visited");

        let unbounded = verify_ledger::<TestPayload>(&path, None).unwrap();
        assert!(
            unbounded.ok,
            "unbounded, the same file verifies: {unbounded:?}"
        );
        assert_eq!(unbounded.entries, 2);
        let _ = std::fs::remove_file(&path);
    }

    /// A file with no newline anywhere in it is bounded too. The bound
    /// has to sit in front of the line read rather than behind it:
    /// measuring a record after reading it to the next newline means a
    /// file with no newline is read whole before anyone checks a length.
    #[test]
    fn a_file_with_no_newline_is_still_bounded() {
        let path = temp_path("visit-unterminated");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "z".repeat(64 * 1024)).unwrap();

        let mut seen: Vec<u64> = Vec::new();
        let bounded = verify_ledger_visiting::<TestPayload>(&path, None, Some(256), &mut |e| {
            seen.push(e.seq);
        })
        .unwrap();

        assert!(!bounded.ok, "{bounded:?}");
        assert_eq!(bounded.broken_seq, Some(0));
        assert!(
            bounded
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("256-byte record bound"),
            "the bound has to be what stopped it, not the JSON parse that \
             would also fail on these bytes: {bounded:?}"
        );
        assert!(seen.is_empty(), "nothing was verified, so nothing is shown");
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

    /// A payload that can be told to contradict itself (WOR-2211).
    ///
    /// Separate from [`TestPayload`] rather than a flag on it, so the
    /// existing chain tests keep exercising the default
    /// `provenance_conflict`, which is what a payload with no internal
    /// claim to contradict returns and what most implementors will inherit.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ClaimingPayload {
        /// Who the line is charged to. The attribution a refusal has to
        /// carry: a global count of contradictions tells an operator of a
        /// multi-tenant deployment nothing they can act on.
        tenant: String,
        /// The line the claim is about.
        unit: String,
        /// The provenance the line declares.
        declared_source: String,
        /// Whether the proof it carries is the one `measured` needs.
        evidence_is_measured: bool,
    }

    impl LedgerPayload for ClaimingPayload {
        fn dedup_key(&self) -> Option<&str> {
            None
        }

        fn provenance_conflict(&self) -> Option<crate::metrics::ProvenanceConflict<'_>> {
            let evidence_source = if self.evidence_is_measured {
                "measured"
            } else {
                "origin_header"
            };
            if self.declared_source == evidence_source {
                return None;
            }
            Some(crate::metrics::ProvenanceConflict {
                tenant_id: self.tenant.as_str(),
                unit: self.unit.as_str(),
                declared_source: self.declared_source.as_str(),
                evidence_source,
            })
        }
    }

    fn claiming(declared_source: &str, evidence_is_measured: bool) -> ClaimingPayload {
        ClaimingPayload {
            tenant: "acme".to_string(),
            unit: "result_row".to_string(),
            declared_source: declared_source.to_string(),
            evidence_is_measured,
        }
    }

    #[test]
    fn a_record_that_contradicts_itself_breaks_verification_without_being_tampered_with() {
        // Written through the ledger, so the digests and links are the ones
        // a production writer produces. Nothing here is edited afterwards:
        // an edited line fails on its digest first and would prove nothing
        // about this check.
        let path = temp_path("incoherent");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<ClaimingPayload>::open(&path, None).unwrap();
            ledger.append_checked(&claiming("measured", true)).unwrap();
            ledger.append_checked(&claiming("measured", false)).unwrap();
            ledger.append_checked(&claiming("measured", true)).unwrap();
        }

        let res = verify_ledger::<ClaimingPayload>(&path, None).unwrap();

        assert!(!res.ok, "a record nobody can settle from must not verify");
        assert_eq!(res.broken_seq, Some(1));
        let reason = res.reason.as_deref().expect("a reason");
        assert!(
            reason.contains("measured") && reason.contains("origin_header"),
            "the verdict names both provenances so an operator sees the contradiction: {reason}"
        );
        assert!(
            reason.contains("authentic"),
            "this is not a tampering verdict and must not read as one: {reason}"
        );

        // And the chain will not take another entry, which is what stops
        // the meter extending a document it has already refused.
        assert!(
            UsageLedger::<ClaimingPayload>::open(&path, None).is_err(),
            "an incoherent entry keeps the ledger closed, exactly as a torn tail does"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A payload that shares the chain but is not a meter (WOR-2318).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct UnmeteredPayload {
        note: String,
    }

    impl LedgerPayload for UnmeteredPayload {
        fn dedup_key(&self) -> Option<&str> {
            None
        }

        fn meter_observed() -> bool {
            false
        }
    }

    #[test]
    fn a_payload_can_opt_out_of_the_meter_instruments_and_still_chain() {
        // The opt-out is a property of the payload type, not of the file,
        // so the two halves are asserted separately: the answer itself,
        // and the fact that answering `false` costs the chain nothing.
        //
        // What this cannot assert in this crate is that the gauges did not
        // move. `crate::metrics::observer()` is a process-wide
        // first-write-wins slot that no unit test here may claim, because
        // the one test in `crate::metrics` that installs a recorder would
        // then race this one for it. The instrument-level assertion lives
        // where the observer is real.
        assert!(
            !UnmeteredPayload::meter_observed(),
            "a payload that is not usage says so at the type level"
        );
        assert!(
            TestPayload::meter_observed(),
            "the default is unchanged for the usage payloads that predate it"
        );

        let path = temp_path("unmetered");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<UnmeteredPayload>::open(&path, None).unwrap();
            for index in 0..3 {
                ledger
                    .append_checked(&UnmeteredPayload {
                        note: format!("entry-{index}"),
                    })
                    .unwrap();
            }
        }
        let res = verify_ledger::<UnmeteredPayload>(&path, None).unwrap();
        assert!(
            res.ok,
            "opting out of the meter does not opt out of the chain: {res:?}"
        );
        assert_eq!(res.entries, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_coherent_chain_of_the_same_payload_still_verifies_and_reopens() {
        // The half that stops the refusal being "refuse everything". Same
        // payload type, same writer, every line agreeing with itself.
        let path = temp_path("coherent-claims");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::<ClaimingPayload>::open(&path, None).unwrap();
            ledger.append_checked(&claiming("measured", true)).unwrap();
            ledger
                .append_checked(&claiming("origin_header", false))
                .unwrap();
        }

        let res = verify_ledger::<ClaimingPayload>(&path, None).unwrap();
        assert!(res.ok, "{res:?}");
        assert_eq!(res.entries, 2);
        assert!(UsageLedger::<ClaimingPayload>::open(&path, None).is_ok());
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

    // --- The durability the module doc promises, asserted directly ---

    /// What the sink does with the next `write`.
    ///
    /// The two failure shapes are separate on purpose: only one of them
    /// leaves an entry the next append could merge into, and the append path
    /// is supposed to tell them apart.
    enum SinkStep {
        /// Take the whole buffer.
        Accept,
        /// Take this many bytes and no more, the way a device that filled
        /// up halfway through a line does.
        Partial(usize),
        /// Fail without moving anything, the way a device that was already
        /// full does.
        Fail(std::io::ErrorKind),
    }

    /// What one entry cost the sink.
    #[derive(Default)]
    struct SinkLog {
        /// Every buffer the sink took, in order, holding only the bytes it
        /// actually accepted.
        writes: Vec<Vec<u8>>,
        /// How many times the sink was told to force its bytes to disk.
        syncs: usize,
        /// What the next `write` calls do, in order. An exhausted script
        /// accepts everything.
        script: std::collections::VecDeque<SinkStep>,
    }

    /// An append target that records instead of writing.
    ///
    /// Deliberately counts `write` calls rather than bytes: `writeln!`
    /// lowers to one `write_all` for the payload and a second for the
    /// newline, and the bytes on disk are identical either way. The call
    /// count is the only place the difference shows.
    struct RecordingSink(std::sync::Arc<parking_lot::Mutex<SinkLog>>);

    impl Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut log = self.0.lock();
            match log.script.pop_front().unwrap_or(SinkStep::Accept) {
                SinkStep::Accept => {
                    log.writes.push(buf.to_vec());
                    Ok(buf.len())
                }
                SinkStep::Partial(count) => {
                    let count = count.min(buf.len());
                    log.writes.push(buf[..count].to_vec());
                    Ok(count)
                }
                SinkStep::Fail(kind) => Err(std::io::Error::new(kind, "injected write failure")),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LedgerSink for RecordingSink {
        fn sync_to_disk(&mut self) -> std::io::Result<()> {
            self.0.lock().syncs += 1;
            Ok(())
        }
    }

    /// A ledger whose appends go to `sink` instead of to a file.
    ///
    /// Built by hand rather than through a test-only constructor so nothing
    /// about the append path changes: `append_checked` below is the exact
    /// code the request path runs, and only the target of its one write
    /// differs.
    fn recording_ledger(sink: RecordingSink) -> UsageLedger<TestPayload> {
        UsageLedger {
            path: PathBuf::from("recording-sink.jsonl"),
            signing_key: None,
            verifying_key: None,
            state: parking_lot::Mutex::new(LedgerState {
                seq: 0,
                head: GENESIS_HASH.to_string(),
                seen: HashSet::new(),
                file: Box::new(sink),
                torn: false,
            }),
            payload: PhantomData,
        }
    }

    #[test]
    fn an_append_is_one_write_and_one_forced_sync() {
        let log = std::sync::Arc::new(parking_lot::Mutex::new(SinkLog::default()));
        let ledger = recording_ledger(RecordingSink(std::sync::Arc::clone(&log)));

        ledger
            .append_checked(&event(Some("req-1"), 1.0))
            .expect("append")
            .expect("a fresh dedup key is recorded");

        let log = log.lock();
        assert_eq!(
            log.writes.len(),
            1,
            "an entry and its newline must reach the file in one write; two writes let a \
             stopped process leave a payload the next append merges into",
        );
        let written = &log.writes[0];
        assert_eq!(
            written.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "exactly one terminator, at the end",
        );
        assert_eq!(written.last(), Some(&b'\n'));
        assert_eq!(
            log.syncs, 1,
            "an entry the caller was told was written must have been forced to disk; \
             `Write::flush` on a `File` is a no-op and loses it to a power cut",
        );
    }

    #[test]
    fn a_torn_write_refuses_every_later_append() {
        let log = std::sync::Arc::new(parking_lot::Mutex::new(SinkLog::default()));
        let ledger = recording_ledger(RecordingSink(std::sync::Arc::clone(&log)));

        // Ten bytes land, then the device gives up: the file now ends in a
        // JSON prefix with no newline.
        log.lock().script.extend([
            SinkStep::Partial(10),
            SinkStep::Fail(std::io::ErrorKind::StorageFull),
        ]);
        let failed = ledger.append_checked(&event(Some("req-1"), 1.0));
        assert!(failed.is_err(), "a write that failed is not an append");

        // The bytes that landed have no terminator. Appending after them
        // would produce one merged line that `open` refuses forever, so the
        // ledger refuses now instead.
        let refused = ledger.append_checked(&event(Some("req-2"), 2.0));
        assert!(
            refused.is_err(),
            "a ledger with a partial line must not be extended",
        );
        assert_eq!(
            log.lock().writes.len(),
            1,
            "only the ten torn bytes reached the sink; the refusal happens before \
             anything else is written",
        );
        assert_eq!(log.lock().syncs, 0, "nothing was durable enough to sync");
        assert_eq!(ledger.head().0, 0, "neither entry joined the chain");
    }

    #[test]
    fn a_write_that_moved_nothing_leaves_the_ledger_appendable() {
        let log = std::sync::Arc::new(parking_lot::Mutex::new(SinkLog::default()));
        let ledger = recording_ledger(RecordingSink(std::sync::Arc::clone(&log)));

        // A full disk that rejects the whole line. Nothing landed, so the
        // file still ends on a newline and there is nothing to merge into.
        log.lock()
            .script
            .push_back(SinkStep::Fail(std::io::ErrorKind::StorageFull));
        let failed = ledger.append_checked(&event(Some("req-1"), 1.0));
        assert!(failed.is_err(), "the caller is told the entry was lost");
        assert_eq!(log.lock().writes.len(), 0, "the sink took no bytes");

        // The assertion this test exists for. Treating every write error as
        // a tear would leave metering dead for the life of the process over
        // a condition that clears on its own, and the retry below is what a
        // caller does once the space comes back.
        let retried = ledger
            .append_checked(&event(Some("req-1"), 1.0))
            .expect("a ledger with an intact file still accepts appends")
            .expect("the failed append never recorded its dedup key");
        assert_eq!(retried.seq, 0, "the lost entry did not consume a sequence");
        assert_eq!(ledger.head().0, 1);
        assert_eq!(log.lock().writes.len(), 1);
        assert_eq!(log.lock().syncs, 1);
    }

    /// WOR-2626: the signed ledger is a billing record, so it must not
    /// be readable by other accounts on the host.
    ///
    /// The file is pre-created world-readable rather than left to the
    /// ambient umask, so the assertion is red before the fix on any
    /// runner rather than only on one whose umask happens to be
    /// `0o022`. It covers both halves of the contract at once: a
    /// pre-existing loose file is tightened, and an append to it still
    /// lands.
    #[cfg(unix)]
    #[test]
    fn the_ledger_file_is_owner_only_even_when_it_already_existed() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("owner-only");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").expect("pre-create the ledger");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen the pre-created ledger");

        let ledger = UsageLedger::<TestPayload>::open(&path, None).expect("open the ledger");
        let appended = ledger
            .append_checked(&event(Some("r1"), 1.0))
            .expect("append one entry");
        assert!(appended.is_some(), "a fresh key is not a duplicate");

        let mode = std::fs::metadata(&path)
            .expect("stat the ledger")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "ledger is {mode:o}, not owner-only");
        assert!(
            std::fs::read_to_string(&path)
                .expect("read the ledger")
                .contains("r1"),
            "tightening the mode must not cost the entry"
        );
        let _ = std::fs::remove_file(&path);
    }
}
