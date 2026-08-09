// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Tamper-evident security audit trail (WOR-2318).
//!
//! The `security_audit` tracing target has always been a stream. Whoever
//! can write the log file can rewrite it, delete a line out of the middle,
//! and leave nothing behind that says so, which makes it a record of what
//! the proxy said rather than a record of what happened. This module gives
//! that one channel a durable form where the difference is detectable.
//!
//! # There is one chain in this workspace and this is not a second one
//!
//! Every byte of the hashing, signing, replay, and verification here comes
//! from [`sbproxy_meter::ledger`], unmodified. That module was already
//! generic over its payload, and `sbproxy-ai` already binds it to a second
//! payload of its own, so binding it to a third is the whole
//! implementation: [`SecurityAuditEntry`] implements
//! [`LedgerPayload`] and everything else follows.
//!
//! What the chain gives, in its own words and reproduced here so an
//! operator does not have to read the meter to know what they have:
//!
//! * each entry is `SHA-256(prev_hash || seq || recorded_at || event)`, so
//!   editing any record breaks that record's digest and the `prev_hash` of
//!   every record after it;
//! * each entry carries an Ed25519 signature over the raw 32-byte digest,
//!   so a record is attributable to the proxy that wrote it and cannot be
//!   re-forged by somebody who only has write access to the file;
//! * the file is its own write-ahead log. One append serializes, writes,
//!   and flushes under a mutex before returning, so a record that reached
//!   the file survives the process;
//! * verification re-derives the whole chain from genesis and reports the
//!   first sequence number that does not check out.
//!
//! # What it deliberately does not inherit
//!
//! The meter's chain reports into `sbproxy_meter_chain_head`,
//! `sbproxy_meter_append_duration_seconds`,
//! `sbproxy_meter_chain_gap_total`, and the process-wide `ledger` health
//! probe. All four answer "is this proxy metering", and all four are
//! single-valued, so an audit append landing on them would overwrite a
//! billing number with a fact about a different file.
//! [`LedgerPayload::meter_observed`] returns `false` here for that reason,
//! and audit-append latency lands instead on the histogram the audit
//! channel already has,
//! `sbproxy_audit_emit_duration_seconds{channel="security"}`.
//!
//! Nor does it inherit the meter's `degraded` failure default. That
//! default is justified in the metering runtime by "billing is not a
//! security boundary", and the argument does not carry across: an operator
//! who set `audit.sink: chain` asked for a trail, so a chain that will not
//! open fails the boot rather than serving traffic whose security events
//! go unrecorded. See [`SecurityAuditChain::open`].
//!
//! # Keys
//!
//! No new key story. The chain signs with the proxy's one Ed25519
//! identity, `proxy.web_bot_auth` (`key_id` as the `kid`,
//! `ed25519_seed_hex` as the 32-byte seed), which is the same identity
//! `proxy.attestation.sign_with` names for the receipt chain. A deployment
//! that already publishes that key can hand an auditor the public half and
//! the file and nothing else.
//!
//! # What a record may carry
//!
//! Exactly the fields [`SecurityAuditEntry`] already ships to the
//! `security_audit` tracing target, byte for byte, and nothing added here.
//! That type is documented as secret-free and the durability makes the
//! promise load bearing rather than merely tidy: a credential written into
//! a hash chain cannot be quietly removed later, because quiet removal is
//! the thing the chain exists to prevent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use sbproxy_meter::ledger::{LedgerPayload, UsageLedger};

pub use ed25519_dalek::VerifyingKey;
pub use sbproxy_meter::ledger::{verifying_key_from_seed_hex, LedgerVerifyResult};

use crate::audit::SecurityAuditEntry;

/// A security audit entry is chained one-for-one with the event it
/// records.
///
/// `dedup_key` is `None`, and that is the deliberate answer rather than a
/// missing feature. The ledger's dedup collapses two deliveries of one
/// event, which is right for a usage record that may be retried and wrong
/// for a denial: two requests from the same client, in the same second,
/// refused by the same rule, are two refusals. `request_id` looks like a
/// key and is not one, because an entry can be emitted without one and a
/// single request can be denied more than once as it passes different
/// gates. Collapsing either case would under-report an attack.
///
/// `meter_observed` is `false`: see the module docs.
impl LedgerPayload for SecurityAuditEntry {
    fn dedup_key(&self) -> Option<&str> {
        None
    }

    fn meter_observed() -> bool {
        false
    }
}

/// The hash-chained, signed security audit trail for this process.
///
/// One file, one payload type, opened once at boot and held for the life
/// of the process. A reload does not reopen it: the chain is append-only
/// and reopening under a new configuration mid-life would either continue
/// a file the new configuration does not name or start a second one that
/// looks like a gap.
pub struct SecurityAuditChain {
    /// The chain itself. Owns the file handle, the sequence counter, and
    /// the signing key.
    ledger: UsageLedger<SecurityAuditEntry>,
    /// Where the chain lives, kept for log lines.
    path: PathBuf,
    /// The `kid` of the signing identity. The public selector, never the
    /// key.
    key_id: String,
    /// Whether the most recent append failed.
    ///
    /// Exists only to keep the failure log line from firing once per
    /// denied request. A full disk during an attack would otherwise turn
    /// one problem into two.
    degraded: AtomicBool,
}

impl std::fmt::Debug for SecurityAuditChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand written, not derived. `ledger` holds a signing key, and
        // while `UsageLedger` redacts its own `Debug`, a derive here would
        // be one added field away from printing whatever that field holds.
        formatter
            .debug_struct("SecurityAuditChain")
            .field("path", &self.path)
            .field("kid", &self.key_id)
            .field("degraded", &self.degraded.load(Ordering::Relaxed))
            .finish()
    }
}

impl SecurityAuditChain {
    /// Open (or create) the chain at `path`, signing every entry with the
    /// 32-byte Ed25519 seed `seed_hex` under the key id `key_id`.
    ///
    /// Fails, rather than degrading, on every problem it can hit: a parent
    /// directory that cannot be created, a seed that is not 32 bytes of
    /// hex, a file that cannot be appended to, or an existing file whose
    /// last line is torn. The caller is boot, so the failure is a proxy
    /// that does not start.
    ///
    /// That is the opposite of what the metering chain does with the same
    /// conditions, and the difference is the point. Metering defaults to
    /// `degraded` because a full ledger disk must not take an API down and
    /// billing can be reconciled afterwards. An audit trail cannot: the
    /// events that would have gone in the hole are the ones an
    /// investigator needs, and there is no later moment at which they can
    /// be recovered. An operator who does not want that trade has not set
    /// `audit.sink: chain`.
    pub fn open(path: &Path, seed_hex: &str, key_id: &str) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    anyhow::anyhow!(
                        "audit.path {}: cannot create the directory {}: {error}",
                        path.display(),
                        parent.display()
                    )
                })?;
            }
        }
        let ledger = UsageLedger::<SecurityAuditEntry>::open(path, Some(seed_hex))
            .map_err(|error| anyhow::anyhow!("audit.path {}: {error}", path.display()))?;
        Ok(Self {
            ledger,
            path: path.to_path_buf(),
            key_id: key_id.to_string(),
            degraded: AtomicBool::new(false),
        })
    }

    /// The `kid` this chain signs under, so boot can say which key an
    /// auditor will need without going near the seed.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Append one entry, absorbing any failure.
    ///
    /// Deliberately infallible from the caller's side. This runs from
    /// `SecurityAuditEntry::emit`, which runs on the request path from
    /// inside policy denials and auth failures, and a caller there has
    /// nothing useful to do with an error: the request is already being
    /// refused, and failing it a second way would turn a full disk into an
    /// outage.
    ///
    /// A failure is loud once and then quiet. The first one, and the first
    /// one after any recovery, is logged at `error` on the
    /// `security_audit` target itself, which is the pipe an operator is
    /// already watching for security events and therefore the right place
    /// to learn that the pipe has a hole in it. Repeats are suppressed so
    /// an attack against a proxy with a full disk does not also produce
    /// one log line per refused request.
    fn append(&self, entry: &SecurityAuditEntry) {
        match self.ledger.append_checked(entry) {
            Ok(_) => {
                if self.degraded.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        target: "security_audit",
                        path = %self.path.display(),
                        kid = %self.key_id,
                        "security audit chain is writable again; entries recorded while it was \
                         not are absent from the chain and cannot be backfilled"
                    );
                }
            }
            Err(error) => {
                if !self.degraded.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        target: "security_audit",
                        %error,
                        path = %self.path.display(),
                        kid = %self.key_id,
                        "security audit chain append failed; security events are still being \
                         logged but are no longer entering the tamper-evident trail"
                    );
                }
            }
        }
    }
}

/// The process-wide chain, or nothing when `audit.sink` does not ask for
/// one.
///
/// A `OnceLock` rather than a swappable handle for the same reason the
/// session-ledger sink is one: the chain is append-only and set once at
/// boot, and a reload that replaced it would leave two files each of which
/// looks complete and neither of which is.
static CHAIN: OnceLock<SecurityAuditChain> = OnceLock::new();

/// Register the process-wide security audit chain. Returns `Err` if one
/// was already registered. Call once at startup.
pub fn install_security_audit_chain(chain: SecurityAuditChain) -> Result<(), &'static str> {
    CHAIN
        .set(chain)
        .map_err(|_| "security audit chain already registered")
}

/// Append one entry to the chain, if one is installed.
///
/// Called from [`SecurityAuditEntry::emit`]. With no chain configured this
/// is one relaxed load and a return, which is what keeps the default
/// deployment paying nothing for a feature it did not turn on.
pub(crate) fn append_security_audit(entry: &SecurityAuditEntry) {
    if let Some(chain) = CHAIN.get() {
        chain.append(entry);
    }
}

/// Re-derive a security audit chain from genesis and report the first
/// broken link.
///
/// Pass the verifying key to check signatures as well as the chain; pass
/// `None` to check only that the links hold. An auditor with the public
/// key and the file needs nothing else, and in particular does not need to
/// trust the binary that wrote it: the digest layout is documented in
/// [`sbproxy_meter::ledger`] and is reproducible from any Ed25519 and
/// SHA-256 implementation.
///
/// `Err` means the file could not be read at all. Damage inside a readable
/// file comes back as a [`LedgerVerifyResult`] with `ok: false` and the
/// sequence number it stopped at, because an investigator wants to know
/// where the chain broke rather than only that it did.
pub fn verify_security_audit_chain(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<SecurityAuditEntry>(path, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-byte seed in hex, distinct per test so two chains never share
    /// a key by accident.
    fn seed(tag: u8) -> String {
        format!("{tag:02x}").repeat(32)
    }

    /// Open a chain for a test, panicking on the failures the tests that
    /// care about failure assert on directly. Keeps the call sites short
    /// enough that `cargo fmt` has nothing to say about them.
    fn open_chain(path: &Path, seed_hex: &str) -> SecurityAuditChain {
        SecurityAuditChain::open(path, seed_hex, "audit-kid").expect("chain opens")
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sb-audit-chain-{}-{tag}.jsonl", std::process::id()))
    }

    fn denial(reason: &str) -> SecurityAuditEntry {
        SecurityAuditEntry::policy_violation(
            "rate_limit",
            reason,
            429,
            Some("api.example.com".to_string()),
            Some("203.0.113.7".parse().unwrap()),
            Some(format!("req-{reason}")),
            Some("POST".to_string()),
        )
        .with_tenant_id("acme")
        .with_api_key_id(Some("sbp_public_key_id"))
    }

    #[test]
    fn a_signed_chain_of_denials_verifies_against_its_key() {
        let path = temp_path("valid");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x11);
        {
            let chain = open_chain(&path, &seed);
            for index in 0..4 {
                chain.append(&denial(&format!("burst-{index}")));
            }
        }

        let key = verifying_key_from_seed_hex(&seed).expect("seed derives a public key");
        let result = verify_security_audit_chain(&path, Some(&key)).expect("file is readable");
        assert!(result.ok, "an untouched chain verifies: {result:?}");
        assert_eq!(result.entries, 4);
        assert_eq!(result.broken_seq, None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_mutated_record_fails_verification_at_the_record_that_moved() {
        let path = temp_path("mutated");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x22);
        {
            let chain = open_chain(&path, &seed);
            chain.append(&denial("first"));
            chain.append(&denial("second"));
            chain.append(&denial("third"));
        }

        // The edit an insider makes: soften the record of one denial and
        // leave the rest of the file alone.
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 3, "three entries were written");
        lines[1] = lines[1].replace("\"reason\":\"second\"", "\"reason\":\"allowed\"");
        assert!(lines[1].contains("allowed"), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        // The chain alone catches it, with no key involved: the digest no
        // longer matches the bytes.
        let unsigned = verify_security_audit_chain(&path, None).expect("file is readable");
        assert!(!unsigned.ok, "a mutated record must not verify");
        assert_eq!(unsigned.broken_seq, Some(1));
        let reason = unsigned.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("tampered"),
            "the verdict says what happened: {reason}"
        );

        // And so does the signed check, which is the one an auditor runs.
        let key = verifying_key_from_seed_hex(&seed).expect("seed derives a public key");
        let signed = verify_security_audit_chain(&path, Some(&key)).expect("file is readable");
        assert!(!signed.ok, "a mutated record must not verify under the key");
        assert_eq!(signed.broken_seq, Some(1));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_deleted_record_fails_verification() {
        // The other half of tamper evidence, and the one a plain log file
        // cannot give at all: removing a line leaves no trace in a stream
        // and breaks the sequence in a chain.
        let path = temp_path("deleted");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x33);
        {
            let chain = open_chain(&path, &seed);
            for index in 0..3 {
                chain.append(&denial(&format!("kept-{index}")));
            }
        }

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let lines: Vec<&str> = content.lines().collect();
        let without_middle = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, without_middle).expect("chain is writable");

        let result = verify_security_audit_chain(&path, None).expect("file is readable");
        assert!(!result.ok, "a removed record must not verify");
        assert_eq!(
            result.broken_seq,
            Some(2),
            "the gap is reported at the sequence number that survived it"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_chain_signed_by_another_key_is_rejected() {
        // What stops somebody who can write the file from simply rewriting
        // it: they can produce a consistent chain, but not one that
        // verifies against the published key.
        let path = temp_path("forged");
        let _ = std::fs::remove_file(&path);
        let forger = seed(0x44);
        {
            let chain = open_chain(&path, &forger);
            chain.append(&denial("rewritten"));
        }

        // Internally consistent, so the unsigned walk is happy.
        let unsigned = verify_security_audit_chain(&path, None).expect("file is readable");
        assert!(unsigned.ok, "the forged chain is self-consistent");

        // The real key says otherwise.
        let real = verifying_key_from_seed_hex(&seed(0x45)).expect("seed derives a public key");
        let signed = verify_security_audit_chain(&path, Some(&real)).expect("file is readable");
        assert!(!signed.ok, "a chain signed by another key must be rejected");
        assert_eq!(signed.broken_seq, Some(0));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_chained_record_is_the_record_the_tracing_target_ships() {
        // The one property that makes a single field list worth having:
        // the SIEM's copy of an event and the chain's copy are the same
        // bytes, so neither can be used to impeach the other.
        let path = temp_path("byte-identical");
        let _ = std::fs::remove_file(&path);
        let entry = denial("verbatim");
        let emitted = serde_json::to_string(&entry).expect("entry serializes");
        {
            let chain = open_chain(&path, &seed(0x55));
            chain.append(&entry);
        }

        let line = std::fs::read_to_string(&path).expect("chain is readable");
        // Substring, not a parse-and-re-serialize. Round-tripping through
        // `serde_json::Value` sorts the keys, because its map is a BTreeMap
        // unless `preserve_order` is on, so that comparison would fail on
        // field order even when the bytes on disk are identical, and pass on
        // a chain that had genuinely rewritten them. Asserting the emitted
        // record appears verbatim in the line is the property itself.
        assert!(
            line.contains(&emitted),
            "the chained payload is the emitted record, unchanged\n  emitted: {emitted}\n  line:    {line}"
        );
        let written: serde_json::Value =
            serde_json::from_str(line.trim()).expect("the entry is one JSON line");
        assert!(
            written.get("signature").is_some(),
            "and it is signed: {written}"
        );
        assert!(
            !line.contains("sk-"),
            "no credential material reaches the file: {line}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_torn_final_line_keeps_the_chain_closed() {
        // Boot must refuse rather than chain onto a head that was never
        // fully written. Inherited from the ledger; asserted here because
        // it is the behavior an operator meets, and because this crate
        // turns it into a failed boot rather than a degraded meter.
        let path = temp_path("torn");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x66);
        {
            let chain = open_chain(&path, &seed);
            chain.append(&denial("whole"));
            chain.append(&denial("cut-in-half"));
        }
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let last = lines.pop().unwrap_or_default();
        lines.push(last[..last.len() / 2].to_string());
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        let error = SecurityAuditChain::open(&path, &seed, "audit-kid")
            .expect_err("a torn tail must keep the chain closed");
        assert!(
            error.to_string().contains("audit.path"),
            "the error names the key that configured the file: {error}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unparseable_seed_is_refused_rather_than_signed_around() {
        let path = temp_path("bad-seed");
        let _ = std::fs::remove_file(&path);
        let error = SecurityAuditChain::open(&path, "not-hex", "audit-kid")
            .expect_err("a seed that is not 32 bytes of hex cannot sign anything");
        assert!(
            error.to_string().contains("audit.path"),
            "the error names the key that configured the file: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_installed_chain_receives_what_emit_records() {
        // End to end through the public emitter, which is the path a
        // denial actually takes. The chain is process-global and
        // first-write-wins, so this test tolerates entries other tests in
        // the same process contributed and asserts on its own marker.
        let path = temp_path("installed");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x77);
        let chain = open_chain(&path, &seed);
        assert_eq!(chain.key_id(), "audit-kid");
        if install_security_audit_chain(chain).is_err() {
            // Another test in this process claimed the slot first. The
            // append path is covered by the tests above; there is nothing
            // left for this one to prove.
            let _ = std::fs::remove_file(&path);
            return;
        }

        SecurityAuditEntry::policy_violation(
            "waf",
            "installed-chain-marker",
            403,
            Some("api.example.com".to_string()),
            None,
            Some("req-installed".to_string()),
            Some("GET".to_string()),
        )
        .emit();

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("installed-chain-marker"),
            "emit() reached the chain: {content}"
        );

        // Deliberately no verification assertion here. The chain is
        // installed for the rest of the process, so any other test that
        // emits a security audit event appends to this same file, and a
        // read that catches a line mid-write would fail a verify for a
        // reason that has nothing to do with the code under test. The
        // verification properties are asserted above, against chains
        // nothing else can reach.
    }
}
