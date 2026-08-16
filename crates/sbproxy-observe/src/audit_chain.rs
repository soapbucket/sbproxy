// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Tamper-evident audit trails (WOR-2318, WOR-2470).
//!
//! The `security_audit` and `config_audit` tracing targets have always
//! been streams. Whoever can write a log file can rewrite it, delete a
//! line out of the middle, and leave nothing behind that says so, which
//! makes each one a record of what the proxy said rather than a record of
//! what happened. This module gives those two channels a durable form
//! where the difference is detectable.
//!
//! # There is one chain in this workspace and these are not new ones
//!
//! Every byte of the hashing, signing, replay, and verification here comes
//! from [`sbproxy_meter::ledger`], unmodified. That module was already
//! generic over its payload, and `sbproxy-ai` already binds it to a second
//! payload of its own, so binding it to two more is the whole
//! implementation: [`SecurityAuditEntry`] and [`ConfigAuditEntry`]
//! implement [`LedgerPayload`] and everything else follows.
//!
//! # Two channels, two files, one shape
//!
//! One private generic, `AuditChain<P>`, carries the whole of that shape,
//! and [`SecurityAuditChain`] and [`ConfigAuditChain`] are the two
//! bindings of it. They are separate files rather than one, because a
//! chain is a chain of exactly one payload type: verification
//! re-serializes each record to re-derive its digest, so two payload types
//! in one file would break the walk at the first record of the wrong kind.
//! Separate files also mean an operator can hand an auditor the config
//! trail without handing over every denial the proxy ever issued.
//!
//! Each is opt-in on its own key. `audit.path` turns on the security
//! chain, `audit.config_path` turns on the config chain, and a deployment
//! that sets neither pays a relaxed load per event and nothing else.
//! `key_audit` is still deliberately not chainable: see [`crate::audit`]
//! for why its before/after diff has to be proven secret-free first.
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
//! [`LedgerPayload::meter_observed`] returns `false` for both payloads here
//! for that reason, and audit-append latency lands instead on the
//! histogram each audit channel already has,
//! `sbproxy_audit_emit_duration_seconds{channel="security"}` and
//! `{channel="config"}`.
//!
//! Nor does it inherit the meter's `degraded` failure default. That
//! default is justified in the metering runtime by "billing is not a
//! security boundary", and the argument does not carry across: an operator
//! who set `audit.sink: chain` asked for a trail, so a chain that will not
//! open fails the boot rather than serving traffic whose security events
//! go unrecorded. See [`SecurityAuditChain::open`].
//!
//! An append that fails once the process is up cannot fail the boot, so it
//! is reported instead of swallowed: both append functions return whether
//! the entry reached the file, and the emitter folds a `false` into the
//! `outcome` label of its own histogram. That is the difference between a
//! chain that is on and a chain that is working, and only the second one
//! is worth anything to an investigator.
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
//! Exactly the fields [`SecurityAuditEntry`] and [`ConfigAuditEntry`]
//! already ship to their tracing targets, byte for byte, and nothing added
//! here. Both types are documented as secret-free and the durability makes
//! the promise load bearing rather than merely tidy: a credential written
//! into a hash chain cannot be quietly removed later, because quiet
//! removal is the thing the chain exists to prevent.
//!
//! On the config channel what gets chained is the change, never the
//! document: a [`ConfigAuditEntry`] carries which origins moved, which
//! revision it moved between, and who asked for it, and not one config
//! value. The values are where the credentials live, which is why
//! chaining the record of a reload is safe and chaining what it loaded
//! would not be.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use sbproxy_meter::ledger::{LedgerPayload, UsageLedger};

pub use ed25519_dalek::VerifyingKey;
pub use sbproxy_meter::ledger::{verifying_key_from_seed_hex, LedgerVerifyResult};

use crate::audit::{ConfigAuditEntry, SecurityAuditEntry};

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

/// A config audit entry is chained one-for-one with the change it records,
/// for the same reason a denial is.
///
/// `dedup_key` is `None` again, and the argument is if anything stronger
/// here: two reloads that move the same origin set the same way are two
/// reloads, and the pair an investigator most wants to see side by side is
/// the change and the change that put it back. A ledger that collapsed
/// them would answer "did anything happen twice" with "no" precisely when
/// the answer matters.
///
/// `meter_observed` is `false`: see the module docs.
impl LedgerPayload for ConfigAuditEntry {
    fn dedup_key(&self) -> Option<&str> {
        None
    }

    fn meter_observed() -> bool {
        false
    }
}

/// Which audited channel a chain is the durable half of.
///
/// Carried as a field rather than a type parameter because every one of
/// its answers is a string an operator reads: the tracing target the
/// degraded lines land on, the config key that named the file, and the
/// word the messages use. A chain of one payload type on the security
/// channel and a chain of the same type on the config channel would be a
/// bug, and this makes it one value to get wrong rather than four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditChannel {
    /// `security_audit`: denials, framing violations, auth failures.
    Security,
    /// `config_audit`: reloads, mesh broadcasts, API origin updates.
    Config,
}

impl AuditChannel {
    /// The tracing target this channel's records and degraded lines share.
    const fn target(self) -> &'static str {
        match self {
            Self::Security => "security_audit",
            Self::Config => "config_audit",
        }
    }

    /// The word the log lines use: "the *security* audit chain".
    const fn label(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Config => "config",
        }
    }

    /// The config key that named the file, so a failure to open it points
    /// at the line an operator has to edit.
    const fn config_key(self) -> &'static str {
        match self {
            Self::Security => "audit.path",
            Self::Config => "audit.config_path",
        }
    }

    /// The wrapper type name, for `Debug`.
    const fn type_name(self) -> &'static str {
        match self {
            Self::Security => "SecurityAuditChain",
            Self::Config => "ConfigAuditChain",
        }
    }
}

/// A hash-chained, signed audit trail: one file, one payload type, one
/// channel.
///
/// Private, and reached only through [`SecurityAuditChain`] and
/// [`ConfigAuditChain`]. The wrappers exist so the two chains cannot be
/// mixed up by a caller holding the wrong one, and so each keeps the
/// concrete `open` signature boot already calls.
struct AuditChain<P> {
    /// The chain itself. Owns the file handle, the sequence counter, and
    /// the signing key.
    ledger: UsageLedger<P>,
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
    /// Which channel this chain records, fixed at construction.
    channel: AuditChannel,
}

impl<P> std::fmt::Debug for AuditChain<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand written, not derived. `ledger` holds a signing key, and
        // while `UsageLedger` redacts its own `Debug`, a derive here would
        // be one added field away from printing whatever that field holds.
        formatter
            .debug_struct(self.channel.type_name())
            .field("path", &self.path)
            .field("kid", &self.key_id)
            .field("channel", &self.channel.target())
            .field("degraded", &self.degraded.load(Ordering::Relaxed))
            .finish()
    }
}

impl<P: LedgerPayload> AuditChain<P> {
    /// Open (or create) the chain at `path`, signing every entry with the
    /// 32-byte Ed25519 seed `seed_hex` under the key id `key_id`.
    ///
    /// Fails, rather than degrading, on every problem it can hit: a parent
    /// directory that cannot be created, a seed that is not 32 bytes of
    /// hex, a file that cannot be appended to, or an existing file whose
    /// last line is torn. Every message is prefixed with the config key
    /// that named the file, because the reader is an operator looking for
    /// the line to edit rather than a caller looking for a variant to
    /// match on. Why it fails rather than degrades is on the two public
    /// `open` methods that call this.
    fn open(
        path: &Path,
        seed_hex: &str,
        key_id: &str,
        channel: AuditChannel,
    ) -> anyhow::Result<Self> {
        let key = channel.config_key();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    anyhow::anyhow!(
                        "{key} {}: cannot create the directory {}: {error}",
                        path.display(),
                        parent.display()
                    )
                })?;
            }
        }
        let ledger = UsageLedger::<P>::open(path, Some(seed_hex))
            .map_err(|error| anyhow::anyhow!("{key} {}: {error}", path.display()))?;
        Ok(Self {
            ledger,
            path: path.to_path_buf(),
            key_id: key_id.to_string(),
            degraded: AtomicBool::new(false),
            channel,
        })
    }

    /// The `kid` this chain signs under, so boot can say which key an
    /// auditor will need without going near the seed.
    fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Append one entry, absorbing any failure, and report whether it
    /// reached the file.
    ///
    /// Never returns an `Err` and never panics, because this runs from
    /// `emit`, which runs on the request path from inside policy denials
    /// and auth failures. A caller there has nothing useful to do with an
    /// error: the request is already being refused, and failing it a
    /// second way would turn a full disk into an outage. The `bool` is not
    /// an error channel either; it is one fact the emitter folds into the
    /// `outcome` label of its own histogram, so "the chain is configured"
    /// and "the chain is taking writes" stop being the same statement.
    ///
    /// A failure is loud once and then quiet. The first one, and the first
    /// one after any recovery, is logged at `error` on this channel's own
    /// tracing target, which is the pipe an operator is already watching
    /// for these events and therefore the right place to learn that the
    /// pipe has a hole in it. Repeats are suppressed so an attack against
    /// a proxy with a full disk does not also produce one log line per
    /// refused request.
    fn append(&self, entry: &P) -> bool {
        match self.ledger.append_checked(entry) {
            Ok(_) => {
                if self.degraded.swap(false, Ordering::Relaxed) {
                    self.log_recovered();
                }
                true
            }
            Err(error) => {
                if !self.degraded.swap(true, Ordering::Relaxed) {
                    self.log_failed(&error);
                }
                false
            }
        }
    }

    /// Say once that the chain is taking appends again.
    ///
    /// The match on `channel` is not ceremony. `tracing` bakes `target:`
    /// into a `static` callsite, so it has to be a literal at the macro
    /// site and cannot be read out of a field; one arm per channel is the
    /// whole price of that. The message is built above the match so the
    /// arms cannot drift apart.
    fn log_recovered(&self) {
        let message = format!(
            "{} audit chain is writable again; entries recorded while it was not are absent \
             from the chain and cannot be backfilled",
            self.channel.label()
        );
        match self.channel {
            AuditChannel::Security => tracing::info!(
                target: "security_audit",
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
            AuditChannel::Config => tracing::info!(
                target: "config_audit",
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
        }
    }

    /// Say once that appends are being dropped. See `log_recovered` above
    /// for why the target is matched rather than read from the field.
    fn log_failed(&self, error: &anyhow::Error) {
        let message = format!(
            "{label} audit chain append failed; {label} events are still being logged but are \
             no longer entering the tamper-evident trail",
            label = self.channel.label()
        );
        match self.channel {
            AuditChannel::Security => tracing::error!(
                target: "security_audit",
                %error,
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
            AuditChannel::Config => tracing::error!(
                target: "config_audit",
                %error,
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
        }
    }
}

/// The hash-chained, signed security audit trail for this process.
///
/// One file, one payload type, opened once at boot and held for the life
/// of the process. A reload does not reopen it: the chain is append-only
/// and reopening under a new configuration mid-life would either continue
/// a file the new configuration does not name or start a second one that
/// looks like a gap.
pub struct SecurityAuditChain(AuditChain<SecurityAuditEntry>);

impl std::fmt::Debug for SecurityAuditChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl SecurityAuditChain {
    /// Open (or create) the security chain at `path`, signing every entry
    /// with the 32-byte Ed25519 seed `seed_hex` under the key id `key_id`.
    ///
    /// Fails, rather than degrading, on every problem it can hit: a parent
    /// directory that cannot be created, a seed that is not 32 bytes of
    /// hex, a file that cannot be appended to, or an existing file whose
    /// last line is torn. The caller is boot, so the failure is a proxy
    /// that does not start, and the error names `audit.path`.
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
        AuditChain::open(path, seed_hex, key_id, AuditChannel::Security).map(Self)
    }

    /// The `kid` this chain signs under, so boot can say which key an
    /// auditor will need without going near the seed.
    pub fn key_id(&self) -> &str {
        self.0.key_id()
    }

    /// Append one denial, reporting whether it reached the file.
    fn append(&self, entry: &SecurityAuditEntry) -> bool {
        self.0.append(entry)
    }
}

/// The hash-chained, signed config-change audit trail for this process.
///
/// The same shape as [`SecurityAuditChain`] and deliberately a second
/// file: the two payload types verify separately, and a config trail is
/// the artifact a change-management auditor asks for on its own.
pub struct ConfigAuditChain(AuditChain<ConfigAuditEntry>);

impl std::fmt::Debug for ConfigAuditChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl ConfigAuditChain {
    /// Open (or create) the config chain at `path`, signing every entry
    /// with the 32-byte Ed25519 seed `seed_hex` under the key id `key_id`.
    ///
    /// Same failure posture as [`SecurityAuditChain::open`], for the same
    /// reason and with the same consequence at boot, and normally the same
    /// signing identity: one proxy, one key, two files. The error names
    /// `audit.config_path`, which is the key that turned this chain on.
    pub fn open(path: &Path, seed_hex: &str, key_id: &str) -> anyhow::Result<Self> {
        AuditChain::open(path, seed_hex, key_id, AuditChannel::Config).map(Self)
    }

    /// The `kid` this chain signs under, so boot can say which key an
    /// auditor will need without going near the seed.
    pub fn key_id(&self) -> &str {
        self.0.key_id()
    }

    /// Append one config change, reporting whether it reached the file.
    fn append(&self, entry: &ConfigAuditEntry) -> bool {
        self.0.append(entry)
    }
}

/// The process-wide security chain, or nothing when `audit.sink` does not
/// ask for one.
///
/// A `OnceLock` rather than a swappable handle for the same reason the
/// session-ledger sink is one: the chain is append-only and set once at
/// boot, and a reload that replaced it would leave two files each of which
/// looks complete and neither of which is.
static CHAIN: OnceLock<SecurityAuditChain> = OnceLock::new();

/// The process-wide config chain, or nothing when `audit.config_path` is
/// absent. Its own slot, on the same terms as `CHAIN` above.
static CONFIG_CHAIN: OnceLock<ConfigAuditChain> = OnceLock::new();

/// Register the process-wide security audit chain. Returns `Err` if one
/// was already registered. Call once at startup.
pub fn install_security_audit_chain(chain: SecurityAuditChain) -> Result<(), &'static str> {
    CHAIN
        .set(chain)
        .map_err(|_| "security audit chain already registered")
}

/// Register the process-wide config audit chain. Returns `Err` if one was
/// already registered. Call once at startup.
pub fn install_config_audit_chain(chain: ConfigAuditChain) -> Result<(), &'static str> {
    CONFIG_CHAIN
        .set(chain)
        .map_err(|_| "config audit chain already registered")
}

/// Append one entry to the security chain, if one is installed, and report
/// whether the entry is now on a file.
///
/// Called from [`SecurityAuditEntry::emit`]. With no chain configured this
/// is one relaxed load and a return, which is what keeps the default
/// deployment paying nothing for a feature it did not turn on.
///
/// No chain installed is `true`, and that is a claim rather than a
/// shortcut: the caller folds `false` into an `outcome` label that means
/// "this event did not reach the durable trail it was promised", and a
/// deployment that never asked for a durable trail made no such promise.
/// Reporting a failure there would put every default deployment
/// permanently in a failure state and make the label useless on the ones
/// that did ask.
pub(crate) fn append_security_audit(entry: &SecurityAuditEntry) -> bool {
    match CHAIN.get() {
        Some(chain) => chain.append(entry),
        None => true,
    }
}

/// Append one entry to the config chain, if one is installed, and report
/// whether the entry is now on a file. Same absent-is-not-a-failure rule
/// as [`append_security_audit`].
pub(crate) fn append_config_audit(entry: &ConfigAuditEntry) -> bool {
    match CONFIG_CHAIN.get() {
        Some(chain) => chain.append(entry),
        None => true,
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

/// Re-derive a config audit chain from genesis and report the first broken
/// link. The same walk as [`verify_security_audit_chain`], over the other
/// payload type.
///
/// A chain file has to be verified as the type that wrote it. Pointing
/// this at the security chain reports a break at the first record, not a
/// clean walk: a denial has no `source` or `origins_*`, so it does not
/// decode as a config record at all and the walk stops with `unparseable
/// entry`. That is the honest answer, and it is the reason the two
/// channels get two files rather than one.
pub fn verify_config_audit_chain(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<ConfigAuditEntry>(path, verifying_key)
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

    /// The same, for the other channel.
    fn open_config_chain(path: &Path, seed_hex: &str) -> ConfigAuditChain {
        ConfigAuditChain::open(path, seed_hex, "audit-kid").expect("chain opens")
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

    /// A config change with every optional field populated, so the tamper
    /// tests below are editing a record of the shape a real reload writes
    /// rather than a minimal one.
    fn config_change(source: &str) -> ConfigAuditEntry {
        ConfigAuditEntry::new(
            source,
            vec!["added.example".to_string()],
            vec!["removed.example".to_string()],
            vec!["modified.example".to_string()],
        )
        .with_tenant_id("acme")
        .with_actor("ops@example.com")
        .with_revisions(Some("rev-1"), Some("rev-2"))
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

    #[test]
    fn a_mutated_config_record_fails_verification_at_the_record_that_moved() {
        // The security tamper proof, run again over the other payload.
        // The machinery is shared, so this is the test that says the
        // config channel is genuinely bound to it rather than merely
        // compiling against it.
        let path = temp_path("config-mutated");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0x88);
        {
            let chain = open_config_chain(&path, &seed);
            assert!(chain.append(&config_change("first")), "the append lands");
            assert!(chain.append(&config_change("second")), "the append lands");
            assert!(chain.append(&config_change("third")), "the append lands");
        }

        // The edit a change-management auditor exists to catch: relabel
        // who asked for a reload, so a change nobody approved reads as a
        // change the API made, and leave the rest of the file alone.
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 3, "three entries were written");
        lines[1] = lines[1].replace("\"source\":\"second\"", "\"source\":\"api\"");
        assert!(lines[1].contains("\"source\":\"api\""), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        let unsigned = verify_config_audit_chain(&path, None).expect("file is readable");
        assert!(!unsigned.ok, "a mutated record must not verify");
        assert_eq!(unsigned.broken_seq, Some(1));
        let reason = unsigned.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("tampered"),
            "the verdict says what happened: {reason}"
        );

        let key = verifying_key_from_seed_hex(&seed).expect("seed derives a public key");
        let signed = verify_config_audit_chain(&path, Some(&key)).expect("file is readable");
        assert!(!signed.ok, "a mutated record must not verify under the key");
        assert_eq!(signed.broken_seq, Some(1));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_security_chain_does_not_verify_as_a_config_chain() {
        // Why the two channels get two files. A verifier pointed at the
        // wrong one says so at the first record instead of walking it
        // clean, which is what makes "verified" mean anything.
        let path = temp_path("wrong-payload");
        let _ = std::fs::remove_file(&path);
        {
            let chain = open_chain(&path, &seed(0x99));
            assert!(chain.append(&denial("mislabeled")), "the append lands");
        }

        let result = verify_config_audit_chain(&path, None).expect("file is readable");
        assert!(!result.ok, "a denial is not a config record: {result:?}");
        assert_eq!(result.broken_seq, Some(0), "it stops at the first record");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_security_audit_reports_whether_the_entry_reached_the_chain() {
        let path = temp_path("append-reports");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0xbb));

        // Absence of a chain is not a write failure. The caller folds a
        // `false` into an outcome label meaning "this event missed the
        // durable trail it was promised", and a deployment that never
        // asked for one was promised nothing. Asserted before the install
        // below, and only while this process still has no chain: the slot
        // is process-wide and another test may already hold it.
        if CHAIN.get().is_none() {
            assert!(
                append_security_audit(&denial("no-chain-installed")),
                "with no chain configured there is nothing that could have failed"
            );
        }

        if install_security_audit_chain(chain).is_err() {
            // Another test in this process claimed the slot first. Every
            // test here runs in its own process under nextest, so this is
            // the `cargo test --lib` path; the reporting is asserted
            // against chain handles directly above and below.
            let _ = std::fs::remove_file(&path);
            return;
        }

        assert!(
            append_security_audit(&denial("reached-the-file")),
            "an installed, writable chain takes the entry"
        );
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("reached-the-file"),
            "the entry is on the file: {content}"
        );
    }

    #[test]
    fn an_installed_config_chain_takes_what_append_config_audit_is_given() {
        let path = temp_path("config-installed");
        let _ = std::fs::remove_file(&path);
        let chain = open_config_chain(&path, &seed(0xaa));
        assert_eq!(chain.key_id(), "audit-kid");

        if CONFIG_CHAIN.get().is_none() {
            assert!(
                append_config_audit(&config_change("no-chain-installed")),
                "with no config chain configured there is nothing that could have failed"
            );
        }

        if install_config_audit_chain(chain).is_err() {
            // See the security twin above: the slot is process-wide.
            let _ = std::fs::remove_file(&path);
            return;
        }

        assert!(
            append_config_audit(&config_change("installed-config-marker")),
            "an installed chain takes the entry"
        );
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("installed-config-marker"),
            "the entry reached the file: {content}"
        );
    }

    /// A payload that cannot be encoded, which is how the test below
    /// produces an append that fails.
    ///
    /// The obvious alternative does not work, and that is worth writing
    /// down so nobody spends an afternoon on it: making the chain file
    /// read-only with `std::fs::set_permissions` leaves the append
    /// succeeding. The ledger opens the file once and holds the
    /// descriptor for the life of the process, and POSIX checks
    /// permissions at `open(2)` rather than on every `write(2)`, so a
    /// later `chmod` never reaches the writer that is already there. The
    /// real failure is a full disk and there is no portable way to stage
    /// one; an unencodable payload fails `append_checked` at the same
    /// point, before any byte is written, on every platform.
    #[derive(Clone, serde::Deserialize)]
    struct RefusedPayload;

    impl serde::Serialize for RefusedPayload {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("this payload cannot be encoded"))
        }
    }

    impl LedgerPayload for RefusedPayload {
        fn dedup_key(&self) -> Option<&str> {
            None
        }

        fn meter_observed() -> bool {
            false
        }
    }

    fn open_refusing_chain(path: &Path, seed_hex: &str) -> AuditChain<RefusedPayload> {
        AuditChain::open(path, seed_hex, "audit-kid", AuditChannel::Security).expect("chain opens")
    }

    #[test]
    fn a_failed_append_reports_false_and_latches_the_degraded_flag() {
        let path = temp_path("degraded");
        let _ = std::fs::remove_file(&path);
        let chain = open_refusing_chain(&path, &seed(0xcc));

        assert!(
            !chain.append(&RefusedPayload),
            "an append that never reached the file reports false"
        );
        assert!(
            format!("{chain:?}").contains("degraded: true"),
            "and the chain itself says so: {chain:?}"
        );
        // The second failure is silent, because one log line per outage
        // beats one per refused request, and still false: the latch
        // suppresses the line and never the verdict.
        assert!(
            !chain.append(&RefusedPayload),
            "the second failure reports false too"
        );

        let _ = std::fs::remove_file(&path);
    }
}
