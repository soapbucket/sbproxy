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
//! chain, `audit.config_path` turns on the config chain, `audit.key_path`
//! turns on the key/credential-mutation chain, `audit.admin_path` turns on
//! the admin-action chain, and a deployment that sets none of them pays a
//! relaxed load per event and nothing else (WOR-2478).
//!
//! The key channel is the one exception to "every byte the tracing target
//! ships, chained verbatim": [`crate::audit::KeyAuditEntry`] carries a
//! before/after diff of a credential record, and that diff must never
//! reach a file designed to be impossible to quietly amend. What chains
//! instead is [`crate::audit::KeyAuditChainEntry`] - every metadata field
//! the tracing entry carries, plus a keyed-HMAC-SHA256 fingerprint of each
//! before/after field in place of its value. See that type's docs and
//! [`install_key_audit_fingerprint_key`] for the key the fingerprint is
//! computed under.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use sbproxy_meter::ledger::{LedgerPayload, UsageLedger};

pub use ed25519_dalek::VerifyingKey;
pub use sbproxy_meter::ledger::{verifying_key_from_seed_hex, LedgerVerifyResult};

use crate::audit::{
    AdminActionAuditEntry, ConfigAuditEntry, KeyAuditChainEntry, SecurityAuditEntry,
};

/// HMAC-SHA256, keyed by the derived key-audit fingerprint key.
type HmacSha256 = Hmac<Sha256>;

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

/// A key-audit chain entry is chained one-for-one with the mutation it
/// records, for the same reason a denial and a config change are: two
/// mutations of the same key in the same second are two events, not one
/// retried.
///
/// `meter_observed` is `false`: see the module docs.
impl LedgerPayload for KeyAuditChainEntry {
    fn dedup_key(&self) -> Option<&str> {
        None
    }

    fn meter_observed() -> bool {
        false
    }
}

/// An admin-action chain entry is chained one-for-one with the action it
/// records, on the same terms as the other three channels.
///
/// `meter_observed` is `false`: see the module docs.
impl LedgerPayload for AdminActionAuditEntry {
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
    /// `key_audit`: key/credential mutations, metadata and fingerprints
    /// only (WOR-2478).
    Key,
    /// `sbproxy::admin::audit`: authenticated admin-console actions
    /// (WOR-2478).
    Admin,
}

impl AuditChannel {
    /// The tracing target this channel's records and degraded lines share.
    const fn target(self) -> &'static str {
        match self {
            Self::Security => "security_audit",
            Self::Config => "config_audit",
            Self::Key => "key_audit",
            Self::Admin => "sbproxy::admin::audit",
        }
    }

    /// The word the log lines use: "the *security* audit chain".
    const fn label(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Config => "config",
            Self::Key => "key",
            Self::Admin => "admin",
        }
    }

    /// The config key that named the file, so a failure to open it points
    /// at the line an operator has to edit.
    const fn config_key(self) -> &'static str {
        match self {
            Self::Security => "audit.path",
            Self::Config => "audit.config_path",
            Self::Key => "audit.key_path",
            Self::Admin => "audit.admin_path",
        }
    }

    /// The wrapper type name, for `Debug`.
    const fn type_name(self) -> &'static str {
        match self {
            Self::Security => "SecurityAuditChain",
            Self::Config => "ConfigAuditChain",
            Self::Key => "KeyAuditChain",
            Self::Admin => "AdminActionAuditChain",
        }
    }
}

/// A hash-chained, signed audit trail: one file, one payload type, one
/// channel.
///
/// Private, and reached only through [`SecurityAuditChain`],
/// [`ConfigAuditChain`], [`KeyAuditChain`], and [`AdminActionAuditChain`].
/// The wrappers exist so the four chains cannot be mixed up by a caller
/// holding the wrong one, and so each keeps the concrete `open` signature
/// boot already calls.
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
                sbproxy_util::secure_fs::create_dir_all_owner_only(parent).map_err(|error| {
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
            AuditChannel::Key => tracing::info!(
                target: "key_audit",
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
            AuditChannel::Admin => tracing::info!(
                target: "sbproxy::admin::audit",
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
            AuditChannel::Key => tracing::error!(
                target: "key_audit",
                %error,
                path = %self.path.display(),
                kid = %self.key_id,
                "{message}"
            ),
            AuditChannel::Admin => tracing::error!(
                target: "sbproxy::admin::audit",
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

/// The hash-chained, signed key/credential-mutation audit trail for this
/// process (WOR-2478).
///
/// A third file, same shape as [`SecurityAuditChain`] and
/// [`ConfigAuditChain`]: its own payload type verifies on its own. What it
/// chains is [`KeyAuditChainEntry`], not [`crate::audit::KeyAuditEntry`]
/// itself - see that type's docs for why the diff never makes it here.
pub struct KeyAuditChain(AuditChain<KeyAuditChainEntry>);

impl std::fmt::Debug for KeyAuditChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl KeyAuditChain {
    /// Open (or create) the key chain at `path`, signing every entry with
    /// the 32-byte Ed25519 seed `seed_hex` under the key id `key_id`. Same
    /// failure posture as [`SecurityAuditChain::open`]: the error names
    /// `audit.key_path`.
    pub fn open(path: &Path, seed_hex: &str, key_id: &str) -> anyhow::Result<Self> {
        AuditChain::open(path, seed_hex, key_id, AuditChannel::Key).map(Self)
    }

    /// The `kid` this chain signs under.
    pub fn key_id(&self) -> &str {
        self.0.key_id()
    }

    /// Append one key/credential mutation record, reporting whether it
    /// reached the file.
    fn append(&self, entry: &KeyAuditChainEntry) -> bool {
        self.0.append(entry)
    }
}

/// The hash-chained, signed admin-action audit trail for this process
/// (WOR-2478).
///
/// The durable half of the admin ring's `admin` channel
/// ([`crate::audit_ring`]): the ring stays the fast, bounded read model
/// behind the admin console, and this is where the same records survive a
/// restart and resist a quiet edit.
pub struct AdminActionAuditChain(AuditChain<AdminActionAuditEntry>);

impl std::fmt::Debug for AdminActionAuditChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, formatter)
    }
}

impl AdminActionAuditChain {
    /// Open (or create) the admin chain at `path`, signing every entry
    /// with the 32-byte Ed25519 seed `seed_hex` under the key id `key_id`.
    /// Same failure posture as [`SecurityAuditChain::open`]: the error
    /// names `audit.admin_path`.
    pub fn open(path: &Path, seed_hex: &str, key_id: &str) -> anyhow::Result<Self> {
        AuditChain::open(path, seed_hex, key_id, AuditChannel::Admin).map(Self)
    }

    /// The `kid` this chain signs under.
    pub fn key_id(&self) -> &str {
        self.0.key_id()
    }

    /// Append one admin-action record, reporting whether it reached the
    /// file.
    fn append(&self, entry: &AdminActionAuditEntry) -> bool {
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

/// The process-wide key chain, or nothing when `audit.key_path` is absent.
/// Its own slot, on the same terms as `CHAIN` above (WOR-2478).
static KEY_CHAIN: OnceLock<KeyAuditChain> = OnceLock::new();

/// The process-wide admin chain, or nothing when `audit.admin_path` is
/// absent. Its own slot, on the same terms as `CHAIN` above (WOR-2478).
static ADMIN_CHAIN: OnceLock<AdminActionAuditChain> = OnceLock::new();

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

/// Register the process-wide key audit chain. Returns `Err` if one was
/// already registered. Call once at startup (WOR-2478).
pub fn install_key_audit_chain(chain: KeyAuditChain) -> Result<(), &'static str> {
    KEY_CHAIN
        .set(chain)
        .map_err(|_| "key audit chain already registered")
}

/// Register the process-wide admin audit chain. Returns `Err` if one was
/// already registered. Call once at startup (WOR-2478).
pub fn install_admin_audit_chain(chain: AdminActionAuditChain) -> Result<(), &'static str> {
    ADMIN_CHAIN
        .set(chain)
        .map_err(|_| "admin audit chain already registered")
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

/// Append one entry to the key chain, if one is installed, and report
/// whether the entry is now on a file. Same absent-is-not-a-failure rule
/// as [`append_security_audit`]. Called from
/// [`crate::audit::KeyAuditEntry::emit`] with the metadata-and-fingerprint
/// [`KeyAuditChainEntry`], never the entry that carries the raw diff.
pub(crate) fn append_key_audit(entry: &KeyAuditChainEntry) -> bool {
    match KEY_CHAIN.get() {
        Some(chain) => chain.append(entry),
        None => true,
    }
}

/// Append one entry to the admin chain, if one is installed, and report
/// whether the entry is now on a file. Same absent-is-not-a-failure rule
/// as [`append_security_audit`]. Called from
/// [`crate::audit::AdminActionAuditEntry::emit`].
pub(crate) fn append_admin_audit(entry: &AdminActionAuditEntry) -> bool {
    match ADMIN_CHAIN.get() {
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

/// Re-derive a key audit chain from genesis and report the first broken
/// link. The same walk as [`verify_security_audit_chain`], over
/// [`KeyAuditChainEntry`] (WOR-2478).
pub fn verify_key_audit_chain(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<KeyAuditChainEntry>(path, verifying_key)
}

/// Re-derive an admin audit chain from genesis and report the first broken
/// link. The same walk as [`verify_security_audit_chain`], over
/// [`AdminActionAuditEntry`] (WOR-2478).
pub fn verify_admin_audit_chain(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<AdminActionAuditEntry>(path, verifying_key)
}

// --- WOR-2579: reading the chains back ---
//
// `sbproxy audit verify` is the auditor's read: a separate process, a
// copy of the file, no proxy involved, and no bound on anything. What
// follows is the operator's read, served from the running proxy to the
// admin console, and it differs in exactly two ways. It keeps only a
// window of records rather than the file, and it caps how large a single
// record it will look at. Everything else is the same walk, through the
// same `sbproxy_meter::ledger` function, because a viewer that verified
// with one code path and displayed with another would eventually show a
// record no walk had checked.

/// The four chained channels, in the order the console lists them.
///
/// Public so the admin route validates `?channel=` against this list
/// rather than a second copy of the same four strings. Each entry is the
/// same word the chain labels itself with internally, which is also what a
/// record's `channel` field carries in the response.
pub const AUDIT_CHAIN_CHANNELS: [&str; 4] = ["security", "config", "key", "admin"];

/// Default page size for [`read_audit_chain`] when a caller asks for none.
pub const DEFAULT_AUDIT_CHAIN_LIMIT: usize = 100;

/// Largest page [`read_audit_chain`] will serve, whatever a caller asks
/// for. The page is the memory bound: the walk streams the file and holds
/// this many records at most, so the cap is what keeps a chain of any size
/// from being a way to make the proxy allocate.
pub const MAX_AUDIT_CHAIN_LIMIT: usize = 500;

/// Largest single chained record the viewer will read: 1 MiB.
///
/// No writer of ours produces one anywhere near this, so hitting it means
/// the file is not what we wrote. Stopping there and reporting it as a
/// verification failure is the honest answer for a bounded reader; the
/// unbounded authority for a file in that state is `sbproxy audit verify`,
/// which passes `None` for this bound and reads whatever is there.
const VIEWER_MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The acting identity a chained record names, for the viewer's `actor`
/// filter and column.
///
/// A trait with four hand-written impls rather than a lookup into the
/// serialized JSON, because the field differs per channel and the compiler
/// should be the thing that notices when one is renamed. A JSON probe for
/// `"actor"` would keep compiling and quietly start matching nothing,
/// which on a filter over an audit trail reads as "this operator did
/// nothing" rather than as a bug.
trait ChainViewerRow {
    /// Who acted, when the record names anybody.
    fn viewer_actor(&self) -> Option<&str>;
}

/// The security channel records refusals of requests, which have no
/// operator: the acting identity is the client the proxy refused.
impl ChainViewerRow for SecurityAuditEntry {
    fn viewer_actor(&self) -> Option<&str> {
        self.client_ip.as_deref()
    }
}

/// Absent on a file-watcher or mesh-broadcast reload, which no operator
/// asked for. That is a real answer rather than a gap: those rows show a
/// blank actor and an `actor=` filter does not match them.
impl ChainViewerRow for ConfigAuditEntry {
    fn viewer_actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }
}

/// The principal that mutated the key or credential.
impl ChainViewerRow for KeyAuditChainEntry {
    fn viewer_actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }
}

/// The console operator whose action this is.
impl ChainViewerRow for AdminActionAuditEntry {
    fn viewer_actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }
}

/// One chained record, verified, as the viewer serves it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditChainRecord {
    /// Which chain it came off: `security`, `config`, `key`, or `admin`.
    pub channel: &'static str,
    /// Its position in that chain. Only comparable within one channel.
    pub seq: u64,
    /// The chained RFC 3339 timestamp. Inside the hashed bytes, so it is
    /// as tamper-evident as the payload.
    pub recorded_at: String,
    /// Who acted, when the record names anybody: the operator on the
    /// config, key, and admin channels, and the client IP on the security
    /// channel, which has no operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The chained payload, verbatim. Not a projection of it: the record
    /// is already secret-free by construction on all four channels, and
    /// re-editing it here would mean an operator reading a record the
    /// chain cannot prove they were shown.
    pub event: serde_json::Value,
}

/// What a caller wants out of one chain.
///
/// Every field narrows; none widens. A default query is "the newest
/// [`DEFAULT_AUDIT_CHAIN_LIMIT`] records", and adding a filter can only
/// return fewer.
#[derive(Debug, Clone, Default)]
pub struct AuditChainQuery {
    /// Exact match on the record's acting identity, per channel. Exact
    /// rather than substring: an audit filter that matched `root` against
    /// `rootkit` would answer a question nobody asked.
    pub actor: Option<String>,
    /// Lower bound on `recorded_at`, unix milliseconds, inclusive.
    pub since_ms: Option<i64>,
    /// Upper bound on `recorded_at`, unix milliseconds, inclusive.
    pub until_ms: Option<i64>,
    /// Page cursor: only records below this sequence number.
    pub before_seq: Option<u64>,
    /// Page size, clamped into `1..=`[`MAX_AUDIT_CHAIN_LIMIT`].
    pub limit: usize,
}

/// One channel's answer: what the walk found, and what it proved.
///
/// The verification fields are not optional decoration on the records.
/// A caller that renders `records` without `ok` is showing a page it has
/// no basis for, which is the failure mode this whole surface exists to
/// avoid.
#[derive(Debug, Clone)]
pub struct AuditChainRead {
    /// The channel walked.
    pub channel: &'static str,
    /// The file it walked.
    pub path: String,
    /// The `kid` this chain signs under.
    pub key_id: String,
    /// Records committed to the chain when the read started.
    pub chain_entries: u64,
    /// Records the walk verified. Below `chain_entries` when the walk
    /// stopped early or when the file has lost records this process
    /// wrote, which is itself a failure; above it when an append landed
    /// while the walk was running, which is not.
    pub verified_entries: u64,
    /// Whether every link and every signature held.
    pub ok: bool,
    /// The first sequence that failed, when `ok` is false.
    pub broken_seq: Option<u64>,
    /// Why it failed, when `ok` is false.
    pub reason: Option<String>,
    /// Records matching the filters across the verified prefix.
    pub total_matched: u64,
    /// Cursor for the next older page, when one exists.
    pub next_before_seq: Option<u64>,
    /// The page, newest first.
    pub records: Vec<AuditChainRecord>,
    /// Set when the file could not be read at all, in which case nothing
    /// above it was verified and `ok` is false.
    pub error: Option<String>,
}

impl AuditChainRead {
    /// A channel whose file could not be opened. `ok` is false, because
    /// "we could not check" and "we checked and it was fine" are not the
    /// same answer and only one of them may render as a clean chain.
    fn unreadable(channel: &'static str, path: String, key_id: String, error: String) -> Self {
        Self {
            channel,
            path,
            key_id,
            chain_entries: 0,
            verified_entries: 0,
            ok: false,
            broken_seq: None,
            reason: None,
            total_matched: 0,
            next_before_seq: None,
            records: Vec::new(),
            error: Some(error),
        }
    }
}

/// Parse one RFC 3339 timestamp into unix milliseconds.
///
/// Public so the admin route can reject a malformed `since=` with a `400`
/// naming the parameter, using the same parser that will later compare it
/// against a record, rather than a second one that might disagree.
pub fn parse_chain_timestamp(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|at| at.timestamp_millis())
}

impl<P: LedgerPayload> AuditChain<P> {
    /// Walk this chain and return one page of it, verified.
    fn read_window(&self, query: &AuditChainQuery) -> AuditChainRead
    where
        P: ChainViewerRow,
    {
        let channel = self.channel.label();
        let path = self.path.display().to_string();
        let Some(verifying_key) = self.ledger.verifying_key() else {
            // Unreachable: `AuditChain::open` always passes a seed. Handled
            // rather than asserted because the alternative is a walk that
            // silently checks hash links only and still reports `ok: true`,
            // and a signature nobody checked must never render as verified.
            return AuditChainRead {
                ok: false,
                reason: Some(
                    "this chain has no verifying key, so no signature was checked".to_string(),
                ),
                ..AuditChainRead::unreadable(
                    channel,
                    path,
                    self.key_id.clone(),
                    "no verifying key".to_string(),
                )
            };
        };
        let (chain_entries, _head) = self.ledger.head();
        let limit = query.limit.clamp(1, MAX_AUDIT_CHAIN_LIMIT);

        // The window is the memory bound: at most `limit` records are held
        // however long the file is, because the oldest is dropped as soon
        // as a newer one arrives to replace it.
        let mut window: std::collections::VecDeque<AuditChainRecord> =
            std::collections::VecDeque::with_capacity(limit);
        let mut total_matched: u64 = 0;

        let verdict = sbproxy_meter::ledger::verify_ledger_visiting::<P>(
            &self.path,
            Some(&verifying_key),
            Some(VIEWER_MAX_RECORD_BYTES),
            &mut |entry| {
                if query.before_seq.is_some_and(|before| entry.seq >= before) {
                    return;
                }
                let actor = entry.event.viewer_actor();
                if query
                    .actor
                    .as_deref()
                    .is_some_and(|wanted| actor != Some(wanted))
                {
                    return;
                }
                if query.since_ms.is_some() || query.until_ms.is_some() {
                    // A record whose own timestamp will not parse cannot be
                    // placed inside or outside a range, so a time filter
                    // excludes it rather than guessing. It still counts
                    // toward the chain and still breaks verification if the
                    // bytes were touched; only this filter cannot speak to
                    // it.
                    let Some(at) = parse_chain_timestamp(&entry.recorded_at) else {
                        return;
                    };
                    if query.since_ms.is_some_and(|since| at < since) {
                        return;
                    }
                    if query.until_ms.is_some_and(|until| at > until) {
                        return;
                    }
                }
                total_matched += 1;
                if window.len() == limit {
                    window.pop_front();
                }
                window.push_back(AuditChainRecord {
                    channel,
                    seq: entry.seq,
                    recorded_at: entry.recorded_at.clone(),
                    actor: actor.map(str::to_string),
                    event: serde_json::to_value(&entry.event).unwrap_or_else(|error| {
                        serde_json::json!({
                            "error": format!("this record could not be rendered: {error}"),
                        })
                    }),
                });
            },
        );

        match verdict {
            Ok(result) => {
                // Newest first: the walk runs oldest to newest, and the
                // deque kept the tail of it.
                let records: Vec<AuditChainRecord> = window.into_iter().rev().collect();
                let next_before_seq = if total_matched > records.len() as u64 {
                    records.last().map(|record| record.seq)
                } else {
                    None
                };
                // A file somebody truncated reads as a short, clean
                // chain. Every link in what is left still holds, because
                // the walk has nothing to check the file against except
                // itself, so the most obvious tamper there is - delete
                // the tail, or the whole trail - is the one a link check
                // alone cannot see.
                //
                // `chain_entries` is the missing comparison. It counts
                // records this process wrote and flushed, so a walk that
                // finds fewer is reading a file that lost some of them.
                // Only ever short: an append landing between the head
                // read above and the end of the walk makes the walk's
                // count larger, which is the ordinary case on a live
                // chain and not a finding.
                let missing = chain_entries.saturating_sub(result.entries);
                let truncated = result.ok && missing > 0;
                AuditChainRead {
                    channel,
                    path,
                    key_id: self.key_id.clone(),
                    chain_entries,
                    verified_entries: result.entries,
                    ok: result.ok && !truncated,
                    broken_seq: result.broken_seq.or(truncated.then_some(result.entries)),
                    reason: result.reason.or_else(|| {
                        truncated.then(|| {
                            format!(
                                "this process wrote {chain_entries} records to this chain and \
                                 the file holds {}: {missing} are missing from it",
                                result.entries
                            )
                        })
                    }),
                    total_matched,
                    next_before_seq,
                    records,
                    error: None,
                }
            }
            // The file could not be read at all. Whatever the walk had
            // gathered before that is dropped along with the claim it was
            // gathered under: a half-read file has no verified prefix.
            Err(error) => {
                AuditChainRead::unreadable(channel, path, self.key_id.clone(), error.to_string())
            }
        }
    }
}

/// Whether `channel` has a chain installed on this process.
///
/// Separate from [`read_audit_chain`] because "is this channel on" is a
/// question the viewer answers for all four channels on every request,
/// including the three it was not asked to walk, and walking a file to
/// find out would make a filtered read cost the same as an unfiltered
/// one. An unknown channel name is `false`.
pub fn audit_chain_installed(channel: &str) -> bool {
    match channel {
        "security" => CHAIN.get().is_some(),
        "config" => CONFIG_CHAIN.get().is_some(),
        "key" => KEY_CHAIN.get().is_some(),
        "admin" => ADMIN_CHAIN.get().is_some(),
        _ => false,
    }
}

/// Read one page of an installed chain, verifying it on the way.
///
/// `None` means this deployment has no chain on that channel, which is the
/// default and is not an error: the caller renders it as "not configured".
/// `Some` always carries a verdict, including the verdict "this file could
/// not be read".
///
/// An unknown `channel` is also `None`. Callers that need to tell the two
/// apart validate against [`AUDIT_CHAIN_CHANNELS`] first.
pub fn read_audit_chain(channel: &str, query: &AuditChainQuery) -> Option<AuditChainRead> {
    match channel {
        "security" => CHAIN.get().map(|chain| chain.0.read_window(query)),
        "config" => CONFIG_CHAIN.get().map(|chain| chain.0.read_window(query)),
        "key" => KEY_CHAIN.get().map(|chain| chain.0.read_window(query)),
        "admin" => ADMIN_CHAIN.get().map(|chain| chain.0.read_window(query)),
        _ => None,
    }
}

// --- WOR-2478: the key-audit fingerprint key ---
//
// A key/credential mutation's before/after values must never reach the
// chain (see `KeyAuditChainEntry`'s docs), so the chain carries a
// keyed-HMAC-SHA256 fingerprint of each field instead. The key that HMAC
// runs under is derived once per process from the operator's
// `key_management.crypto.master_key`, under a dedicated
// [`sbproxy_security::HkdfPurpose::KeyAuditFingerprint`], the same shape
// `sbproxy-keystore::crypto::derive_wrap_key` uses for the envelope
// DEK-wrapping key: the master key as HKDF input keying material, an
// empty salt, purpose alone for domain separation. Neither the master key
// nor this derived key is ever serialized, logged, or written to the
// chain; the derived key exists only in process memory as the input to an
// HMAC computation.

/// The process-wide key-audit fingerprint key, or nothing before
/// [`install_key_audit_fingerprint_key`] has run.
static KEY_AUDIT_FINGERPRINT_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Derive and install the process-wide key-audit fingerprint key from the
/// operator's key-management master key (WOR-2478).
///
/// Takes the master key by reference and immediately consumes it into an
/// HKDF derivation; this function never retains, logs, or returns the
/// master key itself, and the derived key it stores is likewise never
/// exposed outside this module. Call from wherever the master key is
/// resolved (`sbproxy-core`'s key plane), not from boot's
/// `install_audit_chain`: the key-management master key and the
/// `proxy.web_bot_auth` signing identity resolve from different config
/// blocks at different points in startup, and this function's job is
/// independent of whether the key chain file itself is even open.
///
/// First-write-wins, on the same terms as the chain installers above: a
/// hot reload that resolves a different master key does not re-derive
/// this key, for the same reason a reload does not reopen a chain file
/// (see the module docs). A deployment that rotates
/// `key_management.crypto.master_key` needs a restart for the fingerprint
/// key to follow, exactly as it already needs one for previously sealed
/// credential envelopes to stay openable under the old key today. See
/// [`KeyAuditChainEntry::key_epoch`] for how a reader tells that a
/// rotation happened at all.
pub fn install_key_audit_fingerprint_key(master_key: &[u8]) {
    let derived = sbproxy_security::hkdf_derive_purpose(
        master_key,
        b"",
        sbproxy_security::HkdfPurpose::KeyAuditFingerprint,
        32,
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    let _ = KEY_AUDIT_FINGERPRINT_KEY.set(key);
}

/// Whether a key-audit chain file is installed for this process.
///
/// Exposed so [`crate::audit::KeyAuditEntry::emit`] can skip building a
/// [`KeyAuditChainEntry`] entirely on a deployment that never turned the
/// key chain on (WOR-2478 M8): [`append_key_audit`] already treats an
/// uninstalled chain as a no-op, but constructing the entry that would
/// have been thrown away is not free - every before/after field gets an
/// HMAC computed for it - so the check moves in front of that work
/// instead of after it.
pub(crate) fn key_audit_chain_installed() -> bool {
    KEY_CHAIN.get().is_some()
}

/// Key-audit diff field names the one production caller
/// (`sbproxy-core`'s `admin_keys::audit_mutation_scoped`) emits today.
/// Names on this list are copied into the chain verbatim - readable to
/// an auditor without needing the fingerprint key at all, the same trade
/// Vault's audit log makes for its own closed field-name vocabulary -
/// because they are a closed, reviewed set rather than a caller-supplied
/// string. A field name that is not on this list does not get to land in
/// a file designed to be impossible to quietly amend either: see
/// [`fingerprinted_field_name`] (WOR-2478 I3/M6). Grow this list in the
/// same commit that adds a new field to a `KeyAuditEntry::with_diff`
/// call site, not before.
const KNOWN_KEY_AUDIT_FIELD_NAMES: &[&str] = &["status"];

/// Prefix on a fingerprinted (non-allowlisted) field name in the chained
/// map, so a reader can tell the two shapes apart at a glance: `status`
/// reads as a name, `f:3f9c...` reads as a fingerprint.
const FIELD_NAME_FINGERPRINT_PREFIX: &str = "f:";

/// Hex characters kept from a field name/value fingerprint's full
/// HMAC-SHA256 digest: 32 hex characters, 16 bytes, 128 bits.
const FIELD_FINGERPRINT_HEX_LEN: usize = 32;

/// Hex characters kept from the key-epoch tag's full HMAC-SHA256 digest.
/// Deliberately much shorter than a field fingerprint: the epoch is not
/// trying to resist brute force (there is nothing to invert - it is not
/// a digest of any secret value, only of the fixed string `b"epoch"`
/// under the derived key), only to give two records a short, glanceable
/// "same key or not" tag. See [`KeyAuditChainEntry::key_epoch`].
const KEY_EPOCH_HEX_LEN: usize = 8;

/// HMAC-SHA256 `data` under `key`, hex encoded and truncated to the
/// first `hex_len` hex characters, the shared primitive under every
/// fingerprint and the epoch tag below. 128 bits (the field-fingerprint
/// length) is not brute-forceable back to the input by anyone without
/// the derived key, which is the property a field fingerprint needs;
/// none of these calls is a general-purpose hash.
///
/// `Option`-returning rather than infallible: `Hmac::new_from_slice`
/// only ever errs on a key length HMAC-SHA256 does not accept, which a
/// fixed 32-byte `key` never hits in practice, but that is a fact about
/// this call site rather than something the type system can promise, so
/// the caller decides what "no fingerprint" means (omit the field)
/// rather than this function taking down the process on an input it
/// cannot actually receive.
///
/// A free function, not a method, so it is testable without touching the
/// process-wide `KEY_AUDIT_FINGERPRINT_KEY` slot: determinism,
/// key-separation, and (for values) name-binding are properties of the
/// functions built on top of this one, not of any installed state.
fn hmac_hex(key: &[u8; 32], data: &[u8], hex_len: usize) -> Option<String> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let full = hex::encode(digest);
    Some(full[..hex_len.min(full.len())].to_string())
}

/// HMAC-SHA256 a field's name-bound value: `b"value\0" || name || 0x00 ||
/// canonical(value)`. Binding the name into the value's own MAC
/// (WOR-2478 I3/M6) means two mutations that set different fields to the
/// same value no longer fingerprint identically: `{"status":"blocked"}`
/// and some future `{"role":"blocked"}` disagree, where the bare value
/// digest alone would not have.
///
/// The leading `b"value\0"` domain-separates this input from
/// [`hmac_name`]'s (WOR-2478 review, M8): without it, a field literally
/// named `name` whose canonical value bytes equal some other field's raw
/// name would make `hmac_value(key, "name", that_value)` and
/// `hmac_name(key, that_other_field)` hash the identical byte string
/// (`hmac_name`'s `b"name\0" || name` looks exactly like `hmac_value`'s
/// old `name || 0x00 || canonical(value)` in that one case), so the two
/// keyspaces the doc comment on `hmac_name` claims are kept apart were
/// not, for that input. Prefixing both functions with their own literal
/// tag closes it: the two inputs now differ in their first six bytes no
/// matter what `name` or `value` a caller passes.
fn hmac_value(key: &[u8; 32], name: &str, value: &serde_json::Value) -> Option<String> {
    // `serde_json_canonicalizer` (RFC 8785 / JCS) rather than
    // `serde_json::to_vec`: the latter's object-key order only happens
    // to be insertion-order-independent while nothing in the
    // dependency graph enables serde_json's `preserve_order` feature,
    // and cedar-policy-core enables it workspace-wide (WOR-2585). A
    // fingerprint that quietly started depending on insertion order
    // would still verify against itself but would no longer match a
    // value rebuilt with different insertion order, which is exactly
    // the silent mismatch this function exists to prevent.
    let canonical = serde_json_canonicalizer::to_vec(value).ok()?;
    let mut data = Vec::with_capacity(6 + name.len() + 1 + canonical.len());
    data.extend_from_slice(b"value\0");
    data.extend_from_slice(name.as_bytes());
    data.push(0);
    data.extend_from_slice(&canonical);
    hmac_hex(key, &data, FIELD_FINGERPRINT_HEX_LEN)
}

/// HMAC-SHA256 a field NAME, domain-separated from [`hmac_value`] by the
/// `b"name\0"` prefix so the two keyspaces cannot be confused. Used only
/// for a name that fails [`is_known_key_audit_field_name`]; see
/// [`fingerprinted_field_name`].
fn hmac_name(key: &[u8; 32], name: &str) -> Option<String> {
    let mut data = Vec::with_capacity(5 + name.len());
    data.extend_from_slice(b"name\0");
    data.extend_from_slice(name.as_bytes());
    hmac_hex(key, &data, FIELD_FINGERPRINT_HEX_LEN)
}

/// Whether `name` is on the closed, reviewed key-audit diff field-name
/// vocabulary. See [`KNOWN_KEY_AUDIT_FIELD_NAMES`].
fn is_known_key_audit_field_name(name: &str) -> bool {
    KNOWN_KEY_AUDIT_FIELD_NAMES.contains(&name)
}

/// The map key one field lands under in the chained snapshot: `name`
/// verbatim when it is on the closed allowlist, or its own keyed,
/// domain-separated fingerprint (prefixed so it reads as one) when it is
/// not (WOR-2478 I3/M6). An arbitrary caller-supplied field name can
/// therefore never land verbatim in the chain file, only an allowlisted
/// one can. Returns `None` exactly when [`hmac_name`] does, for a name
/// that fails the allowlist (see that function's docs for when that is).
fn fingerprinted_field_name(key: &[u8; 32], name: &str) -> Option<String> {
    if is_known_key_audit_field_name(name) {
        Some(name.to_string())
    } else {
        hmac_name(key, name).map(|hash| format!("{FIELD_NAME_FINGERPRINT_PREFIX}{hash}"))
    }
}

/// Fingerprint one named field under the installed key-audit fingerprint
/// key: the map key ([`fingerprinted_field_name`]) paired with the
/// name-bound value fingerprint ([`hmac_value`]). `None` when no key has
/// been installed yet: a fingerprint computed under no key would not be
/// a fingerprint of anything, so the field is omitted rather than
/// derived under an all-zero placeholder.
fn fingerprint_named_field(name: &str, value: &serde_json::Value) -> Option<(String, String)> {
    let key = KEY_AUDIT_FINGERPRINT_KEY.get()?;
    let value_fingerprint = hmac_value(key, name, value)?;
    let map_key = fingerprinted_field_name(key, name)?;
    Some((map_key, value_fingerprint))
}

/// Fingerprint one non-secret-but-identifying value under the key-audit
/// fingerprint key (WOR-2570).
///
/// The read audit's selective-hash posture, borrowed from HashiCorp
/// Vault's audit devices: a sensitive string identifier is replaced by a
/// keyed HMAC, everything that is not an identifier (timestamps, outcomes,
/// tenant) passes through readable, and an investigator who suspects a
/// specific value confirms it by hashing that value the same way rather
/// than by reading it out of the trail.
///
/// The `hmac-sha256:` prefix is Vault's own spelling and is load bearing
/// here: it makes a hashed identifier impossible to mistake for a real
/// one, in a field whose other records carry real ones.
///
/// Returns `None` before a fingerprint key is installed, so a caller can
/// tell "not hashed because the key was missing" from "hashed to this",
/// and refuse to emit rather than emit the value in the clear.
pub fn fingerprint_key_audit_value(field: &str, value: &str) -> Option<String> {
    // Reuses `hmac_value`, the same construction the before/after
    // fingerprint maps run through, rather than opening a second one. A
    // second construction here would mean an investigator hashing an id
    // through this function and comparing it to a `before_fingerprint`
    // entry for the same field silently never matches.
    let key = KEY_AUDIT_FINGERPRINT_KEY.get()?;
    let digest = hmac_value(key, field, &serde_json::Value::String(value.to_string()))?;
    Some(format!("hmac-sha256:{digest}"))
}

/// The fingerprint epoch tag, for callers outside this module.
///
/// Two fingerprints are only comparable when they carry the same epoch;
/// see [`crate::audit::KeyAuditChainEntry::key_epoch`].
pub fn fingerprint_epoch() -> String {
    key_audit_fingerprint_epoch()
}

/// Fingerprint every top-level field of a key/credential before/after
/// snapshot (WOR-2478).
///
/// A JSON object fingerprints one entry per key. Anything else a caller
/// might pass as a snapshot (a scalar, an array, or simply absent)
/// fingerprints as a single field named `"value"`, so a diff shaped
/// either way still produces something. Called from
/// [`crate::audit::KeyAuditEntry::emit`]; never the raw name or value,
/// only their digests under a key only the operator's master secret can
/// derive, and only when a fingerprint key has actually been installed
/// (this omits the entry rather than fingerprinting with a placeholder).
pub(crate) fn fingerprint_key_audit_snapshot(
    value: Option<&serde_json::Value>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(value) = value else {
        return out;
    };
    match value.as_object() {
        Some(map) => {
            for (field, field_value) in map {
                if let Some((map_key, fingerprint)) = fingerprint_named_field(field, field_value) {
                    out.insert(map_key, fingerprint);
                }
            }
        }
        None => {
            if let Some((map_key, fingerprint)) = fingerprint_named_field("value", value) {
                out.insert(map_key, fingerprint);
            }
        }
    }
    out
}

/// The current key-audit fingerprint key's epoch tag, or an empty string
/// before a fingerprint key has been installed (WOR-2478 I4). See
/// [`KeyAuditChainEntry::key_epoch`] for what this is for; kept as a
/// standalone free function ([`epoch_tag`]) underneath so the property
/// "same key -> same tag, different key -> different tag" is testable
/// without touching the process-wide slot.
pub(crate) fn key_audit_fingerprint_epoch() -> String {
    KEY_AUDIT_FINGERPRINT_KEY
        .get()
        .and_then(epoch_tag)
        .unwrap_or_default()
}

/// `hex(HMAC(key, b"epoch"))[..8]`. See [`key_audit_fingerprint_epoch`].
fn epoch_tag(key: &[u8; 32]) -> Option<String> {
    hmac_hex(key, b"epoch", KEY_EPOCH_HEX_LEN)
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

    // --- WOR-2478: the key and admin channels ---

    /// The same, for the key channel.
    fn open_key_chain(path: &Path, seed_hex: &str) -> KeyAuditChain {
        KeyAuditChain::open(path, seed_hex, "audit-kid").expect("chain opens")
    }

    /// The same, for the admin channel.
    fn open_admin_chain(path: &Path, seed_hex: &str) -> AdminActionAuditChain {
        AdminActionAuditChain::open(path, seed_hex, "audit-kid").expect("chain opens")
    }

    /// A key-audit chain entry with every optional field populated, so the
    /// tamper test below is editing a record shaped like a real mutation
    /// rather than a minimal one.
    fn key_mutation(id: &str) -> KeyAuditChainEntry {
        let mut before_fingerprint = BTreeMap::new();
        before_fingerprint.insert(
            "status".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        let mut after_fingerprint = BTreeMap::new();
        after_fingerprint.insert(
            "status".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );
        KeyAuditChainEntry {
            timestamp: "2026-08-16T00:00:00Z".to_string(),
            op: "rotate".to_string(),
            resource: "key".to_string(),
            id: id.to_string(),
            actor: Some("operator-jo".to_string()),
            tenant_id: Some("acme".to_string()),
            key_epoch: "test-epoch".to_string(),
            before_fingerprint,
            after_fingerprint,
            outcome: Some("applied".to_string()),
            context: None,
        }
    }

    /// An admin-action chain entry with every optional field populated.
    fn admin_action(action: &str) -> AdminActionAuditEntry {
        AdminActionAuditEntry::new(
            action,
            Some("operator-jo".to_string()),
            Some("acme".to_string()),
            Some("sbp_admin_test_key".to_string()),
            Some("req-admin-test".to_string()),
            Some("PATCH /api/keys/abc".to_string()),
        )
    }

    #[test]
    fn a_mutated_key_record_fails_verification_at_the_record_that_moved() {
        // The security/config tamper proof, run again over the
        // metadata-and-fingerprint payload: proof the key channel is
        // genuinely bound to the shared chain machinery.
        let path = temp_path("key-mutated");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0xa1);
        {
            let chain = open_key_chain(&path, &seed);
            assert!(chain.append(&key_mutation("key-first")), "the append lands");
            assert!(
                chain.append(&key_mutation("key-second")),
                "the append lands"
            );
            assert!(chain.append(&key_mutation("key-third")), "the append lands");
        }

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 3, "three entries were written");
        lines[1] = lines[1].replace("\"id\":\"key-second\"", "\"id\":\"key-tampered\"");
        assert!(lines[1].contains("key-tampered"), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        let unsigned = verify_key_audit_chain(&path, None).expect("file is readable");
        assert!(!unsigned.ok, "a mutated record must not verify");
        assert_eq!(unsigned.broken_seq, Some(1));
        let reason = unsigned.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("tampered"),
            "the verdict says what happened: {reason}"
        );

        let key = verifying_key_from_seed_hex(&seed).expect("seed derives a public key");
        let signed = verify_key_audit_chain(&path, Some(&key)).expect("file is readable");
        assert!(!signed.ok, "a mutated record must not verify under the key");
        assert_eq!(signed.broken_seq, Some(1));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_mutated_admin_record_fails_verification_at_the_record_that_moved() {
        let path = temp_path("admin-mutated");
        let _ = std::fs::remove_file(&path);
        let seed = seed(0xa2);
        {
            let chain = open_admin_chain(&path, &seed);
            assert!(chain.append(&admin_action("first")), "the append lands");
            assert!(chain.append(&admin_action("second")), "the append lands");
            assert!(chain.append(&admin_action("third")), "the append lands");
        }

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 3, "three entries were written");
        lines[1] = lines[1].replace("\"action\":\"second\"", "\"action\":\"tampered\"");
        assert!(lines[1].contains("tampered"), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        let unsigned = verify_admin_audit_chain(&path, None).expect("file is readable");
        assert!(!unsigned.ok, "a mutated record must not verify");
        assert_eq!(unsigned.broken_seq, Some(1));
        let reason = unsigned.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("tampered"),
            "the verdict says what happened: {reason}"
        );

        let key = verifying_key_from_seed_hex(&seed).expect("seed derives a public key");
        let signed = verify_admin_audit_chain(&path, Some(&key)).expect("file is readable");
        assert!(!signed.ok, "a mutated record must not verify under the key");
        assert_eq!(signed.broken_seq, Some(1));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_key_chain_does_not_verify_as_a_config_chain() {
        // Why the key channel gets its own file, mirroring the
        // security/config pairing: a verifier pointed at the wrong file
        // stops at the first record instead of walking it clean.
        let path = temp_path("key-wrong-payload");
        let _ = std::fs::remove_file(&path);
        {
            let chain = open_key_chain(&path, &seed(0xa3));
            assert!(
                chain.append(&key_mutation("mislabeled")),
                "the append lands"
            );
        }

        let result = verify_config_audit_chain(&path, None).expect("file is readable");
        assert!(
            !result.ok,
            "a key mutation is not a config record: {result:?}"
        );
        assert_eq!(result.broken_seq, Some(0), "it stops at the first record");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_installed_key_chain_takes_what_append_key_audit_is_given() {
        let path = temp_path("key-installed");
        let _ = std::fs::remove_file(&path);
        let chain = open_key_chain(&path, &seed(0xa4));
        assert_eq!(chain.key_id(), "audit-kid");

        if KEY_CHAIN.get().is_none() {
            assert!(
                append_key_audit(&key_mutation("no-chain-installed")),
                "with no key chain configured there is nothing that could have failed"
            );
        }

        if install_key_audit_chain(chain).is_err() {
            // Another test in this process claimed the slot first (the
            // `cargo test` fallback path; nextest gives every test its own
            // process, which is what the gate actually runs).
            let _ = std::fs::remove_file(&path);
            return;
        }

        assert!(
            append_key_audit(&key_mutation("installed-key-marker")),
            "an installed chain takes the entry"
        );
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("installed-key-marker"),
            "the entry reached the file: {content}"
        );
    }

    #[test]
    fn an_installed_admin_chain_takes_what_append_admin_audit_is_given() {
        let path = temp_path("admin-installed");
        let _ = std::fs::remove_file(&path);
        let chain = open_admin_chain(&path, &seed(0xa5));
        assert_eq!(chain.key_id(), "audit-kid");

        if ADMIN_CHAIN.get().is_none() {
            assert!(
                append_admin_audit(&admin_action("no-chain-installed")),
                "with no admin chain configured there is nothing that could have failed"
            );
        }

        if install_admin_audit_chain(chain).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }

        assert!(
            append_admin_audit(&admin_action("installed-admin-marker")),
            "an installed chain takes the entry"
        );
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("installed-admin-marker"),
            "the entry reached the file: {content}"
        );
    }

    #[test]
    fn key_audit_value_fingerprint_is_deterministic_key_dependent_and_name_bound() {
        // A pure-function test, independent of the process-wide
        // fingerprint-key slot: same name + same value + same key must
        // always agree, and any one of the three changing must break
        // that agreement.
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let value = serde_json::json!({ "status": "active" });

        let fp1 = hmac_value(&key_a, "status", &value).expect("value fingerprints");
        let fp2 = hmac_value(&key_a, "status", &value).expect("value fingerprints");
        assert_eq!(fp1, fp2, "same name + value + key -> same fingerprint");
        assert_eq!(
            fp1.len(),
            FIELD_FINGERPRINT_HEX_LEN,
            "truncated to 32 hex chars for log ergonomics"
        );

        let fp3 = hmac_value(&key_b, "status", &value).expect("value fingerprints");
        assert_ne!(fp1, fp3, "a different derived key must not agree");

        let other_value = serde_json::json!({ "status": "blocked" });
        let fp4 = hmac_value(&key_a, "status", &other_value).expect("value fingerprints");
        assert_ne!(
            fp1, fp4,
            "a different value under the same name and key must not agree"
        );

        // WOR-2478 I3/M6(b): the value MAC binds the field name, so two
        // fields set to the identical value must not fingerprint
        // identically either.
        let fp5 = hmac_value(&key_a, "role", &value).expect("value fingerprints");
        assert_ne!(
            fp1, fp5,
            "the same value under a different field name must not agree"
        );
    }

    #[test]
    fn key_audit_value_fingerprint_is_stable_across_json_object_key_insertion_order() {
        // WOR-2478 M7: guards the assumption that `serde_json::Value`'s
        // map canonicalizes independent of insertion order (true today
        // because this workspace does not enable serde_json's
        // `preserve_order` feature; a BTreeMap-backed map always
        // serializes in sorted key order regardless of how it was
        // built). If that assumption ever breaks, this is the test that
        // catches it rather than a silent fingerprint mismatch in
        // production.
        let key = [0x33u8; 32];

        let mut forward = serde_json::Map::new();
        forward.insert("x".to_string(), serde_json::json!(1));
        forward.insert("y".to_string(), serde_json::json!(2));
        let value_forward = serde_json::Value::Object(forward);

        let mut reverse = serde_json::Map::new();
        reverse.insert("y".to_string(), serde_json::json!(2));
        reverse.insert("x".to_string(), serde_json::json!(1));
        let value_reverse = serde_json::Value::Object(reverse);

        let fp_forward = hmac_value(&key, "field", &value_forward).expect("value fingerprints");
        let fp_reverse = hmac_value(&key, "field", &value_reverse).expect("value fingerprints");
        assert_eq!(
            fp_forward, fp_reverse,
            "canonical serialization must not depend on object key insertion order"
        );
    }

    #[test]
    fn key_audit_epoch_is_stable_per_key_and_differs_across_keys() {
        // WOR-2478 I4: same key -> same epoch every time; different key
        // -> different epoch. Drives `epoch_tag` directly for the same
        // reason the value-fingerprint tests above drive `hmac_value`
        // directly: independent of the process-wide slot.
        let key_a = [0x44u8; 32];
        let key_b = [0x55u8; 32];

        let epoch_a1 = epoch_tag(&key_a).expect("epoch tags");
        let epoch_a2 = epoch_tag(&key_a).expect("epoch tags");
        assert_eq!(epoch_a1, epoch_a2, "the same key must yield a stable epoch");
        assert_eq!(
            epoch_a1.len(),
            KEY_EPOCH_HEX_LEN,
            "the epoch tag is 8 hex characters"
        );

        let epoch_b = epoch_tag(&key_b).expect("epoch tags");
        assert_ne!(
            epoch_a1, epoch_b,
            "a different key must yield a different epoch"
        );
    }

    #[test]
    fn fingerprint_key_audit_snapshot_keeps_allowlisted_names_verbatim_and_fingerprints_others() {
        // WOR-2478 I3/M6(a): `status` is the one field name the
        // production caller emits today, so it is on the closed
        // allowlist and lands in the chain readable. `note` is not, so
        // it must not land in the chain under its own name at all -
        // only under its own keyed, prefixed fingerprint.
        install_key_audit_fingerprint_key(b"test-master-for-snapshot-fields");
        let snapshot = fingerprint_key_audit_snapshot(Some(&serde_json::json!({
            "status": "active",
            "note": "rotated",
        })));
        assert_eq!(snapshot.len(), 2, "one entry per field: {snapshot:?}");
        assert!(
            snapshot.contains_key("status"),
            "an allowlisted name is copied verbatim: {snapshot:?}"
        );
        assert!(
            !snapshot.contains_key("note"),
            "a non-allowlisted name must never land verbatim: {snapshot:?}"
        );
        let fingerprinted_key = snapshot
            .keys()
            .find(|k| k.starts_with(FIELD_NAME_FINGERPRINT_PREFIX))
            .expect("the non-allowlisted field lands under its fingerprinted name");
        assert!(
            !fingerprinted_key.contains("note"),
            "the fingerprinted name must not embed the raw name either: {fingerprinted_key}"
        );

        let empty = fingerprint_key_audit_snapshot(None);
        assert!(empty.is_empty(), "no snapshot, no fingerprints");
    }

    // --- WOR-2579: the console viewer's bounded read ---

    /// A denial from a named client, so the viewer's actor filter has
    /// something to be exact about.
    fn denial_from(reason: &str, ip: &str) -> SecurityAuditEntry {
        SecurityAuditEntry::policy_violation(
            "waf",
            reason,
            403,
            Some("api.example.com".to_string()),
            Some(ip.parse().expect("a test IP parses")),
            Some(format!("req-{reason}")),
            Some("GET".to_string()),
        )
    }

    /// A page is the newest window, newest first, and the cursor walks
    /// strictly backwards through the rest without repeating a record or
    /// skipping one.
    #[test]
    fn the_viewer_pages_a_chain_backwards_without_gaps() {
        let path = temp_path("viewer-page");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x41));
        for index in 0..5 {
            chain.append(&denial_from(&format!("page-{index}"), "203.0.113.7"));
        }

        let first = chain.0.read_window(&AuditChainQuery {
            limit: 2,
            ..AuditChainQuery::default()
        });
        assert!(first.ok, "an untouched chain verifies: {first:?}");
        assert_eq!(first.channel, "security");
        assert_eq!(first.chain_entries, 5);
        assert_eq!(first.verified_entries, 5, "the walk reads the whole file");
        assert_eq!(first.total_matched, 5);
        let seqs: Vec<u64> = first.records.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![4, 3], "newest first: {seqs:?}");
        assert_eq!(first.next_before_seq, Some(3));

        let second = chain.0.read_window(&AuditChainQuery {
            limit: 2,
            before_seq: first.next_before_seq,
            ..AuditChainQuery::default()
        });
        let seqs: Vec<u64> = second.records.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![2, 1], "the cursor is exclusive: {seqs:?}");
        assert_eq!(
            second.total_matched, 3,
            "the cursor narrows the count too, or the last page never ends"
        );
        assert_eq!(second.next_before_seq, Some(1));

        let last = chain.0.read_window(&AuditChainQuery {
            limit: 2,
            before_seq: Some(1),
            ..AuditChainQuery::default()
        });
        let seqs: Vec<u64> = last.records.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![0], "{seqs:?}");
        assert_eq!(last.next_before_seq, None, "the walk back ends");

        let _ = std::fs::remove_file(&path);
    }

    /// The actor filter is an exact match. One that matched
    /// `203.0.113.7` against `203.0.113.70` would answer a question
    /// nobody asked, on a surface where the answer is evidence.
    #[test]
    fn the_viewer_actor_filter_is_exact_not_a_prefix() {
        let path = temp_path("viewer-actor");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x42));
        chain.append(&denial_from("short", "203.0.113.7"));
        chain.append(&denial_from("long", "203.0.113.70"));

        let read = chain.0.read_window(&AuditChainQuery {
            actor: Some("203.0.113.7".to_string()),
            limit: 10,
            ..AuditChainQuery::default()
        });

        assert!(read.ok, "{read:?}");
        assert_eq!(read.total_matched, 1, "only the exact actor: {read:?}");
        assert_eq!(read.records.len(), 1);
        assert_eq!(read.records[0].actor.as_deref(), Some("203.0.113.7"));
        assert_eq!(read.records[0].event["reason"], "short");
        assert_eq!(
            read.verified_entries, 2,
            "a filter narrows the page, never the walk: {read:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The acting identity is read per channel: the config chain names
    /// the operator who asked for the reload, and a reload nobody asked
    /// for names nobody rather than borrowing a field from elsewhere.
    #[test]
    fn the_viewer_reads_the_actor_per_channel() {
        let path = temp_path("viewer-config-actor");
        let _ = std::fs::remove_file(&path);
        let chain = open_config_chain(&path, &seed(0x43));
        chain.append(&config_change("api"));
        chain.append(&ConfigAuditEntry::new(
            "watcher",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));

        let read = chain.0.read_window(&AuditChainQuery {
            limit: 10,
            ..AuditChainQuery::default()
        });
        assert!(read.ok, "{read:?}");
        assert_eq!(read.channel, "config");
        let actors: Vec<Option<&str>> = read
            .records
            .iter()
            .map(|record| record.actor.as_deref())
            .collect();
        assert_eq!(
            actors,
            vec![None, Some("ops@example.com")],
            "newest first, and a watcher reload names nobody: {actors:?}"
        );

        let named = chain.0.read_window(&AuditChainQuery {
            actor: Some("ops@example.com".to_string()),
            limit: 10,
            ..AuditChainQuery::default()
        });
        assert_eq!(
            named.total_matched, 1,
            "a blank actor is not matched by a named filter: {named:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The time filter narrows and never widens, and an empty page is
    /// still a verified one: excluding every record must not read as a
    /// chain that failed, nor as one nobody checked.
    #[test]
    fn the_viewer_time_filter_narrows_and_never_widens() {
        let path = temp_path("viewer-time");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x44));
        for index in 0..3 {
            chain.append(&denial_from(&format!("when-{index}"), "203.0.113.7"));
        }
        let now = chrono::Utc::now().timestamp_millis();
        let day = 24 * 60 * 60 * 1000;

        let around = chain.0.read_window(&AuditChainQuery {
            since_ms: Some(now - day),
            until_ms: Some(now + day),
            limit: 10,
            ..AuditChainQuery::default()
        });
        assert_eq!(
            around.total_matched, 3,
            "a range around now keeps all three"
        );

        let tomorrow = chain.0.read_window(&AuditChainQuery {
            since_ms: Some(now + day),
            limit: 10,
            ..AuditChainQuery::default()
        });
        assert_eq!(tomorrow.total_matched, 0, "nothing was recorded tomorrow");
        assert!(tomorrow.records.is_empty());
        assert!(tomorrow.ok, "an empty page is a verified one: {tomorrow:?}");
        assert_eq!(tomorrow.verified_entries, 3);

        let yesterday = chain.0.read_window(&AuditChainQuery {
            until_ms: Some(now - day),
            limit: 10,
            ..AuditChainQuery::default()
        });
        assert_eq!(yesterday.total_matched, 0, "nor yesterday");

        let _ = std::fs::remove_file(&path);
    }

    /// The page size is clamped at both ends whatever a caller asks for.
    /// The window is the memory bound, so it is not negotiable.
    #[test]
    fn the_viewer_clamps_the_page_size() {
        let path = temp_path("viewer-limit");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x45));
        for index in 0..3 {
            chain.append(&denial_from(&format!("clamp-{index}"), "203.0.113.7"));
        }

        let zero = chain.0.read_window(&AuditChainQuery {
            limit: 0,
            ..AuditChainQuery::default()
        });
        assert_eq!(zero.records.len(), 1, "zero clamps up to one");
        assert_eq!(
            zero.total_matched, 3,
            "the clamp is on the page, not on the count"
        );

        let huge = chain.0.read_window(&AuditChainQuery {
            limit: MAX_AUDIT_CHAIN_LIMIT.saturating_mul(100),
            ..AuditChainQuery::default()
        });
        assert_eq!(huge.records.len(), 3, "there are only three to serve");
        assert!(huge.ok, "{huge:?}");

        let _ = std::fs::remove_file(&path);
    }

    /// A chain whose file has gone reports the failure rather than a
    /// clean verdict. "We could not check" and "we checked and it held"
    /// must never render the same way.
    #[test]
    fn the_viewer_never_reads_a_missing_chain_file_as_verified() {
        let path = temp_path("viewer-missing");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x46));
        chain.append(&denial_from("gone", "203.0.113.7"));
        std::fs::remove_file(&path).expect("the chain file is removable");

        let read = chain.0.read_window(&AuditChainQuery {
            limit: 10,
            ..AuditChainQuery::default()
        });

        assert!(
            !read.ok,
            "an unreadable file is not a verified one: {read:?}"
        );
        assert!(read.error.is_some(), "and it says so: {read:?}");
        assert!(read.records.is_empty(), "{read:?}");
        assert_eq!(read.verified_entries, 0);
    }

    /// A break stops the page as well as the verdict: nothing after a
    /// tampered record is served, because nothing proved it.
    #[test]
    fn the_viewer_serves_only_the_verified_prefix() {
        let path = temp_path("viewer-break");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x47));
        for index in 0..4 {
            chain.append(&denial_from(&format!("prefix-{index}"), "203.0.113.7"));
        }
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines[2] = lines[2].replace("\"reason\":\"prefix-2\"", "\"reason\":\"allowed\"");
        assert!(lines[2].contains("allowed"), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("chain is writable");

        let read = chain.0.read_window(&AuditChainQuery {
            limit: 10,
            ..AuditChainQuery::default()
        });

        assert!(!read.ok, "{read:?}");
        assert_eq!(read.broken_seq, Some(2));
        let seqs: Vec<u64> = read.records.iter().map(|record| record.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 0],
            "nothing past the break is served: {seqs:?}"
        );
        assert_eq!(read.verified_entries, 2);
        assert_eq!(read.chain_entries, 4, "the file still claims four");

        let _ = std::fs::remove_file(&path);
    }

    /// A file that lost records this process wrote never reads as
    /// verified, even though what is left of it verifies perfectly on
    /// its own terms. Truncating a trail is the most obvious tamper
    /// there is and the one a link check alone cannot see.
    #[test]
    fn a_truncated_chain_file_never_reads_as_verified() {
        let path = temp_path("viewer-truncated");
        let _ = std::fs::remove_file(&path);
        let chain = open_chain(&path, &seed(0x48));
        for index in 0..4 {
            chain.append(&denial_from(&format!("cut-{index}"), "203.0.113.7"));
        }
        let content = std::fs::read_to_string(&path).expect("chain is readable");
        let kept: Vec<&str> = content.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").expect("chain is writable");

        // The walk on its own is satisfied: two records, linked, signed.
        let bare = verify_security_audit_chain(&path, None).expect("file is readable");
        assert!(
            bare.ok,
            "a truncated prefix verifies on its own terms: {bare:?}"
        );

        let read = chain.0.read_window(&AuditChainQuery {
            limit: 10,
            ..AuditChainQuery::default()
        });

        assert!(
            !read.ok,
            "but the viewer knows four records were written: {read:?}"
        );
        assert_eq!(read.chain_entries, 4);
        assert_eq!(read.verified_entries, 2);
        assert_eq!(
            read.broken_seq,
            Some(2),
            "named at the first record that is gone: {read:?}"
        );
        assert!(
            read.reason
                .as_deref()
                .unwrap_or_default()
                .contains("missing"),
            "and the verdict says what happened: {read:?}"
        );
        // What survived is still evidence, and is still served.
        let seqs: Vec<u64> = read.records.iter().map(|record| record.seq).collect();
        assert_eq!(seqs, vec![1, 0], "{seqs:?}");

        let _ = std::fs::remove_file(&path);
    }

    /// `read_audit_chain` answers `None` for a channel with no chain and
    /// for a name that is not a channel at all, and
    /// `audit_chain_installed` agrees with it. The two are separate
    /// functions and the console asks both on every request, so a
    /// disagreement would render a configured chain as "off".
    #[test]
    fn an_uninstalled_or_unknown_channel_is_reported_the_same_way() {
        for name in ["not-a-channel", ""] {
            assert!(
                !audit_chain_installed(name),
                "{name} is not a channel at all"
            );
            assert!(
                read_audit_chain(name, &AuditChainQuery::default()).is_none(),
                "{name} has nothing to read"
            );
        }
        for name in AUDIT_CHAIN_CHANNELS {
            assert_eq!(
                audit_chain_installed(name),
                read_audit_chain(name, &AuditChainQuery::default()).is_some(),
                "{name}: installed and readable must be the same answer"
            );
        }
    }
}
