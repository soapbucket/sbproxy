//! The SQLite implementation of the durable settlement contract.
//!
//! SQLite is authoritative here. Every transition that could authorize a
//! request or move funds runs inside `BEGIN IMMEDIATE`, and every rule that
//! matters is a unique constraint or a compare-and-set rather than a read
//! followed by a write. Two processes sharing one database file therefore see
//! the same answers, which is what the crash test exercises.
//!
//! # Migration 1
//!
//! Eight tables, created under `user_version = 1`:
//!
//! | Table | Holds |
//! | --- | --- |
//! | `payment_intents` | One durable intent, its canonical draft, and its finalized requirement |
//! | `payment_attempts` | One provider attempt, its idempotency key, and its dispatch stamp |
//! | `payment_receipts` | The committed proof that a rail settled |
//! | `consumed_payment_proofs` | One proof digest per tenant, ever |
//! | `provider_events` | A redacted, append-only transition trail |
//! | `provider_recovery_envelopes` | Ciphertext only, never plaintext |
//! | `usage_reports` | Queued usage accounting, which never authorizes |
//! | `reconciliation_log` | What a provider query proved, and when |
//!
//! # Migration 2
//!
//! One column, `payment_intents.payer_hash`, added under `user_version = 2`
//! for WOR-2238. It is the opaque scope key
//! [`crate::store::SettlementStore::unresolved_intent_for_route`] matches
//! on, so an unresolved payment withholds fresh challenges from the payer it
//! stranded instead of from every payer of the route. Nullable with no
//! default: a row written by an older build has no payer scope, and the
//! query treats `NULL` as "matches every payer", which is exactly the
//! route-wide behavior those rows were written under. An upgrade therefore
//! cannot turn an existing unresolved intent into a second bill.
//!
//! # Migration 3
//!
//! One table, `served_quote_nonces`, added under `user_version = 3` for
//! WOR-2317. It is the durable half of single serve. Double *charge*
//! protection was already durable, because `consumed_payment_proofs` and
//! `payment_intents.reserved_proof_digest` are rows; double *serve*
//! protection was not, because the request-path nonce ledger was an
//! in-process set that emptied on restart. A client re-presenting an
//! already-settled quote token could therefore be served a second time,
//! once per restart, without paying twice.
//!
//! The table is written through [`SqliteSettlementStore::burn_quote_nonce`],
//! which is the one place a nonce is spent and the one place expired nonces
//! are forgotten. Both happen in a single `BEGIN IMMEDIATE` transaction, so
//! a burn is one commit rather than two.
//!
//! The reconciliation deadline added for the stranded-intent work needed no
//! migration of its own. It is derived from two columns that already exist,
//! `expires_at_ms` and `payer_hash`, and the state it writes is a new value
//! in the `status` column rather than a new column. A database written by
//! this build and read by an older one fails closed on the unknown spelling
//! (`IntentStatus::parse` returns `CorruptRecord`) rather than misreading a
//! stranded intent as something that authorizes.
//!
//! # What is deliberately not stored
//!
//! No credential, no authorization header, no client secret, no macaroon, no
//! rune, no provider response body, and no raw payer identifier reaches a
//! column. Proofs are stored as digests. Recovery material is stored as
//! ciphertext whose plaintext excludes every key. Failures are stored as a
//! closed category plus, at most, a character-class sanitized provider code.
//!
//! `payer_hash` is the one column that says anything at all about who is
//! paying, and it says it in one direction only: the request path derives it
//! through HKDF under a dedicated purpose before this crate ever sees it, so
//! the column holds a derived scope key rather than an address, a customer,
//! a key id, or a user agent. It exists to compare two requests to each
//! other and for nothing else. It is never read back out of the store into a
//! metric label, a log line, a trace field, or a response body, and no
//! method here returns it.
//!
//! # Concurrency
//!
//! `rusqlite` is synchronous, so each operation runs on the blocking pool
//! against a mutex-guarded connection. Write-ahead logging plus a bounded busy
//! timeout lets a second handle on the same file make progress instead of
//! failing immediately.

use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension as _, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::error::BillingError;
use crate::registry::UsageEvent;
use crate::store::{
    BillingClock, ClaimedAttempt, ClaimedUsageEvent, CreateIntent, IntentRecord, LeaseRecovery,
    PreparedAttempt, ProofReservation, ProviderAttempt, ReconciliationOutcome, SettlementStore,
    SharedSettlementStore, SystemClock, UsageOutcome,
};
use crate::types::{
    derive_attempt_id, derive_intent_id, AttemptOperation, AttemptStatus, FailureCategory,
    IntentStatus, PaymentProtocol, PaymentRequirement, PaymentRequirementDraft,
    RecoveryEnvelopeRecord, SafeFailure, SettlementRail, SettlementReceipt,
    SignedPaymentRequirement,
};

/// The schema version this build understands.
pub const SCHEMA_VERSION: i64 = 3;

/// Every table and index migration 1 creates.
const MIGRATION_1: &str = r#"
CREATE TABLE IF NOT EXISTS payment_intents (
    intent_id                TEXT    NOT NULL PRIMARY KEY,
    tenant_id                TEXT    NOT NULL,
    origin_id                TEXT    NOT NULL,
    route                    TEXT    NOT NULL,
    quote_id                 TEXT    NOT NULL,
    request_idempotency_key  TEXT    NOT NULL,
    protocol                 TEXT    NOT NULL,
    advertised_rail          TEXT    NOT NULL,
    settlement_rail          TEXT    NOT NULL,
    status                   TEXT    NOT NULL,
    draft_jcs                TEXT    NOT NULL,
    draft_digest             TEXT    NOT NULL,
    requirement_jcs          TEXT,
    requirement_digest       TEXT,
    quote_token              TEXT,
    quote_nonce              TEXT,
    reserved_proof_digest    TEXT,
    amount_micros            INTEGER NOT NULL,
    currency                 TEXT    NOT NULL,
    expires_at_ms            INTEGER NOT NULL,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL,
    retry_at_ms              INTEGER,
    failure_category         TEXT,
    failure_provider_code    TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_intents_request_key
    ON payment_intents (tenant_id, request_idempotency_key);

CREATE UNIQUE INDEX IF NOT EXISTS payment_intents_quote_nonce
    ON payment_intents (quote_nonce) WHERE quote_nonce IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS payment_intents_reserved_proof
    ON payment_intents (tenant_id, reserved_proof_digest)
    WHERE reserved_proof_digest IS NOT NULL;

CREATE INDEX IF NOT EXISTS payment_intents_sweep
    ON payment_intents (status, expires_at_ms);

CREATE INDEX IF NOT EXISTS payment_intents_route_status
    ON payment_intents (tenant_id, origin_id, route, status);

CREATE TABLE IF NOT EXISTS payment_attempts (
    attempt_id               TEXT    NOT NULL PRIMARY KEY,
    intent_id                TEXT    NOT NULL
        REFERENCES payment_intents (intent_id) ON DELETE CASCADE,
    tenant_id                TEXT    NOT NULL,
    rail                     TEXT    NOT NULL,
    operation                TEXT    NOT NULL,
    attempt_generation       INTEGER NOT NULL,
    provider_idempotency_key TEXT    NOT NULL,
    provider_handle          TEXT,
    lease_token              TEXT,
    lease_expires_at_ms      INTEGER,
    dispatch_started_at_ms   INTEGER,
    response_recorded_at_ms  INTEGER,
    status                   TEXT    NOT NULL,
    failure_category         TEXT,
    failure_provider_code    TEXT,
    failure_retryable        INTEGER,
    retry_at_ms              INTEGER,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_attempts_identity
    ON payment_attempts (intent_id, operation, attempt_generation);

CREATE UNIQUE INDEX IF NOT EXISTS payment_attempts_provider_key
    ON payment_attempts (rail, provider_idempotency_key);

CREATE INDEX IF NOT EXISTS payment_attempts_lease
    ON payment_attempts (status, lease_expires_at_ms);

CREATE TABLE IF NOT EXISTS payment_receipts (
    receipt_key         TEXT    NOT NULL PRIMARY KEY,
    intent_id           TEXT    NOT NULL
        REFERENCES payment_intents (intent_id) ON DELETE CASCADE,
    attempt_id          TEXT    NOT NULL,
    rail                TEXT    NOT NULL,
    method              TEXT    NOT NULL,
    provider_reference  TEXT    NOT NULL,
    settled_at_ms       INTEGER NOT NULL,
    created_at_ms       INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_receipts_intent
    ON payment_receipts (intent_id);

CREATE UNIQUE INDEX IF NOT EXISTS payment_receipts_provider_reference
    ON payment_receipts (rail, provider_reference);

CREATE TABLE IF NOT EXISTS consumed_payment_proofs (
    tenant_id       TEXT    NOT NULL,
    proof_digest    TEXT    NOT NULL,
    intent_id       TEXT    NOT NULL
        REFERENCES payment_intents (intent_id) ON DELETE CASCADE,
    reserved_at_ms  INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, proof_digest)
);

CREATE TABLE IF NOT EXISTS provider_events (
    event_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id            TEXT    NOT NULL,
    intent_id             TEXT    NOT NULL,
    rail                  TEXT    NOT NULL,
    operation             TEXT    NOT NULL,
    phase                 TEXT    NOT NULL,
    failure_category      TEXT,
    failure_provider_code TEXT,
    recorded_at_ms        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_events_attempt
    ON provider_events (attempt_id, event_id);

CREATE TABLE IF NOT EXISTS provider_recovery_envelopes (
    attempt_id      TEXT    NOT NULL PRIMARY KEY
        REFERENCES payment_attempts (attempt_id) ON DELETE CASCADE,
    key_id          TEXT    NOT NULL,
    nonce           BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    aad_digest      BLOB    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_recovery_envelopes_expiry
    ON provider_recovery_envelopes (expires_at_ms);

CREATE TABLE IF NOT EXISTS usage_reports (
    reporter                 TEXT    NOT NULL,
    usage_identifier         TEXT    NOT NULL,
    tenant_id                TEXT    NOT NULL,
    origin_id                TEXT    NOT NULL,
    event_jcs                TEXT    NOT NULL,
    provider_idempotency_key TEXT    NOT NULL,
    status                   TEXT    NOT NULL,
    lease_token              TEXT,
    lease_expires_at_ms      INTEGER,
    dispatch_started_at_ms   INTEGER,
    reported_at_ms           INTEGER,
    provider_reference       TEXT,
    retry_at_ms              INTEGER,
    failure_category         TEXT,
    failure_provider_code    TEXT,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL,
    PRIMARY KEY (reporter, usage_identifier)
);

CREATE INDEX IF NOT EXISTS usage_reports_queue
    ON usage_reports (status, retry_at_ms);

CREATE TABLE IF NOT EXISTS reconciliation_log (
    entry_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id            TEXT    NOT NULL,
    intent_id             TEXT    NOT NULL,
    outcome               TEXT    NOT NULL,
    failure_category      TEXT,
    failure_provider_code TEXT,
    recorded_at_ms        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS reconciliation_log_attempt
    ON reconciliation_log (attempt_id, entry_id);
"#;

/// WOR-2238: the payer scope key the unresolved-intent guard matches on.
///
/// `ALTER TABLE ... ADD COLUMN` is not idempotent the way `CREATE TABLE IF
/// NOT EXISTS` is, so unlike [`MIGRATION_1`] this batch runs exactly once,
/// guarded by the stamped `user_version`. Nullable with no default on
/// purpose: an existing row genuinely has no payer scope, and inventing one
/// would be claiming an identity the request that minted it never carried.
///
/// No new index. The guard's predicate is an `OR` over `payer_hash IS NULL`
/// and an equality, which no index can serve selectively, and
/// `payment_intents_route_status` already narrows the scan to one route's
/// unresolved rows before the payer test runs.
const MIGRATION_2: &str = r#"
ALTER TABLE payment_intents ADD COLUMN payer_hash TEXT;
"#;

/// WOR-2317: the durable ledger of quote nonces that have already served.
///
/// `nonce` is the primary key, which in a `WITHOUT ROWID`-less table is a
/// unique index, and that index is the whole concurrency argument. A burn is
/// an insert that either creates the row or conflicts; there is no read
/// followed by a write for two requests to interleave inside. Two
/// simultaneous presentations of one settled quote therefore produce exactly
/// one insert and one conflict, whichever order SQLite serializes them in.
///
/// `expires_at_ms` is nullable, and null means "no retention bound was
/// supplied, keep this row forever". That is the fail-closed default: a bound
/// nobody stated can never cause a row to be forgotten early, and forgetting
/// a burn early is the only way pruning could let a payment serve twice.
///
/// `burned_at_ms` is when the row was written. Nothing reads it back today;
/// it exists so an operator inspecting the database after an incident can see
/// when a nonce was spent, which the expiry alone cannot tell them.
///
/// Like [`MIGRATION_1`] and unlike [`MIGRATION_2`] this is
/// `CREATE ... IF NOT EXISTS` throughout, so it is idempotent and re-runs
/// harmlessly on every open.
const MIGRATION_3: &str = r#"
CREATE TABLE IF NOT EXISTS served_quote_nonces (
    nonce           TEXT    NOT NULL PRIMARY KEY,
    expires_at_ms   INTEGER,
    burned_at_ms    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS served_quote_nonces_expiry
    ON served_quote_nonces (expires_at_ms);
"#;

/// Every column `payment_intents` rows are read through, in order.
const INTENT_COLUMNS: &str = "intent_id, tenant_id, origin_id, route, quote_id, \
     request_idempotency_key, protocol, settlement_rail, status, draft_jcs, draft_digest, \
     requirement_jcs, requirement_digest, quote_token, quote_nonce, reserved_proof_digest, \
     expires_at_ms, created_at_ms, updated_at_ms";

/// Every column `payment_attempts` rows are read through, in order.
const ATTEMPT_COLUMNS: &str = "attempt_id, intent_id, tenant_id, rail, operation, \
     attempt_generation, provider_idempotency_key, provider_handle, lease_token, \
     lease_expires_at_ms, dispatch_started_at_ms, response_recorded_at_ms, status";

/// How the store is tuned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteStoreConfig {
    /// How long a lease taken by `prepare_attempt` or a claim stays live.
    pub lease_ttl_ms: i64,
    /// How long a writer waits for a competing writer before giving up.
    pub busy_timeout_ms: u64,
}

impl Default for SqliteStoreConfig {
    fn default() -> Self {
        Self {
            lease_ttl_ms: 30_000,
            busy_timeout_ms: 5_000,
        }
    }
}

/// What one call to [`SqliteSettlementStore::burn_quote_nonce`] proved.
///
/// Two variants, not three. The durable ledger has no "never registered"
/// state to report, because the burn is the insert: a nonce is either being
/// spent for the first time right now or it was spent before. There is
/// nothing for a pre-registration step to make known ahead of time, and so
/// no window in which one could be missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteNonceBurn {
    /// This call spent the nonce. The caller may serve exactly one response.
    Fresh,
    /// An earlier call already spent it. The caller must refuse as a replay.
    AlreadyServed,
}

/// The durable settlement store, backed by one SQLite database.
pub struct SqliteSettlementStore {
    connection: Arc<Mutex<Connection>>,
    clock: Arc<dyn BillingClock>,
    config: SqliteStoreConfig,
}

impl SqliteSettlementStore {
    /// Opens or creates a store at `path` with the default tuning.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] when the file cannot be opened and
    /// [`BillingError::UnsupportedSchema`] when the database was written by a
    /// newer build.
    pub fn open(path: &Path) -> Result<Self, BillingError> {
        Self::open_with_config(path, SqliteStoreConfig::default())
    }

    /// Opens or creates a store at `path` with explicit tuning.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`] or [`BillingError::UnsupportedSchema`].
    pub fn open_with_config(path: &Path, config: SqliteStoreConfig) -> Result<Self, BillingError> {
        // Create the database file owner-only (`0o600`) before SQLite
        // sees the path, and tighten it if a previous build left it at
        // `0o644`. Two reasons the order matters. SQLite would create
        // it at `0o666 & ~umask`, so on a default host the settlement
        // ledger, its amounts, and its payer identifiers would be
        // readable by every account on the box. And SQLite copies the
        // main database's mode onto the `-wal` and `-shm` sidecars it
        // opens under `journal_mode = WAL`, so getting the main file
        // right is what gets the sidecars right; there is no other
        // hook for them.
        //
        // `SQLITE_OPEN_URI` is set below, so a `file:` path is a URI
        // that SQLite resolves itself and may not name a file at all
        // (`mode=memory`). Pre-creating a literal `file:...` entry
        // would leave a junk file next to the real database, so that
        // form is handed straight through; every configured
        // `payments.state_path` in the shipped examples is a plain
        // path.
        if !path.to_string_lossy().starts_with("file:") {
            sbproxy_util::secure_fs::ensure_file_owner_only(path)
                .map_err(|_| BillingError::Storage("create settlement database owner-only"))?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|_| BillingError::Storage("open settlement database"))?;
        Self::from_connection(connection, config)
    }

    /// Opens a private in-memory store.
    ///
    /// This is for tests that do not need two handles. Crash and lease tests
    /// must use a file, because two in-memory handles are two databases.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::Storage`].
    pub fn open_in_memory() -> Result<Self, BillingError> {
        let connection = Connection::open_in_memory()
            .map_err(|_| BillingError::Storage("open settlement database"))?;
        Self::from_connection(connection, SqliteStoreConfig::default())
    }

    /// Replaces the clock the store stamps rows with.
    ///
    /// Only the transitions whose trait method takes no `now_ms` read this.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn BillingClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Wraps the store for sharing between the service and the worker.
    pub fn shared(self) -> SharedSettlementStore {
        Arc::new(self)
    }

    /// Returns the configured lease lifetime.
    pub const fn lease_ttl_ms(&self) -> i64 {
        self.config.lease_ttl_ms
    }

    /// Spends one quote nonce, durably, exactly once.
    ///
    /// This is the request path's single-serve ledger, and it lives in this
    /// database rather than beside it on purpose. The nonce burn and the
    /// settlement it authorizes are two facts about one payment, and putting
    /// them in one file means they cannot disagree about which file they are
    /// in: restoring a backup, moving `state_path`, or losing a volume moves
    /// both or neither.
    ///
    /// # Atomicity
    ///
    /// One statement, no read-then-write. The insert either creates the row
    /// or hits the primary key, and the affected-row count is what decides
    /// which of the two happened. Concurrent presentations of one nonce are
    /// serialized by SQLite's write lock, so exactly one of them sees a row
    /// count of 1 and every other one sees 0.
    ///
    /// # Retention
    ///
    /// `expires_at_ms` is the instant after which this nonce can never be
    /// validly presented again, which for a quote nonce is its token's `exp`.
    /// Rows at or past that instant are deleted at the start of the same
    /// transaction, so the table holds live nonces plus whatever expired
    /// since the previous burn and nothing else. Pruning inside the burn is
    /// what keeps the bound true without a scheduler: rows can only
    /// accumulate when burns are happening, and a burn is what prunes.
    ///
    /// Passing `None` keeps the row forever. Use it only where no bound is
    /// known, because an early deletion is the one pruning mistake that can
    /// let a settled payment serve twice.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::StoreUnavailable`] when the connection cannot
    /// be taken and [`BillingError::Storage`] when the transaction fails.
    /// Both mean the burn did not happen and the caller must refuse: there is
    /// no error here that a caller could read as a successful burn, because
    /// success is only ever [`QuoteNonceBurn::Fresh`] on the `Ok` side.
    pub fn burn_quote_nonce(
        &self,
        nonce: &str,
        expires_at_ms: Option<i64>,
    ) -> Result<QuoteNonceBurn, BillingError> {
        let now_ms = self.clock.now_ms();
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| BillingError::StoreUnavailable)?;
        let transaction = begin_immediate(&mut guard)?;

        // Prune first, so the insert is the last thing before the commit and
        // the row count it returns is unambiguous. Ordering cannot lose a
        // burn that still matters: the predicate is exactly "this token has
        // expired", and an expired token is refused before the gate ever
        // reaches a burn.
        transaction
            .execute(
                "DELETE FROM served_quote_nonces
                  WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?1",
                params![now_ms],
            )
            .map_err(|_| BillingError::Storage("prune served quote nonces"))?;

        let inserted = transaction
            .execute(
                "INSERT INTO served_quote_nonces (nonce, expires_at_ms, burned_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (nonce) DO NOTHING",
                params![nonce, expires_at_ms, now_ms],
            )
            .map_err(|_| BillingError::Storage("burn served quote nonce"))?;

        transaction
            .commit()
            .map_err(|_| BillingError::Storage("commit served quote nonce burn"))?;

        // One affected row means this call created it. Zero means the
        // primary key already held it, which is the replay.
        Ok(if inserted == 1 {
            QuoteNonceBurn::Fresh
        } else {
            QuoteNonceBurn::AlreadyServed
        })
    }

    /// Applies pragmas and migration 1 to an open connection.
    fn from_connection(
        connection: Connection,
        config: SqliteStoreConfig,
    ) -> Result<Self, BillingError> {
        connection
            .busy_timeout(std::time::Duration::from_millis(config.busy_timeout_ms))
            .map_err(|_| BillingError::Storage("set busy timeout"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL; \
                 PRAGMA foreign_keys = ON; \
                 PRAGMA synchronous = FULL;",
            )
            .map_err(|_| BillingError::Storage("apply settlement pragmas"))?;

        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| BillingError::Storage("read schema version"))?;
        if version > SCHEMA_VERSION {
            return Err(BillingError::UnsupportedSchema);
        }
        connection
            .execute_batch(MIGRATION_1)
            .map_err(|_| BillingError::Storage("apply migration 1"))?;
        // Migration 1 is idempotent and re-runs harmlessly on every open.
        // Migration 2 is an `ALTER TABLE`, which is not, so the stamped
        // version is what decides: a database opened at 0 (fresh) or 1
        // (written by a build before WOR-2238) gets the column, and one
        // already at 2 does not.
        if version < 2 {
            connection
                .execute_batch(MIGRATION_2)
                .map_err(|_| BillingError::Storage("apply migration 2"))?;
        }
        // Migration 3 is `CREATE ... IF NOT EXISTS` like migration 1, so it
        // is unconditional for the same reason: no stamped version has to be
        // trusted for it to be correct, and a database whose `user_version`
        // is somehow behind its tables still ends up with the table.
        connection
            .execute_batch(MIGRATION_3)
            .map_err(|_| BillingError::Storage("apply migration 3"))?;
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| BillingError::Storage("stamp schema version"))?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            clock: Arc::new(SystemClock),
            config,
        })
    }

    /// Runs one blocking database operation off the async runtime.
    async fn call<T, F>(&self, operation: F) -> Result<T, BillingError>
    where
        F: FnOnce(&mut Connection) -> Result<T, BillingError> + Send + 'static,
        T: Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut guard = connection
                .lock()
                .map_err(|_| BillingError::StoreUnavailable)?;
            operation(&mut guard)
        })
        .await
        .map_err(|_| BillingError::StoreUnavailable)?
    }
}

#[async_trait::async_trait]
impl SettlementStore for SqliteSettlementStore {
    async fn create_or_get_challenge(
        &self,
        draft: &PaymentRequirementDraft,
        draft_digest: [u8; 32],
        request_idempotency_key: &str,
        payer_hash: Option<&str>,
    ) -> Result<CreateIntent, BillingError> {
        if draft.digest()? != draft_digest {
            return Err(BillingError::DigestMismatch);
        }
        if request_idempotency_key.trim().is_empty() {
            return Err(BillingError::InvalidRequirement("request_idempotency_key"));
        }
        let intent_id = derive_intent_id(&draft.tenant_id, request_idempotency_key);
        let draft_jcs = canonical_json(draft)?;
        let draft_digest_hex = hex::encode(draft_digest);
        // The store column is a signed 64-bit integer, so an amount that
        // would wrap is rejected before any row exists.
        let amount_micros =
            i64::try_from(draft.amount.amount_micros).map_err(|_| BillingError::InvalidAmount)?;
        let now_ms = self.clock.now_ms();
        let draft = draft.clone();
        let request_idempotency_key = request_idempotency_key.to_string();
        let payer_hash = payer_hash.map(str::to_string);

        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            if let Some(existing) = load_intent(&transaction, &intent_id)? {
                // Resuming leaves `payer_hash` exactly as the insert wrote
                // it. The row's scope belongs to the payer the payment was
                // minted for, and letting a later caller restamp it would
                // let anyone who can reach this route move a stranded
                // intent out from under the payer it is protecting.
                if existing.draft_digest != draft_digest {
                    return Err(BillingError::IntentConflict);
                }
                let receipt = if existing.status == IntentStatus::Succeeded {
                    load_receipt(&transaction, &intent_id)?
                } else {
                    None
                };
                transaction
                    .commit()
                    .map_err(|_| BillingError::Storage("commit challenge read"))?;
                return Ok(CreateIntent {
                    intent_id,
                    status: existing.status,
                    created: false,
                    draft_digest: existing.draft_digest,
                    requirement_digest: existing.requirement_digest,
                    receipt,
                });
            }

            transaction
                .execute(
                    "INSERT INTO payment_intents (
                        intent_id, tenant_id, origin_id, route, quote_id,
                        request_idempotency_key, protocol, advertised_rail, settlement_rail,
                        status, draft_jcs, draft_digest, amount_micros, currency,
                        expires_at_ms, created_at_ms, updated_at_ms, payer_hash
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                     ?15, ?16, ?17, ?18)",
                    params![
                        intent_id,
                        draft.tenant_id,
                        draft.origin_id,
                        draft.route,
                        draft.quote_id,
                        request_idempotency_key,
                        draft.protocol.as_str(),
                        draft.advertised_rail.as_str(),
                        draft.settlement_rail.as_str(),
                        IntentStatus::Pending.as_str(),
                        draft_jcs,
                        draft_digest_hex,
                        amount_micros,
                        draft.amount.currency,
                        draft.expires_at_ms,
                        now_ms,
                        now_ms,
                        payer_hash,
                    ],
                )
                .map_err(|_| BillingError::Storage("insert settlement intent"))?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit settlement intent"))?;

            Ok(CreateIntent {
                intent_id,
                status: IntentStatus::Pending,
                created: true,
                draft_digest,
                requirement_digest: None,
                receipt: None,
            })
        })
        .await
    }

    async fn finalize_requirement(
        &self,
        intent_id: &str,
        signed: &SignedPaymentRequirement,
    ) -> Result<(), BillingError> {
        signed.verify_digests()?;
        let requirement_jcs = canonical_json(&signed.requirement)?;
        let requirement_digest = signed.requirement_digest;
        let draft_digest = signed.draft_digest;
        let quote_token = signed.quote_token.clone();
        let quote_nonce = signed.quote_nonce();
        let intent_id = intent_id.to_string();
        let now_ms = self.clock.now_ms();

        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let existing =
                load_intent(&transaction, &intent_id)?.ok_or(BillingError::IntentNotFound)?;
            if existing.draft_digest != draft_digest {
                return Err(BillingError::DigestMismatch);
            }
            if let Some(current) = existing.requirement_digest {
                // Finalizing twice is only allowed when it is the same final
                // value. A second, different requirement would let a signed
                // quote point at terms the intent never advertised.
                if current != requirement_digest
                    || existing.quote_token.as_deref() != Some(quote_token.as_str())
                {
                    return Err(BillingError::IntentConflict);
                }
                transaction
                    .commit()
                    .map_err(|_| BillingError::Storage("commit requirement replay"))?;
                return Ok(());
            }
            if existing.status != IntentStatus::Pending {
                return Err(BillingError::InvalidStateTransition {
                    from: existing.status,
                    to: IntentStatus::Pending,
                });
            }

            let updated = transaction
                .execute(
                    "UPDATE payment_intents
                        SET requirement_jcs = ?1, requirement_digest = ?2, quote_token = ?3,
                            quote_nonce = ?4, updated_at_ms = ?5
                      WHERE intent_id = ?6
                        AND draft_digest = ?7
                        AND requirement_digest IS NULL",
                    params![
                        requirement_jcs,
                        hex::encode(requirement_digest),
                        quote_token,
                        quote_nonce,
                        now_ms,
                        intent_id,
                        hex::encode(draft_digest),
                    ],
                )
                // The unique quote nonce is what stops one signed quote from
                // binding to a second requirement.
                .map_err(|_| BillingError::IntentConflict)?;
            if updated == 0 {
                return Err(BillingError::IntentConflict);
            }
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit finalized requirement"))?;
            Ok(())
        })
        .await
    }

    async fn latest_attempt(
        &self,
        intent_id: &str,
        operation: AttemptOperation,
    ) -> Result<Option<ProviderAttempt>, BillingError> {
        let intent_id = intent_id.to_string();
        self.call(move |connection| {
            let row = latest_attempt_row(connection, &intent_id, operation)?;
            Ok(row.map(|row| row.attempt))
        })
        .await
    }

    async fn prepare_attempt(
        &self,
        intent_id: &str,
        operation: AttemptOperation,
        provider_idempotency_key: &str,
        known_provider_handle: Option<&str>,
        now_ms: i64,
    ) -> Result<PreparedAttempt, BillingError> {
        let intent_id = intent_id.to_string();
        let provider_idempotency_key = provider_idempotency_key.to_string();
        let known_provider_handle = known_provider_handle.map(str::to_string);
        let lease_ttl_ms = self.config.lease_ttl_ms;

        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let intent =
                load_intent(&transaction, &intent_id)?.ok_or(BillingError::IntentNotFound)?;
            if intent.status == IntentStatus::Succeeded {
                return Err(BillingError::InvalidStateTransition {
                    from: IntentStatus::Succeeded,
                    to: IntentStatus::Processing,
                });
            }
            if !intent.status.allows_provider_write() {
                return Err(BillingError::InvalidStateTransition {
                    from: intent.status,
                    to: IntentStatus::Processing,
                });
            }

            let latest = latest_attempt_row(&transaction, &intent_id, operation)?;
            let lease_token = mint_lease_token();
            let lease_expires_at_ms = now_ms.saturating_add(lease_ttl_ms);

            let (attempt_id, created) = match latest {
                Some(ref row) if row.attempt.is_dispatched_unresolved() => {
                    // A write may already have landed. No new attempt, no new
                    // key, and no second charge.
                    return Err(BillingError::NeedsReconciliation);
                }
                Some(ref row)
                    if matches!(
                        row.attempt.status,
                        AttemptStatus::Prepared | AttemptStatus::RetryWait
                    ) && row.attempt.dispatch_started_at_ms.is_none() =>
                {
                    if row.lease_is_live(now_ms) {
                        return Err(BillingError::LeaseHeld);
                    }
                    transaction
                        .execute(
                            "UPDATE payment_attempts
                                SET lease_token = ?1, lease_expires_at_ms = ?2, status = ?3,
                                    provider_handle = COALESCE(?4, provider_handle),
                                    updated_at_ms = ?5
                              WHERE attempt_id = ?6
                                AND dispatch_started_at_ms IS NULL",
                            params![
                                lease_token,
                                lease_expires_at_ms,
                                AttemptStatus::Prepared.as_str(),
                                known_provider_handle,
                                now_ms,
                                row.attempt.attempt_id,
                            ],
                        )
                        .map_err(|_| BillingError::Storage("resume payment attempt"))?;
                    (row.attempt.attempt_id.clone(), false)
                }
                Some(ref row) if row.attempt.status == AttemptStatus::Succeeded => {
                    return Err(BillingError::InvalidStateTransition {
                        from: IntentStatus::Succeeded,
                        to: IntentStatus::Processing,
                    });
                }
                other => {
                    let generation = other
                        .as_ref()
                        .map_or(0, |row| row.attempt.attempt_generation + 1);
                    let attempt_id = derive_attempt_id(&intent_id, operation, generation);
                    transaction
                        .execute(
                            "INSERT INTO payment_attempts (
                                attempt_id, intent_id, tenant_id, rail, operation,
                                attempt_generation, provider_idempotency_key, provider_handle,
                                lease_token, lease_expires_at_ms, status, created_at_ms,
                                updated_at_ms
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                            params![
                                attempt_id,
                                intent_id,
                                intent.tenant_id,
                                intent.settlement_rail.as_str(),
                                operation.as_str(),
                                generation,
                                provider_idempotency_key,
                                known_provider_handle,
                                lease_token,
                                lease_expires_at_ms,
                                AttemptStatus::Prepared.as_str(),
                                now_ms,
                                now_ms,
                            ],
                        )
                        .map_err(map_constraint("insert payment attempt"))?;
                    (attempt_id, true)
                }
            };

            if operation != AttemptOperation::PrepareChallenge {
                set_intent_status(&transaction, &intent_id, IntentStatus::Processing, now_ms)?;
            }
            record_provider_event(
                &transaction,
                &attempt_id,
                &intent_id,
                intent.settlement_rail,
                operation,
                "prepared",
                None,
                now_ms,
            )?;

            let attempt = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("reload prepared attempt"))?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit prepared attempt"))?;

            Ok(PreparedAttempt {
                attempt: attempt.attempt,
                lease_token,
                lease_expires_at_ms,
                created,
            })
        })
        .await
    }

    async fn mark_dispatch_started(
        &self,
        attempt_id: &str,
        lease_token: &str,
        now_ms: i64,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("dispatch unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            if row.attempt.dispatch_started_at_ms.is_some() {
                // Stamping twice is a no-op rather than an error: the fact
                // being recorded is already recorded.
                transaction
                    .commit()
                    .map_err(|_| BillingError::Storage("commit dispatch replay"))?;
                return Ok(());
            }
            transaction
                .execute(
                    "UPDATE payment_attempts
                        SET dispatch_started_at_ms = ?1, status = ?2, updated_at_ms = ?1
                      WHERE attempt_id = ?3
                        AND lease_token = ?4
                        AND dispatch_started_at_ms IS NULL",
                    params![
                        now_ms,
                        AttemptStatus::Dispatched.as_str(),
                        attempt_id,
                        lease_token,
                    ],
                )
                .map_err(|_| BillingError::Storage("stamp dispatch"))?;
            record_provider_event(
                &transaction,
                &attempt_id,
                &row.attempt.intent_id,
                row.attempt.rail,
                row.attempt.operation,
                "dispatched",
                None,
                now_ms,
            )?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit dispatch stamp"))?;
            Ok(())
        })
        .await
    }

    async fn mark_succeeded(
        &self,
        attempt_id: &str,
        lease_token: &str,
        receipt: SettlementReceipt,
    ) -> Result<(), BillingError> {
        receipt.validate()?;
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        let now_ms = self.clock.now_ms();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("settle unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            if !row.attempt.operation.can_settle() {
                return Err(BillingError::UnsupportedOperation);
            }
            if row.attempt.dispatch_started_at_ms.is_none() {
                return Err(BillingError::InvalidStateTransition {
                    from: IntentStatus::Processing,
                    to: IntentStatus::Succeeded,
                });
            }
            if row.attempt.intent_id != receipt.intent_id {
                return Err(BillingError::RequirementMismatch);
            }
            commit_success(&transaction, &row, &receipt, now_ms)?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit settlement receipt"))?;
            Ok(())
        })
        .await
    }

    async fn mark_retry_wait_before_dispatch(
        &self,
        attempt_id: &str,
        lease_token: &str,
        retry_at_ms: i64,
        failure: SafeFailure,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        let now_ms = self.clock.now_ms();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("retry unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            if row.attempt.dispatch_started_at_ms.is_some() {
                return Err(BillingError::AlreadyDispatched);
            }
            transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, retry_at_ms = ?2, failure_category = ?3,
                            failure_provider_code = ?4, failure_retryable = ?5,
                            lease_token = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?6
                      WHERE attempt_id = ?7
                        AND lease_token = ?8
                        AND dispatch_started_at_ms IS NULL",
                    params![
                        AttemptStatus::RetryWait.as_str(),
                        retry_at_ms,
                        failure.category.as_str(),
                        failure.provider_code,
                        i64::from(failure.retryable),
                        now_ms,
                        attempt_id,
                        lease_token,
                    ],
                )
                .map_err(|_| BillingError::Storage("record retry wait"))?;
            set_intent_status(
                &transaction,
                &row.attempt.intent_id,
                IntentStatus::RetryWait,
                now_ms,
            )?;
            record_provider_event(
                &transaction,
                &attempt_id,
                &row.attempt.intent_id,
                row.attempt.rail,
                row.attempt.operation,
                "retry_wait",
                Some(&failure),
                now_ms,
            )?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit retry wait"))?;
            Ok(())
        })
        .await
    }

    async fn mark_terminal(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        let now_ms = self.clock.now_ms();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("fail unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            // A dispatched attempt reaching a definitive failure means the
            // provider answered. Recording that answer is what separates this
            // from reconciliation, so the response stamp lands here too.
            let response_recorded_at_ms = row
                .attempt
                .dispatch_started_at_ms
                .map(|_| row.attempt.response_recorded_at_ms.unwrap_or(now_ms));
            transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, failure_category = ?2, failure_provider_code = ?3,
                            failure_retryable = ?4, response_recorded_at_ms = ?5,
                            lease_token = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?6
                      WHERE attempt_id = ?7 AND lease_token = ?8",
                    params![
                        AttemptStatus::Terminal.as_str(),
                        failure.category.as_str(),
                        failure.provider_code,
                        i64::from(failure.retryable),
                        response_recorded_at_ms,
                        now_ms,
                        attempt_id,
                        lease_token,
                    ],
                )
                .map_err(|_| BillingError::Storage("record terminal attempt"))?;
            set_intent_failure(
                &transaction,
                &row.attempt.intent_id,
                IntentStatus::Terminal,
                &failure,
                now_ms,
            )?;
            record_provider_event(
                &transaction,
                &attempt_id,
                &row.attempt.intent_id,
                row.attempt.rail,
                row.attempt.operation,
                "terminal",
                Some(&failure),
                now_ms,
            )?;
            purge_envelope(&transaction, &attempt_id)?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit terminal attempt"))?;
            Ok(())
        })
        .await
    }

    async fn mark_needs_reconciliation(
        &self,
        attempt_id: &str,
        lease_token: &str,
        failure: SafeFailure,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        let now_ms = self.clock.now_ms();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("reconcile unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            if row.attempt.dispatch_started_at_ms.is_none() {
                // Nothing was sent, so there is nothing to reconcile. Calling
                // this here would invent ambiguity that does not exist.
                return Err(BillingError::InvalidStateTransition {
                    from: IntentStatus::Processing,
                    to: IntentStatus::NeedsReconciliation,
                });
            }
            transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, failure_category = ?2, failure_provider_code = ?3,
                            failure_retryable = ?4, lease_token = NULL,
                            lease_expires_at_ms = NULL, updated_at_ms = ?5
                      WHERE attempt_id = ?6 AND lease_token = ?7",
                    params![
                        AttemptStatus::NeedsReconciliation.as_str(),
                        failure.category.as_str(),
                        failure.provider_code,
                        i64::from(failure.retryable),
                        now_ms,
                        attempt_id,
                        lease_token,
                    ],
                )
                .map_err(|_| BillingError::Storage("record reconciliation need"))?;
            set_intent_failure(
                &transaction,
                &row.attempt.intent_id,
                IntentStatus::NeedsReconciliation,
                &failure,
                now_ms,
            )?;
            record_provider_event(
                &transaction,
                &attempt_id,
                &row.attempt.intent_id,
                row.attempt.rail,
                row.attempt.operation,
                "needs_reconciliation",
                Some(&failure),
                now_ms,
            )?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit reconciliation need"))?;
            Ok(())
        })
        .await
    }

    async fn mark_challenge_prepared(
        &self,
        attempt_id: &str,
        lease_token: &str,
        provider_handle: Option<&str>,
        now_ms: i64,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        let provider_handle = provider_handle.map(str::to_string);
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("prepare unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }
            if row.attempt.operation != AttemptOperation::PrepareChallenge {
                return Err(BillingError::UnsupportedOperation);
            }
            transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, provider_handle = COALESCE(?2, provider_handle),
                            response_recorded_at_ms = ?3, lease_token = NULL,
                            lease_expires_at_ms = NULL, updated_at_ms = ?3
                      WHERE attempt_id = ?4 AND lease_token = ?5",
                    params![
                        AttemptStatus::Succeeded.as_str(),
                        provider_handle,
                        now_ms,
                        attempt_id,
                        lease_token,
                    ],
                )
                .map_err(|_| BillingError::Storage("record prepared challenge"))?;
            record_provider_event(
                &transaction,
                &attempt_id,
                &row.attempt.intent_id,
                row.attempt.rail,
                row.attempt.operation,
                "challenge_prepared",
                None,
                now_ms,
            )?;
            purge_envelope(&transaction, &attempt_id)?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit prepared challenge"))?;
            Ok(())
        })
        .await
    }

    async fn load_intent(&self, intent_id: &str) -> Result<Option<IntentRecord>, BillingError> {
        let intent_id = intent_id.to_string();
        self.call(move |connection| load_intent(connection, &intent_id))
            .await
    }

    async fn load_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<Option<ProviderAttempt>, BillingError> {
        let attempt_id = attempt_id.to_string();
        self.call(move |connection| {
            Ok(load_attempt_row(connection, &attempt_id)?.map(|row| row.attempt))
        })
        .await
    }

    async fn load_access_receipt(
        &self,
        intent_id: &str,
    ) -> Result<Option<SettlementReceipt>, BillingError> {
        let intent_id = intent_id.to_string();
        self.call(move |connection| {
            let Some(intent) = load_intent(connection, &intent_id)? else {
                return Ok(None);
            };
            // The state check lives here so no call site can forget it.
            if !intent.status.authorizes_origin() {
                return Ok(None);
            }
            load_receipt(connection, &intent_id)
        })
        .await
    }

    async fn unresolved_intent_for_route(
        &self,
        tenant_id: &str,
        origin_id: &str,
        route: &str,
        payer_hash: Option<&str>,
    ) -> Result<Option<String>, BillingError> {
        let tenant_id = tenant_id.to_string();
        let origin_id = origin_id.to_string();
        let route = route.to_string();
        let payer_hash = payer_hash.map(str::to_string);
        self.call(move |connection| {
            // Oldest first, so the intent an operator is told about is the one
            // that has been stuck longest rather than whichever row the
            // planner reached first.
            //
            // The payer clause (WOR-2238) is three ways of saying "this
            // request could be the payer whose money is stuck": the scopes
            // match, the row predates payer scoping and belongs to nobody in
            // particular, or this request carries no identity to compare.
            // Only two identified and different payers fall through it.
            //
            // Known and out of scope here (WOR-2230's original notes, still
            // true): this is a read with no lock, so two simultaneous
            // tokenless requests can both pass it; `/article` and `/article/`
            // are two routes and get two bills; and the read hits the local
            // SQLite file, so in a multi-node deployment the guard is per
            // store rather than per cluster.
            connection
                .query_row(
                    "SELECT intent_id FROM payment_intents
                      WHERE tenant_id = ?1 AND origin_id = ?2 AND route = ?3
                        AND status = ?4
                        AND (payer_hash IS NULL OR ?5 IS NULL OR payer_hash = ?5)
                      ORDER BY created_at_ms
                      LIMIT 1",
                    params![
                        tenant_id,
                        origin_id,
                        route,
                        IntentStatus::NeedsReconciliation.as_str(),
                        payer_hash,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| BillingError::Storage("read unresolved route intent"))
        })
        .await
    }

    async fn reserve_proof(
        &self,
        intent_id: &str,
        proof_digest: [u8; 32],
        now_ms: i64,
    ) -> Result<ProofReservation, BillingError> {
        let intent_id = intent_id.to_string();
        let digest_hex = hex::encode(proof_digest);
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let intent =
                load_intent(&transaction, &intent_id)?.ok_or(BillingError::IntentNotFound)?;

            if intent.status == IntentStatus::Succeeded {
                if intent.reserved_proof_digest != Some(proof_digest) {
                    return Err(BillingError::ProofConflict);
                }
                let receipt =
                    load_receipt(&transaction, &intent_id)?.ok_or(BillingError::CorruptRecord)?;
                transaction
                    .commit()
                    .map_err(|_| BillingError::Storage("commit settled proof read"))?;
                return Ok(ProofReservation::AlreadySettled(receipt));
            }

            if let Some(existing) = intent.reserved_proof_digest {
                if existing != proof_digest {
                    return Err(BillingError::ProofConflict);
                }
                transaction
                    .commit()
                    .map_err(|_| BillingError::Storage("commit proof replay"))?;
                return Ok(ProofReservation::AlreadyReservedForIntent);
            }

            let owner: Option<String> = transaction
                .query_row(
                    "SELECT intent_id FROM consumed_payment_proofs
                      WHERE tenant_id = ?1 AND proof_digest = ?2",
                    params![intent.tenant_id, digest_hex],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| BillingError::Storage("read consumed proof"))?;
            if let Some(owner) = owner {
                if owner != intent_id {
                    return Err(BillingError::ProofReplayed);
                }
            } else {
                transaction
                    .execute(
                        "INSERT INTO consumed_payment_proofs
                            (tenant_id, proof_digest, intent_id, reserved_at_ms)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![intent.tenant_id, digest_hex, intent_id, now_ms],
                    )
                    .map_err(|_| BillingError::ProofReplayed)?;
            }

            transaction
                .execute(
                    "UPDATE payment_intents
                        SET reserved_proof_digest = ?1, updated_at_ms = ?2
                      WHERE intent_id = ?3 AND reserved_proof_digest IS NULL",
                    params![digest_hex, now_ms, intent_id],
                )
                .map_err(|_| BillingError::ProofConflict)?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit proof reservation"))?;
            Ok(ProofReservation::Reserved)
        })
        .await
    }

    async fn put_recovery_envelope(
        &self,
        envelope: &RecoveryEnvelopeRecord,
    ) -> Result<(), BillingError> {
        let envelope = envelope.clone();
        self.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO provider_recovery_envelopes
                        (attempt_id, key_id, nonce, ciphertext, aad_digest, created_at_ms,
                         expires_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT (attempt_id) DO UPDATE SET
                        key_id = excluded.key_id, nonce = excluded.nonce,
                        ciphertext = excluded.ciphertext, aad_digest = excluded.aad_digest,
                        created_at_ms = excluded.created_at_ms,
                        expires_at_ms = excluded.expires_at_ms",
                    params![
                        envelope.attempt_id,
                        envelope.key_id,
                        envelope.nonce.to_vec(),
                        envelope.ciphertext,
                        envelope.aad_digest.to_vec(),
                        envelope.created_at_ms,
                        envelope.expires_at_ms,
                    ],
                )
                .map_err(|_| BillingError::Storage("store recovery envelope"))?;
            Ok(())
        })
        .await
    }

    async fn load_recovery_envelope(
        &self,
        attempt_id: &str,
    ) -> Result<Option<RecoveryEnvelopeRecord>, BillingError> {
        let attempt_id = attempt_id.to_string();
        self.call(move |connection| {
            let row = connection
                .query_row(
                    "SELECT attempt_id, key_id, nonce, ciphertext, aad_digest, created_at_ms,
                            expires_at_ms
                       FROM provider_recovery_envelopes WHERE attempt_id = ?1",
                    params![attempt_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| BillingError::Storage("read recovery envelope"))?;
            let Some((attempt_id, key_id, nonce, ciphertext, aad_digest, created, expires)) = row
            else {
                return Ok(None);
            };
            Ok(Some(RecoveryEnvelopeRecord {
                attempt_id,
                key_id,
                nonce: nonce.try_into().map_err(|_| BillingError::CorruptRecord)?,
                ciphertext,
                aad_digest: aad_digest
                    .try_into()
                    .map_err(|_| BillingError::CorruptRecord)?,
                created_at_ms: created,
                expires_at_ms: expires,
            }))
        })
        .await
    }

    async fn purge_recovery_envelope(&self, attempt_id: &str) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        self.call(move |connection| purge_envelope(connection, &attempt_id))
            .await
    }

    async fn purge_expired_recovery_envelopes(&self, now_ms: i64) -> Result<u64, BillingError> {
        self.call(move |connection| {
            let purged = connection
                .execute(
                    "DELETE FROM provider_recovery_envelopes WHERE expires_at_ms <= ?1",
                    params![now_ms],
                )
                .map_err(|_| BillingError::Storage("purge expired envelopes"))?;
            Ok(purged as u64)
        })
        .await
    }

    async fn strand_unattributable_intents(
        &self,
        now_ms: i64,
        grace_ms: i64,
        limit: u32,
    ) -> Result<u64, BillingError> {
        // Computed here rather than as `expires_at_ms + ?grace` in SQL, so
        // the arithmetic saturates in Rust instead of wrapping in SQLite on a
        // row with an absurd stored expiry.
        let cutoff_ms = now_ms.saturating_sub(grace_ms.max(0));
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            // Three conditions, and dropping any one of them is a double
            // charge or a lost payment.
            //
            // `status = needs_reconciliation` keeps this away from every
            // intent that is merely waiting: a `Pending` or `RetryWait` row
            // has no outstanding write and is the challenge sweep's job.
            //
            // `payer_hash IS NULL` is the whole scope of WOR-2317. A row with
            // a payer scope withholds the route from one identified payer and
            // from nobody else, and that payer is someone the deployment may
            // concretely owe. Only the rows that withhold from everybody, on
            // the mere possibility that one of them is the stranded payer,
            // age out.
            //
            // `expires_at_ms <= cutoff` is the deadline itself. The quote
            // token signs `exp` from this same column, and the verifier
            // refuses an expired token, so past it no holder can redeem this
            // intent however the funds land.
            //
            // Oldest expiry first, so a backlog drains in the order it
            // stranded rather than in whatever order the planner walks.
            //
            // Nothing else on the row is touched. `failure_category` keeps
            // the `ambiguous` value `mark_needs_reconciliation` wrote, the
            // attempt keeps its `needs_reconciliation` status and stays on
            // the reconciliation queue, and no receipt is created. This
            // sweep releases a gate; it does not decide anything about money.
            let stranded = transaction
                .execute(
                    "UPDATE payment_intents
                        SET status = ?1, updated_at_ms = ?2
                      WHERE intent_id IN (
                            SELECT intent_id FROM payment_intents
                             WHERE status = ?3
                               AND payer_hash IS NULL
                               AND expires_at_ms <= ?4
                             ORDER BY expires_at_ms
                             LIMIT ?5)",
                    params![
                        IntentStatus::Stranded.as_str(),
                        now_ms,
                        IntentStatus::NeedsReconciliation.as_str(),
                        cutoff_ms,
                        limit,
                    ],
                )
                .map_err(|_| BillingError::Storage("strand unattributable intents"))?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit stranded intents"))?;
            Ok(stranded as u64)
        })
        .await
    }

    async fn expire_stale_challenges(&self, now_ms: i64, limit: u32) -> Result<u64, BillingError> {
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let expired = transaction
                .execute(
                    "UPDATE payment_intents
                        SET status = ?1, failure_category = ?2, updated_at_ms = ?3
                      WHERE intent_id IN (
                            SELECT i.intent_id FROM payment_intents i
                             WHERE i.status = ?4
                               AND i.expires_at_ms <= ?3
                               AND NOT EXISTS (
                                   SELECT 1 FROM payment_attempts a
                                    WHERE a.intent_id = i.intent_id
                                      AND a.dispatch_started_at_ms IS NOT NULL
                                      AND a.response_recorded_at_ms IS NULL)
                             LIMIT ?5)",
                    params![
                        IntentStatus::Terminal.as_str(),
                        FailureCategory::Expired.as_str(),
                        now_ms,
                        IntentStatus::Pending.as_str(),
                        limit,
                    ],
                )
                .map_err(|_| BillingError::Storage("expire stale challenges"))?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit challenge expiry"))?;
            Ok(expired as u64)
        })
        .await
    }

    async fn recover_stale_leases(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<LeaseRecovery, BillingError> {
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;

            // No stamp means nothing was sent, so the attempt may retry.
            let returned = transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, lease_token = NULL, lease_expires_at_ms = NULL,
                            failure_category = ?2, updated_at_ms = ?3
                      WHERE attempt_id IN (
                            SELECT attempt_id FROM payment_attempts
                             WHERE status = ?4
                               AND lease_expires_at_ms IS NOT NULL
                               AND lease_expires_at_ms <= ?3
                               AND dispatch_started_at_ms IS NULL
                             LIMIT ?5)",
                    params![
                        AttemptStatus::RetryWait.as_str(),
                        FailureCategory::Unavailable.as_str(),
                        now_ms,
                        AttemptStatus::Prepared.as_str(),
                        limit,
                    ],
                )
                .map_err(|_| BillingError::Storage("recover undispatched leases"))?;

            // A stamp with no recorded response means a write may have landed.
            let ambiguous = transaction
                .execute(
                    "UPDATE payment_attempts
                        SET status = ?1, lease_token = NULL, lease_expires_at_ms = NULL,
                            failure_category = ?2, updated_at_ms = ?3
                      WHERE attempt_id IN (
                            SELECT attempt_id FROM payment_attempts
                             WHERE status = ?4
                               AND lease_expires_at_ms IS NOT NULL
                               AND lease_expires_at_ms <= ?3
                               AND dispatch_started_at_ms IS NOT NULL
                               AND response_recorded_at_ms IS NULL
                             LIMIT ?5)",
                    params![
                        AttemptStatus::NeedsReconciliation.as_str(),
                        FailureCategory::Ambiguous.as_str(),
                        now_ms,
                        AttemptStatus::Dispatched.as_str(),
                        limit,
                    ],
                )
                .map_err(|_| BillingError::Storage("recover dispatched leases"))?;

            // Intents follow their attempts, and never out of a final state.
            //
            // `Stranded` joins that exclusion list even though it is not
            // final (WOR-2317). A stranded intent's attempt is still
            // `needs_reconciliation` by design, so without this clause the
            // very next lease sweep would drag the intent back to
            // `NeedsReconciliation` and re-gate the route, and the deadline
            // would hold for exactly one sweep interval. The intent can still
            // leave `Stranded`, but only through `record_reconciliation`,
            // where a provider actually proved something.
            transaction
                .execute(
                    "UPDATE payment_intents
                        SET status = ?1, updated_at_ms = ?2
                      WHERE status NOT IN (?3, ?4, ?5)
                        AND intent_id IN (
                            SELECT intent_id FROM payment_attempts WHERE status = ?6)",
                    params![
                        IntentStatus::NeedsReconciliation.as_str(),
                        now_ms,
                        IntentStatus::Succeeded.as_str(),
                        IntentStatus::Terminal.as_str(),
                        IntentStatus::Stranded.as_str(),
                        AttemptStatus::NeedsReconciliation.as_str(),
                    ],
                )
                .map_err(|_| BillingError::Storage("propagate reconciliation state"))?;
            transaction
                .execute(
                    "UPDATE payment_intents
                        SET status = ?1, updated_at_ms = ?2
                      WHERE status = ?3
                        AND intent_id IN (
                            SELECT intent_id FROM payment_attempts
                             WHERE status = ?4 AND dispatch_started_at_ms IS NULL)",
                    params![
                        IntentStatus::RetryWait.as_str(),
                        now_ms,
                        IntentStatus::Processing.as_str(),
                        AttemptStatus::RetryWait.as_str(),
                    ],
                )
                .map_err(|_| BillingError::Storage("propagate retry state"))?;

            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit lease recovery"))?;
            Ok(LeaseRecovery {
                returned_to_retry_wait: returned as u64,
                moved_to_needs_reconciliation: ambiguous as u64,
            })
        })
        .await
    }

    async fn claim_reconciliation(
        &self,
        now_ms: i64,
        lease_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<ClaimedAttempt>, BillingError> {
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let ids: Vec<String> = {
                let mut statement = transaction
                    .prepare(
                        "SELECT attempt_id FROM payment_attempts
                          WHERE status = ?1
                            AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= ?2)
                          ORDER BY updated_at_ms LIMIT ?3",
                    )
                    .map_err(|_| BillingError::Storage("prepare reconciliation claim"))?;
                let rows = statement
                    .query_map(
                        params![AttemptStatus::NeedsReconciliation.as_str(), now_ms, limit],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|_| BillingError::Storage("scan reconciliation queue"))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|_| BillingError::Storage("read reconciliation queue"))?
            };

            let mut claimed = Vec::with_capacity(ids.len());
            for attempt_id in ids {
                let lease_token = mint_lease_token();
                let lease_expires_at_ms = now_ms.saturating_add(lease_ttl_ms);
                let updated = transaction
                    .execute(
                        "UPDATE payment_attempts
                            SET lease_token = ?1, lease_expires_at_ms = ?2, updated_at_ms = ?3
                          WHERE attempt_id = ?4 AND status = ?5",
                        params![
                            lease_token,
                            lease_expires_at_ms,
                            now_ms,
                            attempt_id,
                            AttemptStatus::NeedsReconciliation.as_str(),
                        ],
                    )
                    .map_err(|_| BillingError::Storage("claim reconciliation attempt"))?;
                if updated == 0 {
                    continue;
                }
                let row = load_attempt_row(&transaction, &attempt_id)?
                    .ok_or(BillingError::Storage("reload claimed attempt"))?;
                claimed.push(PreparedAttempt {
                    attempt: row.attempt,
                    lease_token,
                    lease_expires_at_ms,
                    created: false,
                });
            }
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit reconciliation claim"))?;
            Ok(claimed)
        })
        .await
    }

    async fn record_reconciliation(
        &self,
        attempt_id: &str,
        lease_token: &str,
        outcome: ReconciliationOutcome,
        now_ms: i64,
    ) -> Result<(), BillingError> {
        let attempt_id = attempt_id.to_string();
        let lease_token = lease_token.to_string();
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let row = load_attempt_row(&transaction, &attempt_id)?
                .ok_or(BillingError::Storage("reconcile unknown attempt"))?;
            if row.lease_token.as_deref() != Some(lease_token.as_str()) {
                return Err(BillingError::LeaseLost);
            }

            let (label, failure) = match &outcome {
                ReconciliationOutcome::ProvenSucceeded(receipt) => {
                    receipt.validate()?;
                    if receipt.intent_id != row.attempt.intent_id {
                        return Err(BillingError::RequirementMismatch);
                    }
                    if !row.attempt.operation.can_settle() {
                        return Err(BillingError::UnsupportedOperation);
                    }
                    commit_success(&transaction, &row, receipt, now_ms)?;
                    ("proven_succeeded", None)
                }
                ReconciliationOutcome::ProvenNotDispatched(failure) => {
                    // The provider proved the write never landed, so this
                    // attempt is finished and a later client retry may open a
                    // fresh generation with a fresh key.
                    close_attempt(
                        &transaction,
                        &attempt_id,
                        &lease_token,
                        AttemptStatus::Terminal,
                        failure,
                        Some(now_ms),
                        now_ms,
                    )?;
                    set_intent_status(
                        &transaction,
                        &row.attempt.intent_id,
                        IntentStatus::RetryWait,
                        now_ms,
                    )?;
                    purge_envelope(&transaction, &attempt_id)?;
                    ("proven_not_dispatched", Some(failure.clone()))
                }
                ReconciliationOutcome::ProvenFailed(failure) => {
                    close_attempt(
                        &transaction,
                        &attempt_id,
                        &lease_token,
                        AttemptStatus::Terminal,
                        failure,
                        Some(now_ms),
                        now_ms,
                    )?;
                    set_intent_failure(
                        &transaction,
                        &row.attempt.intent_id,
                        IntentStatus::Terminal,
                        failure,
                        now_ms,
                    )?;
                    purge_envelope(&transaction, &attempt_id)?;
                    ("proven_failed", Some(failure.clone()))
                }
                ReconciliationOutcome::Unresolved(failure) => {
                    // Nothing was proved, so nothing changes except the lease.
                    close_attempt(
                        &transaction,
                        &attempt_id,
                        &lease_token,
                        AttemptStatus::NeedsReconciliation,
                        failure,
                        None,
                        now_ms,
                    )?;
                    ("unresolved", Some(failure.clone()))
                }
            };

            transaction
                .execute(
                    "INSERT INTO reconciliation_log
                        (attempt_id, intent_id, outcome, failure_category,
                         failure_provider_code, recorded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        attempt_id,
                        row.attempt.intent_id,
                        label,
                        failure.as_ref().map(|failure| failure.category.as_str()),
                        failure
                            .as_ref()
                            .and_then(|failure| failure.provider_code.clone()),
                        now_ms,
                    ],
                )
                .map_err(|_| BillingError::Storage("write reconciliation log"))?;
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit reconciliation outcome"))?;
            Ok(())
        })
        .await
    }

    async fn enqueue_usage_event(&self, event: &UsageEvent) -> Result<bool, BillingError> {
        if event.reporter.trim().is_empty() || event.usage_identifier.trim().is_empty() {
            return Err(BillingError::InvalidRequirement("usage_identifier"));
        }
        let event_jcs = canonical_json(event)?;
        let key = usage_idempotency_key(&event.reporter, &event.usage_identifier);
        let event = event.clone();
        let now_ms = self.clock.now_ms();
        self.call(move |connection| {
            let inserted = connection
                .execute(
                    "INSERT OR IGNORE INTO usage_reports
                        (reporter, usage_identifier, tenant_id, origin_id, event_jcs,
                         provider_idempotency_key, status, created_at_ms, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?7)",
                    params![
                        event.reporter,
                        event.usage_identifier,
                        event.tenant_id,
                        event.origin_id,
                        event_jcs,
                        key,
                        now_ms,
                    ],
                )
                .map_err(|_| BillingError::Storage("queue usage event"))?;
            Ok(inserted == 1)
        })
        .await
    }

    async fn claim_usage_events(
        &self,
        now_ms: i64,
        lease_ttl_ms: i64,
        limit: u32,
    ) -> Result<Vec<ClaimedUsageEvent>, BillingError> {
        self.call(move |connection| {
            let transaction = begin_immediate(connection)?;
            let rows: Vec<(String, String, String, String, Option<i64>)> = {
                let mut statement = transaction
                    .prepare(
                        "SELECT reporter, usage_identifier, event_jcs, provider_idempotency_key,
                                dispatch_started_at_ms
                           FROM usage_reports
                          WHERE status = 'queued'
                            AND (retry_at_ms IS NULL OR retry_at_ms <= ?1)
                            AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= ?1)
                          ORDER BY updated_at_ms LIMIT ?2",
                    )
                    .map_err(|_| BillingError::Storage("prepare usage claim"))?;
                let mapped = statement
                    .query_map(params![now_ms, limit], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                        ))
                    })
                    .map_err(|_| BillingError::Storage("scan usage queue"))?;
                mapped
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| BillingError::Storage("read usage queue"))?
            };

            let mut claimed = Vec::with_capacity(rows.len());
            for (reporter, usage_identifier, event_jcs, key, dispatched) in rows {
                let lease_token = mint_lease_token();
                let updated = transaction
                    .execute(
                        "UPDATE usage_reports
                            SET lease_token = ?1, lease_expires_at_ms = ?2, updated_at_ms = ?3
                          WHERE reporter = ?4 AND usage_identifier = ?5 AND status = 'queued'",
                        params![
                            lease_token,
                            now_ms.saturating_add(lease_ttl_ms),
                            now_ms,
                            reporter,
                            usage_identifier,
                        ],
                    )
                    .map_err(|_| BillingError::Storage("claim usage event"))?;
                if updated == 0 {
                    continue;
                }
                let event: UsageEvent =
                    serde_json::from_str(&event_jcs).map_err(|_| BillingError::CorruptRecord)?;
                claimed.push(ClaimedUsageEvent {
                    event,
                    lease_token,
                    provider_idempotency_key: key,
                    previously_dispatched: dispatched.is_some(),
                });
            }
            transaction
                .commit()
                .map_err(|_| BillingError::Storage("commit usage claim"))?;
            Ok(claimed)
        })
        .await
    }

    async fn mark_usage_dispatch_started(
        &self,
        reporter: &str,
        usage_identifier: &str,
        lease_token: &str,
        now_ms: i64,
    ) -> Result<(), BillingError> {
        let reporter = reporter.to_string();
        let usage_identifier = usage_identifier.to_string();
        let lease_token = lease_token.to_string();
        self.call(move |connection| {
            let updated = connection
                .execute(
                    "UPDATE usage_reports
                        SET dispatch_started_at_ms = ?1, updated_at_ms = ?1
                      WHERE reporter = ?2 AND usage_identifier = ?3 AND lease_token = ?4",
                    params![now_ms, reporter, usage_identifier, lease_token],
                )
                .map_err(|_| BillingError::Storage("stamp usage dispatch"))?;
            if updated == 0 {
                return Err(BillingError::LeaseLost);
            }
            Ok(())
        })
        .await
    }

    async fn record_usage_outcome(
        &self,
        reporter: &str,
        usage_identifier: &str,
        lease_token: &str,
        outcome: UsageOutcome,
        now_ms: i64,
    ) -> Result<(), BillingError> {
        let reporter = reporter.to_string();
        let usage_identifier = usage_identifier.to_string();
        let lease_token = lease_token.to_string();
        self.call(move |connection| {
            let updated = match &outcome {
                UsageOutcome::Reported(receipt) => connection.execute(
                    "UPDATE usage_reports
                        SET status = 'reported', reported_at_ms = ?1, provider_reference = ?2,
                            lease_token = NULL, lease_expires_at_ms = NULL, retry_at_ms = NULL,
                            failure_category = NULL, failure_provider_code = NULL,
                            updated_at_ms = ?3
                      WHERE reporter = ?4 AND usage_identifier = ?5 AND lease_token = ?6",
                    params![
                        receipt.reported_at_ms,
                        receipt.provider_reference,
                        now_ms,
                        reporter,
                        usage_identifier,
                        lease_token,
                    ],
                ),
                UsageOutcome::Retry {
                    retry_at_ms,
                    failure,
                } => connection.execute(
                    "UPDATE usage_reports
                        SET status = 'queued', retry_at_ms = ?1, failure_category = ?2,
                            failure_provider_code = ?3, lease_token = NULL,
                            lease_expires_at_ms = NULL, updated_at_ms = ?4
                      WHERE reporter = ?5 AND usage_identifier = ?6 AND lease_token = ?7",
                    params![
                        retry_at_ms,
                        failure.category.as_str(),
                        failure.provider_code,
                        now_ms,
                        reporter,
                        usage_identifier,
                        lease_token,
                    ],
                ),
                UsageOutcome::Terminal(failure) => connection.execute(
                    "UPDATE usage_reports
                        SET status = 'terminal', failure_category = ?1,
                            failure_provider_code = ?2, lease_token = NULL,
                            lease_expires_at_ms = NULL, updated_at_ms = ?3
                      WHERE reporter = ?4 AND usage_identifier = ?5 AND lease_token = ?6",
                    params![
                        failure.category.as_str(),
                        failure.provider_code,
                        now_ms,
                        reporter,
                        usage_identifier,
                        lease_token,
                    ],
                ),
            }
            .map_err(|_| BillingError::Storage("record usage outcome"))?;
            if updated == 0 {
                return Err(BillingError::LeaseLost);
            }
            Ok(())
        })
        .await
    }
}

/// One `payment_attempts` row, including the lease columns.
///
/// [`ProviderAttempt`] deliberately has no lease fields, because an adapter
/// has no business reading them. The store needs them, so they ride here.
struct AttemptRow {
    attempt: ProviderAttempt,
    lease_token: Option<String>,
    lease_expires_at_ms: Option<i64>,
}

impl AttemptRow {
    /// Reports whether someone else's lease is still live.
    fn lease_is_live(&self, now_ms: i64) -> bool {
        self.lease_token.is_some() && self.lease_expires_at_ms.is_some_and(|at| at > now_ms)
    }
}

/// Opens an immediate transaction, which takes the write lock up front.
fn begin_immediate(connection: &mut Connection) -> Result<rusqlite::Transaction<'_>, BillingError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| BillingError::StoreUnavailable)
}

/// Serializes a value as RFC 8785 canonical JSON.
fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, BillingError> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|error| BillingError::Canonical(error.to_string()))
}

/// Parses a stored lowercase hex digest.
fn parse_digest(value: &str) -> Result<[u8; 32], BillingError> {
    let bytes = hex::decode(value).map_err(|_| BillingError::CorruptRecord)?;
    bytes.try_into().map_err(|_| BillingError::CorruptRecord)
}

/// Mints an unguessable lease token.
///
/// Guessability matters: a lease token is what authorizes a durable
/// transition, so a predictable one would let a lost holder resume a claim
/// that was recovered away from it.
fn mint_lease_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Derives the provider idempotency key for one usage report.
///
/// Usage reporting is not a settlement attempt: it has no rail, no
/// requirement, and no generation. It gets its own derivation over the
/// reporter and the caller's deduplication identifier, under the same key
/// prefix so operators recognize it in a provider dashboard.
fn usage_idempotency_key(reporter: &str, usage_identifier: &str) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(b"sbproxy-usage-v1\0");
    material.extend_from_slice(reporter.as_bytes());
    material.push(0);
    material.extend_from_slice(usage_identifier.as_bytes());
    let digest: [u8; 32] = Sha256::digest(material.as_slice()).into();
    format!(
        "{}{}",
        crate::types::PROVIDER_IDEMPOTENCY_KEY_PREFIX,
        URL_SAFE_NO_PAD.encode(digest)
    )
}

/// Maps a unique-constraint violation onto a retryable lease conflict.
///
/// Two callers racing to create the same attempt is normal. One wins the
/// unique index and the other should look again rather than fail the request.
fn map_constraint(context: &'static str) -> impl Fn(rusqlite::Error) -> BillingError {
    move |error| match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            BillingError::LeaseHeld
        }
        _ => BillingError::Storage(context),
    }
}

/// The raw columns one `payment_intents` row is read through.
struct IntentColumns {
    intent_id: String,
    tenant_id: String,
    origin_id: String,
    route: String,
    quote_id: String,
    request_idempotency_key: String,
    protocol: String,
    settlement_rail: String,
    status: String,
    draft_jcs: String,
    draft_digest: String,
    requirement_jcs: Option<String>,
    requirement_digest: Option<String>,
    quote_token: Option<String>,
    quote_nonce: Option<String>,
    reserved_proof_digest: Option<String>,
    expires_at_ms: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

/// Reads the intent columns out of one row, in `INTENT_COLUMNS` order.
fn map_intent_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<IntentColumns> {
    Ok(IntentColumns {
        intent_id: row.get(0)?,
        tenant_id: row.get(1)?,
        origin_id: row.get(2)?,
        route: row.get(3)?,
        quote_id: row.get(4)?,
        request_idempotency_key: row.get(5)?,
        protocol: row.get(6)?,
        settlement_rail: row.get(7)?,
        status: row.get(8)?,
        draft_jcs: row.get(9)?,
        draft_digest: row.get(10)?,
        requirement_jcs: row.get(11)?,
        requirement_digest: row.get(12)?,
        quote_token: row.get(13)?,
        quote_nonce: row.get(14)?,
        reserved_proof_digest: row.get(15)?,
        expires_at_ms: row.get(16)?,
        created_at_ms: row.get(17)?,
        updated_at_ms: row.get(18)?,
    })
}

/// Loads one intent.
fn load_intent(
    connection: &Connection,
    intent_id: &str,
) -> Result<Option<IntentRecord>, BillingError> {
    let query = format!("SELECT {INTENT_COLUMNS} FROM payment_intents WHERE intent_id = ?1");
    let columns = connection
        .query_row(&query, params![intent_id], map_intent_columns)
        .optional()
        .map_err(|_| BillingError::Storage("read settlement intent"))?;

    let Some(columns) = columns else {
        return Ok(None);
    };
    let draft: PaymentRequirementDraft =
        serde_json::from_str(&columns.draft_jcs).map_err(|_| BillingError::CorruptRecord)?;
    let requirement = match columns.requirement_jcs.as_deref() {
        Some(json) => Some(
            serde_json::from_str::<PaymentRequirement>(json)
                .map_err(|_| BillingError::CorruptRecord)?,
        ),
        None => None,
    };
    let requirement_digest = match columns.requirement_digest.as_deref() {
        Some(value) => Some(parse_digest(value)?),
        None => None,
    };
    let reserved_proof_digest = match columns.reserved_proof_digest.as_deref() {
        Some(value) => Some(parse_digest(value)?),
        None => None,
    };

    Ok(Some(IntentRecord {
        protocol: PaymentProtocol::parse(&columns.protocol)?,
        settlement_rail: SettlementRail::parse(&columns.settlement_rail)?,
        status: IntentStatus::parse(&columns.status)?,
        draft_digest: parse_digest(&columns.draft_digest)?,
        intent_id: columns.intent_id,
        tenant_id: columns.tenant_id,
        origin_id: columns.origin_id,
        route: columns.route,
        quote_id: columns.quote_id,
        request_idempotency_key: columns.request_idempotency_key,
        draft,
        requirement,
        requirement_digest,
        quote_token: columns.quote_token,
        quote_nonce: columns.quote_nonce,
        reserved_proof_digest,
        expires_at_ms: columns.expires_at_ms,
        created_at_ms: columns.created_at_ms,
        updated_at_ms: columns.updated_at_ms,
    }))
}

/// Loads one attempt and its lease columns.
fn load_attempt_row(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<AttemptRow>, BillingError> {
    let query = format!("SELECT {ATTEMPT_COLUMNS} FROM payment_attempts WHERE attempt_id = ?1");
    let row = connection
        .query_row(&query, params![attempt_id], map_attempt_columns)
        .optional()
        .map_err(|_| BillingError::Storage("read payment attempt"))?;
    row.map(|row| build_attempt_row(connection, row))
        .transpose()
}

/// Loads the newest attempt for one intent and operation.
fn latest_attempt_row(
    connection: &Connection,
    intent_id: &str,
    operation: AttemptOperation,
) -> Result<Option<AttemptRow>, BillingError> {
    let query = format!(
        "SELECT {ATTEMPT_COLUMNS} FROM payment_attempts
          WHERE intent_id = ?1 AND operation = ?2
          ORDER BY attempt_generation DESC LIMIT 1"
    );
    let row = connection
        .query_row(
            &query,
            params![intent_id, operation.as_str()],
            map_attempt_columns,
        )
        .optional()
        .map_err(|_| BillingError::Storage("read latest payment attempt"))?;
    row.map(|row| build_attempt_row(connection, row))
        .transpose()
}

/// The raw columns one `payment_attempts` row is read through.
struct AttemptColumns {
    attempt_id: String,
    intent_id: String,
    tenant_id: String,
    rail: String,
    operation: String,
    attempt_generation: i64,
    provider_idempotency_key: String,
    provider_handle: Option<String>,
    lease_token: Option<String>,
    lease_expires_at_ms: Option<i64>,
    dispatch_started_at_ms: Option<i64>,
    response_recorded_at_ms: Option<i64>,
    status: String,
}

/// Reads the attempt columns out of one row, in `ATTEMPT_COLUMNS` order.
fn map_attempt_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttemptColumns> {
    Ok(AttemptColumns {
        attempt_id: row.get(0)?,
        intent_id: row.get(1)?,
        tenant_id: row.get(2)?,
        rail: row.get(3)?,
        operation: row.get(4)?,
        attempt_generation: row.get(5)?,
        provider_idempotency_key: row.get(6)?,
        provider_handle: row.get(7)?,
        lease_token: row.get(8)?,
        lease_expires_at_ms: row.get(9)?,
        dispatch_started_at_ms: row.get(10)?,
        response_recorded_at_ms: row.get(11)?,
        status: row.get(12)?,
    })
}

/// Turns raw attempt columns into a typed row, attaching the requirement.
fn build_attempt_row(
    connection: &Connection,
    columns: AttemptColumns,
) -> Result<AttemptRow, BillingError> {
    let requirement: Option<String> = connection
        .query_row(
            "SELECT requirement_jcs FROM payment_intents WHERE intent_id = ?1",
            params![columns.intent_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| BillingError::Storage("read attempt requirement"))?
        .flatten();
    let requirement = match requirement.as_deref() {
        Some(json) => Some(
            serde_json::from_str::<PaymentRequirement>(json)
                .map_err(|_| BillingError::CorruptRecord)?,
        ),
        None => None,
    };

    Ok(AttemptRow {
        attempt: ProviderAttempt {
            rail: SettlementRail::parse(&columns.rail)?,
            operation: AttemptOperation::parse(&columns.operation)?,
            attempt_generation: u32::try_from(columns.attempt_generation)
                .map_err(|_| BillingError::CorruptRecord)?,
            status: AttemptStatus::parse(&columns.status)?,
            attempt_id: columns.attempt_id,
            intent_id: columns.intent_id,
            tenant_id: columns.tenant_id,
            provider_idempotency_key: columns.provider_idempotency_key,
            provider_handle: columns.provider_handle,
            dispatch_started_at_ms: columns.dispatch_started_at_ms,
            response_recorded_at_ms: columns.response_recorded_at_ms,
            requirement,
        },
        lease_token: columns.lease_token,
        lease_expires_at_ms: columns.lease_expires_at_ms,
    })
}

/// Loads the committed receipt for one intent, whatever its state.
fn load_receipt(
    connection: &Connection,
    intent_id: &str,
) -> Result<Option<SettlementReceipt>, BillingError> {
    let row = connection
        .query_row(
            "SELECT receipt_key, intent_id, rail, method, provider_reference, settled_at_ms
               FROM payment_receipts WHERE intent_id = ?1",
            params![intent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| BillingError::Storage("read settlement receipt"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let receipt = SettlementReceipt {
        receipt_key: row.0,
        intent_id: row.1,
        rail: SettlementRail::parse(&row.2)?,
        method: row.3,
        provider_reference: row.4,
        settled_at_ms: row.5,
    };
    // A stored receipt whose key does not match its own contents is a
    // corrupted row, not an authorization.
    receipt
        .validate()
        .map_err(|_| BillingError::CorruptRecord)?;
    Ok(Some(receipt))
}

/// Commits the receipt, the attempt success, and the intent success together.
fn commit_success(
    transaction: &rusqlite::Transaction<'_>,
    row: &AttemptRow,
    receipt: &SettlementReceipt,
    now_ms: i64,
) -> Result<(), BillingError> {
    let existing = load_receipt(transaction, &row.attempt.intent_id)?;
    if let Some(existing) = existing {
        // Two winners of one race must not produce two receipts. An identical
        // receipt is the same fact recorded twice; a different one means the
        // caller settled something this intent did not agree to.
        if existing.receipt_key != receipt.receipt_key {
            return Err(BillingError::InvalidStateTransition {
                from: IntentStatus::Succeeded,
                to: IntentStatus::Succeeded,
            });
        }
    } else {
        transaction
            .execute(
                "INSERT INTO payment_receipts
                    (receipt_key, intent_id, attempt_id, rail, method, provider_reference,
                     settled_at_ms, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    receipt.receipt_key,
                    receipt.intent_id,
                    row.attempt.attempt_id,
                    receipt.rail.as_str(),
                    receipt.method,
                    receipt.provider_reference,
                    receipt.settled_at_ms,
                    now_ms,
                ],
            )
            .map_err(|_| BillingError::Storage("insert settlement receipt"))?;
    }

    transaction
        .execute(
            "UPDATE payment_attempts
                SET status = ?1, response_recorded_at_ms = COALESCE(response_recorded_at_ms, ?2),
                    lease_token = NULL, lease_expires_at_ms = NULL, failure_category = NULL,
                    failure_provider_code = NULL, updated_at_ms = ?2
              WHERE attempt_id = ?3",
            params![
                AttemptStatus::Succeeded.as_str(),
                now_ms,
                row.attempt.attempt_id,
            ],
        )
        .map_err(|_| BillingError::Storage("record attempt success"))?;
    transaction
        .execute(
            "UPDATE payment_intents
                SET status = ?1, failure_category = NULL, failure_provider_code = NULL,
                    updated_at_ms = ?2
              WHERE intent_id = ?3",
            params![
                IntentStatus::Succeeded.as_str(),
                now_ms,
                row.attempt.intent_id,
            ],
        )
        .map_err(|_| BillingError::Storage("record intent success"))?;
    record_provider_event(
        transaction,
        &row.attempt.attempt_id,
        &row.attempt.intent_id,
        row.attempt.rail,
        row.attempt.operation,
        "succeeded",
        None,
        now_ms,
    )?;
    purge_envelope(transaction, &row.attempt.attempt_id)?;
    Ok(())
}

/// Writes a closing status onto one leased attempt and releases the lease.
fn close_attempt(
    transaction: &rusqlite::Transaction<'_>,
    attempt_id: &str,
    lease_token: &str,
    status: AttemptStatus,
    failure: &SafeFailure,
    response_recorded_at_ms: Option<i64>,
    now_ms: i64,
) -> Result<(), BillingError> {
    let updated = transaction
        .execute(
            "UPDATE payment_attempts
                SET status = ?1, failure_category = ?2, failure_provider_code = ?3,
                    failure_retryable = ?4,
                    response_recorded_at_ms = COALESCE(?5, response_recorded_at_ms),
                    lease_token = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?6
              WHERE attempt_id = ?7 AND lease_token = ?8",
            params![
                status.as_str(),
                failure.category.as_str(),
                failure.provider_code,
                i64::from(failure.retryable),
                response_recorded_at_ms,
                now_ms,
                attempt_id,
                lease_token,
            ],
        )
        .map_err(|_| BillingError::Storage("close payment attempt"))?;
    if updated == 0 {
        return Err(BillingError::LeaseLost);
    }
    Ok(())
}

/// Moves an intent to a new status, never out of a final one.
fn set_intent_status(
    transaction: &rusqlite::Transaction<'_>,
    intent_id: &str,
    status: IntentStatus,
    now_ms: i64,
) -> Result<(), BillingError> {
    transaction
        .execute(
            "UPDATE payment_intents
                SET status = ?1, updated_at_ms = ?2
              WHERE intent_id = ?3 AND status NOT IN (?4, ?5)",
            params![
                status.as_str(),
                now_ms,
                intent_id,
                IntentStatus::Succeeded.as_str(),
                IntentStatus::Terminal.as_str(),
            ],
        )
        .map_err(|_| BillingError::Storage("update intent status"))?;
    Ok(())
}

/// Moves an intent to a failing status and records the redacted category.
fn set_intent_failure(
    transaction: &rusqlite::Transaction<'_>,
    intent_id: &str,
    status: IntentStatus,
    failure: &SafeFailure,
    now_ms: i64,
) -> Result<(), BillingError> {
    transaction
        .execute(
            "UPDATE payment_intents
                SET status = ?1, failure_category = ?2, failure_provider_code = ?3,
                    updated_at_ms = ?4
              WHERE intent_id = ?5 AND status NOT IN (?6, ?7)",
            params![
                status.as_str(),
                failure.category.as_str(),
                failure.provider_code,
                now_ms,
                intent_id,
                IntentStatus::Succeeded.as_str(),
                IntentStatus::Terminal.as_str(),
            ],
        )
        .map_err(|_| BillingError::Storage("update intent failure"))?;
    Ok(())
}

/// Appends one redacted transition to the provider event trail.
#[allow(clippy::too_many_arguments)] // An audit row is a wide row by nature.
fn record_provider_event(
    connection: &Connection,
    attempt_id: &str,
    intent_id: &str,
    rail: SettlementRail,
    operation: AttemptOperation,
    phase: &str,
    failure: Option<&SafeFailure>,
    now_ms: i64,
) -> Result<(), BillingError> {
    connection
        .execute(
            "INSERT INTO provider_events
                (attempt_id, intent_id, rail, operation, phase, failure_category,
                 failure_provider_code, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                attempt_id,
                intent_id,
                rail.as_str(),
                operation.as_str(),
                phase,
                failure.map(|failure| failure.category.as_str()),
                failure.and_then(|failure| failure.provider_code.clone()),
                now_ms,
            ],
        )
        .map_err(|_| BillingError::Storage("write provider event"))?;
    Ok(())
}

/// Deletes the recovery envelope for one attempt.
fn purge_envelope(connection: &Connection, attempt_id: &str) -> Result<(), BillingError> {
    connection
        .execute(
            "DELETE FROM provider_recovery_envelopes WHERE attempt_id = ?1",
            params![attempt_id],
        )
        .map_err(|_| BillingError::Storage("purge recovery envelope"))?;
    Ok(())
}
