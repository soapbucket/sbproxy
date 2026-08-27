//! One embedded store for the subsystems that need to remember something,
//! split by the only question that matters at the call site: does a restart
//! lose it?
//!
//! # Why this exists
//!
//! Three subsystems arrived at the same problem within one epic. The agent
//! registry has to keep a verified catalog and a registration queue. The
//! outbound notifier has to keep webhook subscriptions and a deadletter
//! queue. The event ingest reconciler has to keep a per-rail watermark. Each
//! one shipped elsewhere with a Postgres table behind it, and each one would
//! have arrived here as its own bespoke redb file, its own table names, its
//! own revision counter, and its own version of the "one handle per file per
//! process" rule that a config reload breaks when you get it wrong.
//!
//! `sbproxy_keystore::embedded::EmbeddedKeyStore` and the Cedar
//! `EmbeddedPolicyStore` had already written that code twice, near
//! identically. This module is the third copy declining to exist.
//!
//! # The state of the art this follows
//!
//! Embedded-first is where API gateways landed. Kong's data planes cache
//! their whole configuration in an embedded LMDB database (`dbless.lmdb`)
//! rather than in a shared database, and Kong's own engineering writeup for
//! that change gives ACID transactions and restart time as the reasons it
//! replaced a JSON file cache. APISIX goes further in its file-driven
//! standalone mode, dropping etcd entirely so a data plane has no external
//! dependency at all, and pays for it by refusing the Admin API in that mode.
//!
//! This module takes Kong's half of that trade rather than APISIX's: an
//! embedded ACID store is the default, and the admin API keeps working,
//! because the mutable state lives in the embedded store instead of in a
//! cluster-wide database. Nothing here needs Postgres, and nothing here
//! needs a sidecar.
//!
//! # Two traits, because durability is a decision, not a detail
//!
//! [`PersistentKv`] is durable. What a caller writes is on disk in an ACID
//! transaction before the call returns, and it is there after a restart.
//!
//! [`EphemeralKv`] is deliberately not. It is in memory, it is bounded, its
//! entries carry a TTL, and a restart empties it. That is a feature for the
//! things that want it: a replay-dedup window, an in-flight attempt counter,
//! a short-lived nonce cache. Storing those durably is worse than useless,
//! because a restart should forget them.
//!
//! Splitting them means the call site says which it wanted. A single
//! `KvStore` trait with a `ttl` argument does not: every caller then has to
//! be read to find out whether its data survives, and the answer is a
//! runtime property of an argument rather than a compile-time property of a
//! type. [`crate::storage::KVStore`] is
//! that other shape, and it stays what it is: the low-level, sync,
//! byte-keyed backend surface behind the response cache and the rate
//! limiters, with `put_with_ttl` returning "not supported" on the backends
//! that cannot do it. This pair is the opposite: async, namespaced,
//! revision-carrying, and total, with no method that can answer "not
//! supported".
//!
//! # Namespaces, not tables
//!
//! redb's `TableDefinition::new` takes a `&'static str`, so a table per
//! logical collection means a `const` per collection and no runtime
//! composition. Instead one table holds every record and the key is
//! `<namespace>\x1f<key>`. [`KvNamespace`] validates its charset at
//! construction and the unit separator is not in it, so the first separator
//! always ends the namespace and no key can reach out of the namespace it
//! was written under. `namespace_isolation_survives_a_hostile_key` pins
//! that.
//!
//! # Revisions
//!
//! One monotonic counter per store, bumped inside the same write transaction
//! as every mutation, exactly as the keystore and the Cedar store do. Each
//! record is stamped with the counter value at its last write, which is what
//! makes [`PersistentKv::put_if_revision`] a real compare-and-swap: an
//! approval that read a pending registration and writes back an approved one
//! cannot clobber a rejection that landed in between.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

#[cfg(feature = "redb-store")]
use redb::{Database, ReadableTable, TableDefinition};

use super::embedded_metrics::{outcome_label, record_kv_op, record_kv_op_count};

/// Byte that separates a namespace from a key inside the single redb table.
///
/// ASCII unit separator. [`KvNamespace::new`] refuses it, and every other
/// byte outside `[a-z0-9_]`, so a namespace can never contain one and the
/// first occurrence in a composed key is always the namespace terminator.
const NS_SEPARATOR: char = '\u{1f}';

/// Longest key a caller may address, in bytes.
///
/// A cap rather than no cap because keys come from registration slugs,
/// subscription ids, and rail names, and at least the first of those is
/// derived from a request body. redb would happily store a megabyte of key;
/// the request that supplied it should be refused instead.
pub const MAX_KEY_BYTES: usize = 512;

/// Longest namespace name, in bytes. Namespaces are compile-time constants
/// in this workspace, so the cap only exists to keep the composed key bound
/// stated in one place, and it stays private for that reason: a caller has
/// nothing to do with the number.
const MAX_NAMESPACE_BYTES: usize = 64;

/// A validated collection name inside an embedded store.
///
/// Construct one per logical collection and hold it in a `const`-like static
/// or a struct field; construction validates, so a namespace that reached a
/// call site is a namespace the store will accept.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KvNamespace(String);

impl KvNamespace {
    /// Validate and wrap a namespace name.
    ///
    /// Accepts `[a-z0-9_]{1,64}`. Everything else is refused, including the
    /// separator this module composes keys with, which is what makes the
    /// namespace boundary structural rather than conventional.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_NAMESPACE_BYTES {
            bail!(
                "kv namespace must be 1..={MAX_NAMESPACE_BYTES} bytes, got {}",
                name.len()
            );
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            bail!("kv namespace {name:?} must match [a-z0-9_]+");
        }
        Ok(Self(name))
    }

    /// The namespace name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compose the stored key for `key` inside this namespace.
    fn compose(&self, key: &str) -> Result<String> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            bail!(
                "kv key must be 1..={MAX_KEY_BYTES} bytes, got {}",
                key.len()
            );
        }
        Ok(format!("{}{NS_SEPARATOR}{key}", self.0))
    }

    /// Inclusive lower bound of this namespace's key range.
    fn range_start(&self) -> String {
        format!("{}{NS_SEPARATOR}", self.0)
    }

    /// Exclusive upper bound of this namespace's key range.
    ///
    /// The separator plus one. Every composed key in this namespace sorts
    /// below it, and the next namespace's keys sort above it, because a
    /// namespace name cannot contain the separator.
    fn range_end(&self) -> String {
        format!("{}{}", self.0, (NS_SEPARATOR as u8 + 1) as char)
    }

    /// Strip the namespace prefix from a stored key.
    fn strip<'a>(&self, stored: &'a str) -> Option<&'a str> {
        stored
            .strip_prefix(self.0.as_str())
            .and_then(|rest| rest.strip_prefix(NS_SEPARATOR))
    }
}

/// One record read out of a [`PersistentKv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvEntry {
    /// Store revision at which this record was last written. Monotonic
    /// across the whole store, so it doubles as the compare-and-swap token
    /// for [`PersistentKv::put_if_revision`].
    pub revision: u64,
    /// Stored bytes, exactly as written.
    pub value: Vec<u8>,
}

/// Outcome of a compare-and-swap write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// The write landed. Carries the new store revision the record now
    /// carries.
    Applied {
        /// Store revision stamped on the record just written.
        revision: u64,
    },
    /// Someone else wrote this key since the caller read it. Carries the
    /// revision the record actually holds, so the caller can re-read and
    /// retry without a second round trip to find out.
    Conflict {
        /// Revision the stored record carries right now.
        actual: u64,
    },
    /// No record under that key. A caller that meant to create rather than
    /// update wants [`PersistentKv::insert_if_absent`].
    NotFound,
}

/// A durable, namespaced key-value store.
///
/// Every write is an ACID transaction that has committed before the call
/// returns, so a record a caller has written is a record a restart keeps.
/// Implemented by [`EmbeddedKvStore`] over redb.
#[async_trait]
pub trait PersistentKv: Send + Sync {
    /// Stable, low-cardinality name this store is counted under on
    /// `sbproxy_embedded_store_operations_total`. Chosen by the subsystem
    /// that opens the store, never derived from a path or a request.
    fn store_name(&self) -> &'static str;

    /// Read one record.
    async fn get(&self, namespace: &KvNamespace, key: &str) -> Result<Option<KvEntry>>;

    /// Read every record in a namespace, in key order.
    ///
    /// The whole namespace, because every caller in this workspace wants the
    /// whole collection (a subscription set, a catalog, a queue page) and a
    /// cursor nobody uses is a cursor nobody tests. A namespace that grows
    /// past what a caller wants to hold at once needs pagination added
    /// deliberately, with the bound the caller can actually enforce.
    async fn list(&self, namespace: &KvNamespace) -> Result<Vec<(String, KvEntry)>>;

    /// Insert or replace a record unconditionally. Returns the store
    /// revision stamped on it.
    async fn put(&self, namespace: &KvNamespace, key: &str, value: &[u8]) -> Result<u64>;

    /// Insert a record only when the key is absent.
    ///
    /// Returns the new revision when it landed, `None` when a record was
    /// already there and nothing was written. The check and the write are
    /// one transaction, so two concurrent registrations of the same slug
    /// cannot both see an empty slot.
    async fn insert_if_absent(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
    ) -> Result<Option<u64>>;

    /// Replace a record only when it still carries `expected_revision`.
    async fn put_if_revision(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
        expected_revision: u64,
    ) -> Result<CasOutcome>;

    /// Remove a record. Removing an absent key is not an error, and still
    /// bumps the store revision, matching `EmbeddedKeyStore::delete_key`.
    async fn delete(&self, namespace: &KvNamespace, key: &str) -> Result<u64>;

    /// The store-wide monotonic revision counter.
    async fn revision(&self) -> Result<u64>;
}

/// A bounded, in-memory key-value store whose contents a restart discards.
///
/// The counterpart to [`PersistentKv`], and the right choice for state whose
/// meaning is tied to this process's lifetime: replay-dedup windows,
/// in-flight attempt counters, short-lived nonce caches. Implemented by
/// [`MemoryKv`].
#[async_trait]
pub trait EphemeralKv: Send + Sync {
    /// Stable, low-cardinality name this store is counted under.
    fn store_name(&self) -> &'static str;

    /// Read a value, unless it has expired. An expired entry reads as
    /// absent whether or not a sweep has reclaimed it yet.
    async fn get(&self, namespace: &KvNamespace, key: &str) -> Result<Option<Vec<u8>>>;

    /// Write a value that stops being visible after `ttl`.
    ///
    /// Returns `false` when the store was at its entry cap and the write was
    /// refused rather than evicting something already there. A refusal is
    /// counted under `op="put",outcome="rejected"`, so a store running at
    /// its cap is visible rather than silently lossy.
    async fn put_with_ttl(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool>;

    /// Remove a value. Removing an absent key is not an error.
    async fn remove(&self, namespace: &KvNamespace, key: &str) -> Result<()>;

    /// How many unexpired entries the store currently holds.
    async fn len(&self) -> usize;

    /// Whether the store holds no unexpired entries.
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

// --- redb-backed PersistentKv ---

#[cfg(feature = "redb-store")]
const RECORDS: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("records");
#[cfg(feature = "redb-store")]
const META: TableDefinition<'static, &str, u64> = TableDefinition::new("meta");
#[cfg(feature = "redb-store")]
const REVISION_KEY: &str = "revision";

/// Stores this process currently holds, keyed by resolved database path.
///
/// See [`EmbeddedKvStore::open_shared`] for why one handle per file per
/// process is a requirement rather than an optimization. Mirrors the
/// registry `sbproxy_keystore::embedded` and the Cedar policy store each
/// carry, which is the third time it has been written and the reason this
/// module exists.
#[cfg(feature = "redb-store")]
static OPEN_STORES: LazyLock<Mutex<HashMap<PathBuf, Weak<EmbeddedKvStore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve `path` to the key the registry compares on, so two spellings of
/// one file do not look like two files and re-open the same database.
///
/// The database file may not exist yet on a first open, in which case
/// `canonicalize` on the file itself fails and the parent directory carries
/// the resolution. Falling back to the path as written is correct but
/// weaker: a missed match only costs the "already open" error the caller
/// would have hit anyway.
#[cfg(feature = "redb-store")]
fn registry_key(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    match (parent.and_then(|p| p.canonicalize().ok()), path.file_name()) {
        (Some(dir), Some(name)) => dir.join(name),
        _ => std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// A redb-backed [`PersistentKv`]. The database file is created at the given
/// path.
#[cfg(feature = "redb-store")]
pub struct EmbeddedKvStore {
    db: Database,
    store_name: &'static str,
}

#[cfg(feature = "redb-store")]
impl EmbeddedKvStore {
    /// Open (or create) the store at `path` under the metric label
    /// `store_name`.
    ///
    /// The file is pre-created owner-only before redb is handed the path.
    /// redb calls `File::create` itself, which asks for `0o666` and lets the
    /// umask decide, so a database holding registration secrets' hashes and
    /// webhook signing-key references would land at `0o644` under the
    /// near-universal `0o022`. redb opens an existing file rather than
    /// replacing it, so creating it at `0o600` first is enough. Same order
    /// `EmbeddedKeyStore::open` uses, and the reason
    /// `scripts/check-durable-file-modes.sh` exists.
    pub fn open(path: impl AsRef<Path>, store_name: &'static str) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            sbproxy_util::secure_fs::create_dir_all_owner_only(parent)
                .with_context(|| format!("create store directory {}", parent.display()))?;
        }
        sbproxy_util::secure_fs::ensure_file_owner_only(path)
            .with_context(|| format!("create embedded store at {}", path.display()))?;
        let db = Database::create(path)
            .with_context(|| format!("open embedded store at {}", path.display()))?;
        let write_txn = db.begin_write().context("begin init transaction")?;
        {
            write_txn
                .open_table(RECORDS)
                .context("open records table")?;
            write_txn.open_table(META).context("open meta table")?;
        }
        write_txn.commit().context("commit init transaction")?;
        Ok(Self { db, store_name })
    }

    /// Open the store at `path`, reusing the handle this process already
    /// holds for that file when there is one.
    ///
    /// redb locks the database file exclusively, so a second [`Self::open`]
    /// of a path this process already holds fails with `Database already
    /// open. Cannot acquire lock.` A config reload builds a candidate
    /// generation of every subsystem while the live generation still owns
    /// its files, so an unconditional re-open makes every reload of a config
    /// that names an embedded store fail and leaves the node on the old
    /// config. One redb handle per file per process is the invariant, and it
    /// belongs to the type that owns the handle rather than to each caller
    /// that might open one.
    ///
    /// Sharing is safe: `Database` is `Send + Sync` and every mutation runs
    /// in its own ACID transaction, so two generations pointed at one file
    /// are two views of one system of record. The registry holds [`Weak`]
    /// references, so the file closes once the last generation referencing
    /// it is dropped.
    ///
    /// The `store_name` of the first opener wins, because the metric label
    /// belongs to the file rather than to whichever generation reopened it.
    pub fn open_shared(path: impl AsRef<Path>, store_name: &'static str) -> Result<Arc<Self>> {
        let path = path.as_ref();
        let key = registry_key(path);
        let mut live = OPEN_STORES.lock();
        if let Some(existing) = live.get(&key).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        let store = Arc::new(Self::open(path, store_name)?);
        // Forget stores nobody holds, so a long-lived process that reloads
        // through a series of paths does not accumulate dead entries.
        live.retain(|_, handle| handle.strong_count() > 0);
        live.insert(key, Arc::downgrade(&store));
        Ok(store)
    }

    /// Bump the revision counter inside an already-open write transaction
    /// and return the new value.
    fn bump_revision(txn: &redb::WriteTransaction) -> Result<u64> {
        let mut meta = txn.open_table(META).context("open meta table")?;
        let current = meta
            .get(REVISION_KEY)
            .context("read revision")?
            .map(|g| g.value())
            .unwrap_or(0);
        let next = current + 1;
        meta.insert(REVISION_KEY, next).context("write revision")?;
        Ok(next)
    }

    /// Frame a record as `<8-byte big-endian revision><value>`.
    fn frame(revision: u64, value: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(8 + value.len());
        framed.extend_from_slice(&revision.to_be_bytes());
        framed.extend_from_slice(value);
        framed
    }

    /// Unframe a stored record.
    ///
    /// A short record means the file was written by something other than
    /// this module, which is an error rather than an empty value: silently
    /// returning `revision = 0` would make every compare-and-swap against
    /// that record succeed.
    fn unframe(stored: &[u8]) -> Result<KvEntry> {
        if stored.len() < 8 {
            bail!(
                "embedded store record is {} bytes, shorter than the 8-byte revision stamp",
                stored.len()
            );
        }
        let (head, value) = stored.split_at(8);
        let mut revision_bytes = [0u8; 8];
        revision_bytes.copy_from_slice(head);
        Ok(KvEntry {
            revision: u64::from_be_bytes(revision_bytes),
            value: value.to_vec(),
        })
    }
}

#[cfg(feature = "redb-store")]
#[async_trait]
impl PersistentKv for EmbeddedKvStore {
    fn store_name(&self) -> &'static str {
        self.store_name
    }

    async fn get(&self, namespace: &KvNamespace, key: &str) -> Result<Option<KvEntry>> {
        let outcome = (|| {
            let composed = namespace.compose(key)?;
            let read = self.db.begin_read().context("begin read")?;
            let table = read.open_table(RECORDS).context("open records table")?;
            match table.get(composed.as_str()).context("get record")? {
                Some(guard) => Ok(Some(Self::unframe(guard.value())?)),
                None => Ok(None),
            }
        })();
        record_kv_op(self.store_name, "get", outcome_label(&outcome));
        outcome
    }

    async fn list(&self, namespace: &KvNamespace) -> Result<Vec<(String, KvEntry)>> {
        let outcome = (|| {
            let read = self.db.begin_read().context("begin read")?;
            let table = read.open_table(RECORDS).context("open records table")?;
            let start = namespace.range_start();
            let end = namespace.range_end();
            let mut out = Vec::new();
            for entry in table
                .range(start.as_str()..end.as_str())
                .context("range records")?
            {
                let (stored_key, stored_value) = entry.context("read record entry")?;
                let Some(key) = namespace.strip(stored_key.value()) else {
                    // Unreachable while the separator stays outside the
                    // namespace charset, and cheaper to skip than to fail a
                    // whole listing on one unexpected row.
                    continue;
                };
                out.push((key.to_string(), Self::unframe(stored_value.value())?));
            }
            Ok(out)
        })();
        record_kv_op(self.store_name, "list", outcome_label(&outcome));
        outcome
    }

    async fn put(&self, namespace: &KvNamespace, key: &str, value: &[u8]) -> Result<u64> {
        let outcome = (|| {
            let composed = namespace.compose(key)?;
            let txn = self.db.begin_write().context("begin write")?;
            let revision = Self::bump_revision(&txn)?;
            {
                let mut table = txn.open_table(RECORDS).context("open records table")?;
                table
                    .insert(composed.as_str(), Self::frame(revision, value).as_slice())
                    .context("insert record")?;
            }
            txn.commit().context("commit put")?;
            Ok(revision)
        })();
        record_kv_op(self.store_name, "put", outcome_label(&outcome));
        outcome
    }

    async fn insert_if_absent(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
    ) -> Result<Option<u64>> {
        let outcome = (|| {
            let composed = namespace.compose(key)?;
            let txn = self.db.begin_write().context("begin insert-if-absent")?;
            let revision = Self::bump_revision(&txn)?;
            let landed = {
                let mut table = txn.open_table(RECORDS).context("open records table")?;
                if table
                    .get(composed.as_str())
                    .context("get record for insert")?
                    .is_some()
                {
                    None
                } else {
                    table
                        .insert(composed.as_str(), Self::frame(revision, value).as_slice())
                        .context("insert record")?;
                    Some(revision)
                }
            };
            txn.commit().context("commit insert-if-absent")?;
            Ok(landed)
        })();
        record_kv_op(self.store_name, "insert", outcome_label(&outcome));
        outcome
    }

    async fn put_if_revision(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
        expected_revision: u64,
    ) -> Result<CasOutcome> {
        let outcome = (|| {
            let composed = namespace.compose(key)?;
            let txn = self.db.begin_write().context("begin CAS")?;
            let revision = Self::bump_revision(&txn)?;
            let result = {
                let mut table = txn.open_table(RECORDS).context("open records table")?;
                // The read guard borrows `table` immutably, so it has to be
                // owned and dropped in its own scope before the insert below
                // can take a mutable borrow.
                let current: Option<KvEntry> = {
                    let guard = table.get(composed.as_str()).context("get record for CAS")?;
                    match guard {
                        Some(found) => Some(Self::unframe(found.value())?),
                        None => None,
                    }
                };
                match current {
                    None => CasOutcome::NotFound,
                    Some(current) if current.revision != expected_revision => {
                        CasOutcome::Conflict {
                            actual: current.revision,
                        }
                    }
                    Some(_) => {
                        table
                            .insert(composed.as_str(), Self::frame(revision, value).as_slice())
                            .context("replace record")?;
                        CasOutcome::Applied { revision }
                    }
                }
            };
            txn.commit().context("commit CAS")?;
            Ok(result)
        })();
        record_kv_op(self.store_name, "cas", outcome_label(&outcome));
        outcome
    }

    async fn delete(&self, namespace: &KvNamespace, key: &str) -> Result<u64> {
        let outcome = (|| {
            let composed = namespace.compose(key)?;
            let txn = self.db.begin_write().context("begin delete")?;
            let revision = Self::bump_revision(&txn)?;
            {
                let mut table = txn.open_table(RECORDS).context("open records table")?;
                table.remove(composed.as_str()).context("remove record")?;
            }
            txn.commit().context("commit delete")?;
            Ok(revision)
        })();
        record_kv_op(self.store_name, "delete", outcome_label(&outcome));
        outcome
    }

    async fn revision(&self) -> Result<u64> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(META).context("open meta table")?;
        Ok(table
            .get(REVISION_KEY)
            .context("read revision")?
            .map(|g| g.value())
            .unwrap_or(0))
    }
}

// --- in-memory EphemeralKv ---

/// Default ceiling on entries a [`MemoryKv`] holds.
///
/// A cap rather than no cap because the callers are dedup windows fed by
/// request-derived keys, and an unbounded map behind one is a memory
/// exhaustion primitive handed to whoever can make the requests. Chosen to
/// be comfortably above a busy replay window and small enough that the worst
/// case is measured in megabytes. Private because [`MemoryKv::new`] already
/// applies it and [`MemoryKv::with_capacity`] is how a caller disagrees.
const DEFAULT_EPHEMERAL_MAX_ENTRIES: usize = 65_536;

struct EphemeralEntry {
    value: Vec<u8>,
    expires_at: Instant,
}

/// An in-memory, TTL-bearing [`EphemeralKv`].
///
/// Expiry is lazy on read plus a bounded sweep when a write finds the store
/// at its cap, which keeps the common path a single map lookup and avoids a
/// background task whose only job is to delete things nobody has asked for.
pub struct MemoryKv {
    entries: Mutex<HashMap<String, EphemeralEntry>>,
    max_entries: usize,
    store_name: &'static str,
}

impl MemoryKv {
    /// Build a store under the metric label `store_name`, holding at most
    /// 65,536 entries. Use [`MemoryKv::with_capacity`] for a different cap.
    pub fn new(store_name: &'static str) -> Self {
        Self::with_capacity(store_name, DEFAULT_EPHEMERAL_MAX_ENTRIES)
    }

    /// Build a store with an explicit entry cap.
    pub fn with_capacity(store_name: &'static str, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
            store_name,
        }
    }

    /// Drop every expired entry. Returns how many went.
    fn sweep(entries: &mut HashMap<String, EphemeralEntry>, now: Instant) -> usize {
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        before - entries.len()
    }
}

#[async_trait]
impl EphemeralKv for MemoryKv {
    fn store_name(&self) -> &'static str {
        self.store_name
    }

    async fn get(&self, namespace: &KvNamespace, key: &str) -> Result<Option<Vec<u8>>> {
        let composed = namespace.compose(key)?;
        let now = Instant::now();
        let entries = self.entries.lock();
        let hit = entries
            .get(&composed)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.value.clone());
        drop(entries);
        record_kv_op(self.store_name, "get", "ok");
        Ok(hit)
    }

    async fn put_with_ttl(
        &self,
        namespace: &KvNamespace,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool> {
        let composed = namespace.compose(key)?;
        let now = Instant::now();
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        let mut entries = self.entries.lock();
        let mut evicted = 0;
        if entries.len() >= self.max_entries && !entries.contains_key(&composed) {
            evicted = Self::sweep(&mut entries, now);
        }
        let accepted = if entries.len() >= self.max_entries && !entries.contains_key(&composed) {
            false
        } else {
            entries.insert(
                composed,
                EphemeralEntry {
                    value: value.to_vec(),
                    expires_at,
                },
            );
            true
        };
        drop(entries);
        if evicted > 0 {
            record_kv_op_count(self.store_name, "evict", "ok", evicted as u64);
        }
        if accepted {
            record_kv_op(self.store_name, "put", "ok");
        } else {
            record_kv_op(self.store_name, "put", "rejected");
        }
        Ok(accepted)
    }

    async fn remove(&self, namespace: &KvNamespace, key: &str) -> Result<()> {
        let composed = namespace.compose(key)?;
        self.entries.lock().remove(&composed);
        record_kv_op(self.store_name, "delete", "ok");
        Ok(())
    }

    async fn len(&self) -> usize {
        let now = Instant::now();
        self.entries
            .lock()
            .values()
            .filter(|entry| entry.expires_at > now)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ns(name: &str) -> KvNamespace {
        KvNamespace::new(name).expect("namespace")
    }

    #[cfg(feature = "redb-store")]
    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!(
            "{}/sbproxy_embedded_kv_test_{}_{}_{:x}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n,
            nanos
        )
    }

    #[test]
    fn namespace_refuses_anything_that_could_forge_a_boundary() {
        assert!(KvNamespace::new("agent_registry").is_ok());
        assert!(KvNamespace::new("").is_err());
        assert!(KvNamespace::new("Agent").is_err(), "uppercase");
        assert!(KvNamespace::new("agent-registry").is_err(), "hyphen");
        assert!(
            KvNamespace::new(format!("a{NS_SEPARATOR}b")).is_err(),
            "the separator itself must never be a namespace byte"
        );
        assert!(KvNamespace::new("x".repeat(MAX_NAMESPACE_BYTES + 1)).is_err());
    }

    /// The namespace boundary is the store's whole cross-tenant story, and
    /// it is structural rather than conventional: the separator is outside
    /// the namespace charset, so the first one always terminates the
    /// namespace and a key cannot reach out of the namespace it was written
    /// under, no matter what bytes it carries.
    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn namespace_isolation_survives_a_hostile_key() {
        let path = temp_path();
        let store = EmbeddedKvStore::open(&path, "test").expect("open");
        let alpha = ns("alpha");
        let beta = ns("beta");

        store.put(&alpha, "shared", b"alpha-value").await.unwrap();
        store.put(&beta, "shared", b"beta-value").await.unwrap();

        // A key that spells out another namespace stays inside its own.
        let hostile = format!("{NS_SEPARATOR}beta{NS_SEPARATOR}shared");
        store.put(&alpha, &hostile, b"forged").await.unwrap();

        assert_eq!(
            store.get(&beta, "shared").await.unwrap().unwrap().value,
            b"beta-value".to_vec(),
            "a key written under alpha must never land in beta"
        );
        let beta_keys: Vec<String> = store
            .list(&beta)
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(beta_keys, vec!["shared".to_string()]);

        let alpha_keys: Vec<String> = store
            .list(&alpha)
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(alpha_keys.len(), 2, "both alpha keys stayed in alpha");

        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn put_get_list_delete_and_revision() {
        let path = temp_path();
        let store = EmbeddedKvStore::open(&path, "test").expect("open");
        let queue = ns("queue");
        assert_eq!(store.revision().await.unwrap(), 0);

        let first = store.put(&queue, "a", b"one").await.unwrap();
        assert_eq!(first, 1);
        assert_eq!(store.revision().await.unwrap(), 1);
        let entry = store.get(&queue, "a").await.unwrap().unwrap();
        assert_eq!(entry.value, b"one".to_vec());
        assert_eq!(entry.revision, 1);

        store.put(&queue, "b", b"two").await.unwrap();
        let listed = store.list(&queue).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, "a", "list is in key order");

        store.delete(&queue, "a").await.unwrap();
        assert!(store.get(&queue, "a").await.unwrap().is_none());

        // Deleting an absent key is not an error and still bumps the
        // revision, matching EmbeddedKeyStore::delete_key.
        let after = store.delete(&queue, "never-existed").await.unwrap();
        assert_eq!(after, store.revision().await.unwrap());

        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn a_stale_writer_loses_the_compare_and_swap() {
        let path = temp_path();
        let store = EmbeddedKvStore::open(&path, "test").expect("open");
        let queue = ns("queue");

        store.put(&queue, "reg-1", b"pending").await.unwrap();
        let read = store.get(&queue, "reg-1").await.unwrap().unwrap();

        // A rejection lands first, carrying the revision it read.
        let rejected = store
            .put_if_revision(&queue, "reg-1", b"rejected", read.revision)
            .await
            .unwrap();
        assert!(matches!(rejected, CasOutcome::Applied { .. }));

        // The approval still holds the revision it read before the
        // rejection. It must not clobber the terminal state.
        let approved = store
            .put_if_revision(&queue, "reg-1", b"approved", read.revision)
            .await
            .unwrap();
        match approved {
            CasOutcome::Conflict { actual } => {
                assert_ne!(actual, read.revision);
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(
            store.get(&queue, "reg-1").await.unwrap().unwrap().value,
            b"rejected".to_vec()
        );

        assert_eq!(
            store
                .put_if_revision(&queue, "absent", b"x", 1)
                .await
                .unwrap(),
            CasOutcome::NotFound
        );

        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn insert_if_absent_refuses_the_second_writer() {
        let path = temp_path();
        let store = EmbeddedKvStore::open(&path, "test").expect("open");
        let queue = ns("queue");

        assert!(store
            .insert_if_absent(&queue, "slug", b"first")
            .await
            .unwrap()
            .is_some());
        assert!(
            store
                .insert_if_absent(&queue, "slug", b"second")
                .await
                .unwrap()
                .is_none(),
            "a taken slug is not handed out twice"
        );
        assert_eq!(
            store.get(&queue, "slug").await.unwrap().unwrap().value,
            b"first".to_vec()
        );

        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn records_survive_a_reopen() {
        let path = temp_path();
        let queue = ns("queue");
        {
            let store = EmbeddedKvStore::open(&path, "test").expect("open");
            store.put(&queue, "durable", b"value").await.unwrap();
        }
        let store = EmbeddedKvStore::open(&path, "test").expect("reopen");
        assert_eq!(
            store.get(&queue, "durable").await.unwrap().unwrap().value,
            b"value".to_vec()
        );
        assert_eq!(store.revision().await.unwrap(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// A config reload opens the candidate generation's store while the live
    /// generation still holds its own, and redb locks the file exclusively.
    /// `open` fails there; `open_shared` hands back the live handle.
    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn open_shared_reuses_the_handle_this_process_already_holds() {
        let path = temp_path();
        let live = EmbeddedKvStore::open_shared(&path, "test").expect("open_shared");

        assert!(
            EmbeddedKvStore::open(&path, "test").is_err(),
            "redb should refuse a second exclusive open, which is what makes \
             open_shared necessary rather than merely cheaper"
        );

        let candidate = EmbeddedKvStore::open_shared(&path, "test").expect("second open_shared");
        assert!(
            Arc::ptr_eq(&live, &candidate),
            "both generations must share one handle"
        );

        let queue = ns("queue");
        live.put(&queue, "k", b"v").await.unwrap();
        assert!(candidate.get(&queue, "k").await.unwrap().is_some());

        drop(candidate);
        drop(live);
        let reopened = EmbeddedKvStore::open_shared(&path, "test").expect("reopen after drop");
        assert_eq!(reopened.revision().await.unwrap(), 1);
        drop(reopened);

        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "redb-store")]
    #[tokio::test]
    async fn a_key_past_the_cap_is_refused_rather_than_stored() {
        let path = temp_path();
        let store = EmbeddedKvStore::open(&path, "test").expect("open");
        let queue = ns("queue");
        let oversized = "k".repeat(MAX_KEY_BYTES + 1);
        assert!(store.put(&queue, &oversized, b"v").await.is_err());
        assert!(store.get(&queue, "").await.is_err(), "empty key refused");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn ephemeral_entries_expire_by_the_clock() {
        let store = MemoryKv::new("test");
        let window = ns("dedup");
        assert!(store
            .put_with_ttl(&window, "fingerprint", b"seen", Duration::from_millis(40))
            .await
            .unwrap());
        assert_eq!(
            store.get(&window, "fingerprint").await.unwrap(),
            Some(b"seen".to_vec())
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store.get(&window, "fingerprint").await.unwrap(),
            None,
            "an expired entry reads as absent whether or not a sweep ran"
        );
        assert!(store.is_empty().await);
    }

    /// The cap is what stops a dedup window fed by request-derived keys from
    /// becoming a memory exhaustion primitive. A full store refuses the
    /// write and says so, rather than evicting a live entry or growing.
    #[tokio::test]
    async fn a_full_ephemeral_store_refuses_rather_than_growing() {
        let store = MemoryKv::with_capacity("test", 2);
        let window = ns("dedup");
        let long = Duration::from_secs(60);
        assert!(store.put_with_ttl(&window, "a", b"1", long).await.unwrap());
        assert!(store.put_with_ttl(&window, "b", b"2", long).await.unwrap());
        assert!(
            !store.put_with_ttl(&window, "c", b"3", long).await.unwrap(),
            "the third write is refused, not silently dropped"
        );
        assert_eq!(store.len().await, 2);

        // Overwriting a key already present is always allowed: it does not
        // grow the store.
        assert!(store.put_with_ttl(&window, "a", b"9", long).await.unwrap());
        assert_eq!(store.get(&window, "a").await.unwrap(), Some(b"9".to_vec()));

        // Once an entry expires the sweep reclaims room for a new one.
        let store = MemoryKv::with_capacity("test", 1);
        assert!(store
            .put_with_ttl(&window, "a", b"1", Duration::from_millis(30))
            .await
            .unwrap());
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            store.put_with_ttl(&window, "b", b"2", long).await.unwrap(),
            "an expired entry must not hold a slot forever"
        );
    }

    #[tokio::test]
    async fn ephemeral_remove_is_idempotent() {
        let store = MemoryKv::new("test");
        let window = ns("dedup");
        store.remove(&window, "absent").await.unwrap();
        store
            .put_with_ttl(&window, "k", b"v", Duration::from_secs(30))
            .await
            .unwrap();
        store.remove(&window, "k").await.unwrap();
        assert_eq!(store.get(&window, "k").await.unwrap(), None);
    }
}
