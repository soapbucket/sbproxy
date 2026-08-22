//! Storage for dynamically-minted Cedar policies.
//!
//! WOR-2586. The epic's central promise is "no Postgres requirement,
//! stateless by default," and this module is where that promise is
//! kept or broken, so start with what it does **not** cover: a
//! `cedar_policies:` block authored in `sb.yml` (or a directory of
//! `.cedar` files it references) compiles into a
//! `cedar_policy::PolicySet` once, at config-load time, through
//! [`super::compiler::compile_all`], exactly like every other policy
//! kind sbproxy already ships (Regorus, CEL). That path never
//! constructs a [`PolicyStore`] and never touches this module; the
//! config file is the system of record and a restart with the same
//! config produces the same compiled set. See
//! `static_policy_compilation_never_touches_a_store` below for the
//! test that pins this boundary.
//!
//! What *does* need a mutable system of record is a policy minted or
//! edited at runtime without a config reload (an admin-API or CLI
//! `apply` path, both follow-up work): something has to hold that
//! policy's source text between the mutation and the next process
//! restart. [`PolicyStore`] is that seam, and [`EmbeddedPolicyStore`]
//! is its default, zero-external-dependency implementation, following
//! the exact pattern `sbproxy-keystore::embedded::EmbeddedKeyStore`
//! already proved out for API keys (WOR-1546):
//!
//! - redb, a pure-Rust embedded ACID KV database, is the default
//!   backend rather than Postgres. `Database` is `Send + Sync`.
//! - Records are JSON-encoded under a `policies` table, keyed by
//!   policy id. A `meta` table holds a monotonic revision counter
//!   bumped inside the same write transaction as every mutation, so
//!   the counter is always consistent with the data a reader sees.
//! - [`EmbeddedPolicyStore::open_shared`] keeps one redb handle per
//!   file per process behind a `Weak`-referenced registry, so a
//!   config reload that builds a candidate policy generation while
//!   the live generation still holds the file does not fail redb's
//!   exclusive-lock check the way an unconditional second `open`
//!   would.
//!
//! [`PolicyStore`] is deliberately narrow: CRUD by policy id plus a
//! store-wide revision counter. It is not a general-purpose KV
//! abstraction, and this module does not implement (or feature-gate)
//! a Postgres backend; WOR-221's durable, content-hash-indexed,
//! quarantine-aware design stays enterprise-only, reachable later as
//! an opt-in [`PolicyStore`] implementor for operators who already run
//! Postgres and want it. Nothing here requires one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const POLICIES: TableDefinition<&str, &[u8]> = TableDefinition::new("policies");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const REVISION_KEY: &str = "revision";

/// One dynamically-minted Cedar policy, addressed by `policy_id`.
///
/// `cedar_source` is the policy's Cedar source text rather than any
/// internal cedar-policy representation: `cedar_policy::PolicySet` has
/// no serde support, but it round-trips losslessly through text via
/// `Display` on the way in and [`super::compiler::compile_all`] on the
/// way back out, which is the same text-in/text-out shape the static
/// config-compiled path already uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPolicy {
    /// Stable identifier the caller addresses this policy by. This is
    /// an application-level id (an admin-API resource id, say), not
    /// necessarily the Cedar `PolicyId` the compiled text carries once
    /// parsed.
    pub policy_id: String,
    /// Cedar source text for this policy.
    pub cedar_source: String,
    /// When this record was last written. Set by the caller so the
    /// store stays free of a wall-clock dependency; tests can pin it.
    pub updated_at: DateTime<Utc>,
}

impl StoredPolicy {
    /// Construct a new record.
    pub fn new(
        policy_id: impl Into<String>,
        cedar_source: impl Into<String>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            cedar_source: cedar_source.into(),
            updated_at,
        }
    }
}

/// A pluggable, mutable store of runtime-minted Cedar policies.
///
/// This is the seam a future admin-API or CLI `apply` path writes
/// through. [`EmbeddedPolicyStore`] is the default implementation;
/// nothing in this crate requires any other backend to exist for
/// sbproxy to start and serve Cedar-governed traffic.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Fetch a policy by id.
    async fn get_policy(&self, policy_id: &str) -> Result<Option<StoredPolicy>>;

    /// List every stored policy. The full result is the current
    /// dynamic-policy bundle: a caller that wants a `PolicySet` calls
    /// this, feeds every `cedar_source` into
    /// [`super::compiler::compile_all`], and gets back the same
    /// validate-before-apply contract the static path already has.
    async fn list_policies(&self) -> Result<Vec<StoredPolicy>>;

    /// Insert or replace a policy record (keyed on `policy_id`).
    async fn put_policy(&self, policy: StoredPolicy) -> Result<()>;

    /// Delete a policy record. Deleting an absent id is not an error.
    async fn delete_policy(&self, policy_id: &str) -> Result<()>;

    /// A monotonic revision number, bumped on every mutation. Lets a
    /// caller cheaply detect that the store changed since it last
    /// read, without diffing the full policy list.
    async fn revision(&self) -> Result<u64>;
}

/// Stores this process currently holds, keyed by resolved database path.
///
/// See [`EmbeddedPolicyStore::open_shared`] for why one handle per file
/// per process is a requirement rather than an optimization; this
/// mirrors `sbproxy_keystore::embedded`'s `OPEN_STORES` registry
/// exactly, over a distinct table set.
static OPEN_STORES: LazyLock<Mutex<HashMap<PathBuf, Weak<EmbeddedPolicyStore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve `path` to the key the registry compares on, so two spellings
/// of one file do not look like two files and re-open the same
/// database.
///
/// The database file may not exist yet on a first open, in which case
/// `canonicalize` on the file itself fails and the parent directory
/// carries the resolution. Falling back to the path as written is
/// correct but weaker: a missed match only costs the "already open"
/// error the caller would have hit anyway.
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

/// A redb-backed [`PolicyStore`]. The database file is created at the
/// given path.
pub struct EmbeddedPolicyStore {
    db: Database,
}

impl EmbeddedPolicyStore {
    /// Open (or create) the store at `path`, ensuring all tables exist.
    ///
    /// The file is pre-created owner-only before redb is handed the
    /// path, for the same reason `EmbeddedKeyStore::open` does: redb
    /// calls `File::create` itself, which asks for `0o666` and lets the
    /// umask decide, and a database holding operator-authored
    /// authorization policy should not land world-readable under a
    /// permissive umask.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        sbproxy_util::secure_fs::ensure_file_owner_only(path)
            .with_context(|| format!("create policy store database at {}", path.display()))?;
        let db = Database::create(path)
            .with_context(|| format!("open policy store database at {}", path.display()))?;
        let write_txn = db.begin_write().context("begin init transaction")?;
        {
            write_txn
                .open_table(POLICIES)
                .context("open policies table")?;
            write_txn.open_table(META).context("open meta table")?;
        }
        write_txn.commit().context("commit init transaction")?;
        Ok(Self { db })
    }

    /// Open the store at `path`, reusing the handle this process already
    /// holds for that file when there is one.
    ///
    /// redb locks the database file exclusively, so a second
    /// [`Self::open`] of a path this process is already holding fails
    /// with `Database already open. Cannot acquire lock.` A config
    /// reload builds a candidate policy generation while the live
    /// generation still owns its store, so an unconditional re-open
    /// makes every reload of a config with dynamic Cedar policies fail
    /// and leaves the node on the old config. One redb handle per file
    /// per process is the invariant, and it belongs to the type that
    /// owns the handle rather than to each caller that might open one.
    ///
    /// Sharing is safe: `Database` is `Send + Sync` and every mutation
    /// runs in its own ACID transaction, so two generations pointed at
    /// one file are two views of one system of record, which is what
    /// they are meant to be. The registry holds [`Weak`] references, so
    /// the file closes once the last generation referencing it is
    /// dropped and a later open reads it afresh.
    pub fn open_shared(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref();
        let key = registry_key(path);
        let mut live = OPEN_STORES.lock();
        if let Some(existing) = live.get(&key).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        let store = Arc::new(Self::open(path)?);
        // Forget stores nobody holds, so a long-lived process that
        // reloads through a series of paths does not accumulate dead
        // entries.
        live.retain(|_, handle| handle.strong_count() > 0);
        live.insert(key, Arc::downgrade(&store));
        Ok(store)
    }

    /// Bump the revision counter inside an already-open write
    /// transaction.
    fn bump_revision(txn: &redb::WriteTransaction) -> Result<()> {
        let mut meta = txn.open_table(META).context("open meta table")?;
        let current = meta
            .get(REVISION_KEY)
            .context("read revision")?
            .map(|g| g.value())
            .unwrap_or(0);
        meta.insert(REVISION_KEY, current + 1)
            .context("write revision")?;
        Ok(())
    }
}

#[async_trait]
impl PolicyStore for EmbeddedPolicyStore {
    async fn get_policy(&self, policy_id: &str) -> Result<Option<StoredPolicy>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(POLICIES).context("open policies table")?;
        match table.get(policy_id).context("get policy")? {
            Some(guard) => {
                let rec = serde_json::from_slice(guard.value()).context("decode policy record")?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    async fn list_policies(&self) -> Result<Vec<StoredPolicy>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(POLICIES).context("open policies table")?;
        let mut out = Vec::new();
        for entry in table.iter().context("iter policies")? {
            let (_, v) = entry.context("read policy entry")?;
            out.push(serde_json::from_slice(v.value()).context("decode policy record")?);
        }
        Ok(out)
    }

    async fn put_policy(&self, record: StoredPolicy) -> Result<()> {
        let bytes = serde_json::to_vec(&record).context("encode policy record")?;
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(POLICIES).context("open policies table")?;
            table
                .insert(record.policy_id.as_str(), bytes.as_slice())
                .context("insert policy")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit put_policy")
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(POLICIES).context("open policies table")?;
            table.remove(policy_id).context("remove policy")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit delete_policy")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!(
            "{}/sbproxy_cedar_storage_test_{}_{}_{:x}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n,
            nanos
        )
    }

    #[tokio::test]
    async fn put_get_list_delete_and_revision() {
        let path = temp_path();
        let store = EmbeddedPolicyStore::open(&path).unwrap();
        assert_eq!(store.revision().await.unwrap(), 0);

        let a = StoredPolicy::new("pol-a", r#"permit(principal, action, resource);"#, now());
        store.put_policy(a.clone()).await.unwrap();
        assert_eq!(store.revision().await.unwrap(), 1);

        let got = store.get_policy("pol-a").await.unwrap().unwrap();
        assert_eq!(got, a);

        let b = StoredPolicy::new(
            "pol-b",
            r#"forbid(principal, action, resource) when { resource has tag };"#,
            now(),
        );
        store.put_policy(b).await.unwrap();
        assert_eq!(store.list_policies().await.unwrap().len(), 2);
        assert_eq!(store.revision().await.unwrap(), 2);

        store.delete_policy("pol-a").await.unwrap();
        assert!(store.get_policy("pol-a").await.unwrap().is_none());
        assert_eq!(store.list_policies().await.unwrap().len(), 1);
        assert_eq!(store.revision().await.unwrap(), 3);

        // Deleting an absent id is not an error. It still bumps the
        // revision, same as `EmbeddedKeyStore::delete_key`: an
        // idempotent no-op delete is still a write transaction from
        // the store's perspective.
        store.delete_policy("never-existed").await.unwrap();
        assert_eq!(store.revision().await.unwrap(), 4);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn persists_across_reopen() {
        let path = temp_path();
        {
            let store = EmbeddedPolicyStore::open(&path).unwrap();
            store
                .put_policy(StoredPolicy::new(
                    "persist",
                    r#"permit(principal, action, resource);"#,
                    now(),
                ))
                .await
                .unwrap();
        }
        let store = EmbeddedPolicyStore::open(&path).unwrap();
        let got = store.get_policy("persist").await.unwrap().unwrap();
        assert_eq!(got.cedar_source, r#"permit(principal, action, resource);"#);
        assert_eq!(store.revision().await.unwrap(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// A config reload opens the candidate generation's store while the
    /// live generation still holds its own, and redb locks the file
    /// exclusively. `open` fails there; `open_shared` hands back the
    /// live handle and the two generations read one system of record.
    #[tokio::test]
    async fn open_shared_reuses_the_handle_this_process_already_holds() {
        let path = temp_path();
        let live = EmbeddedPolicyStore::open_shared(&path).unwrap();

        assert!(
            EmbeddedPolicyStore::open(&path).is_err(),
            "redb should refuse a second exclusive open, which is what makes \
             open_shared necessary rather than merely cheaper"
        );

        let candidate = EmbeddedPolicyStore::open_shared(&path).expect("second open_shared");
        assert!(
            Arc::ptr_eq(&live, &candidate),
            "both generations must share one handle"
        );

        live.put_policy(StoredPolicy::new(
            "pol-a",
            r#"permit(principal, action, resource);"#,
            now(),
        ))
        .await
        .unwrap();
        assert!(candidate.get_policy("pol-a").await.unwrap().is_some());

        // Another spelling of the same file resolves to the same handle.
        let dotted = Path::new(&path)
            .parent()
            .unwrap()
            .join(".")
            .join(Path::new(&path).file_name().unwrap());
        let via_dotted = EmbeddedPolicyStore::open_shared(&dotted).expect("dotted open_shared");
        assert!(Arc::ptr_eq(&live, &via_dotted));

        // Once every generation is gone the file is closed, so a later
        // boot opens it afresh rather than inheriting a handle nobody
        // holds.
        drop(candidate);
        drop(via_dotted);
        drop(live);
        let reopened = EmbeddedPolicyStore::open_shared(&path).expect("reopen after drop");
        assert_eq!(reopened.revision().await.unwrap(), 1);
        drop(reopened);

        std::fs::remove_file(&path).ok();
    }

    /// WOR-2586's central claim: static, config-compiled Cedar policies
    /// need no storage at all. This test runs the exact static path
    /// (source text -> `compile_all` -> `CedarEvaluator`) against a
    /// scratch directory and asserts the directory stays empty
    /// throughout, so a future change that threaded a `PolicyStore`
    /// (or even just an incidental redb file) into the static
    /// compile-time load path goes red here, on the observable side
    /// effect (a file appearing) rather than on an easily-stale
    /// "nothing calls PolicyStore" code inspection.
    #[test]
    fn static_policy_compilation_never_touches_a_store() {
        use crate::cedar::{compile_all, CedarEvaluator, CedarRequest};
        use sbproxy_plugin::PolicyDecision;

        let dir = tempfile::tempdir().expect("scratch dir");

        let src = r#"permit(principal == User::"alice", action, resource);"#;
        let compiled = compile_all(&[("static", src)], None).expect("static compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("evaluator");

        let allow = CedarRequest::new(r#"User::"alice""#, r#"Action::"view""#, r#"Doc::"x""#);
        assert_eq!(evaluator.evaluate(&allow), PolicyDecision::Allow);

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read scratch dir")
            .collect();
        assert!(
            entries.is_empty(),
            "static policy compilation created filesystem entries, implying a \
             store was touched on a path the epic promises is store-free: {entries:?}"
        );
    }
}
