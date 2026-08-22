//! Embedded [`KeyStore`] backend over [redb], the default durable system of
//! record.
//!
//! redb is a pure-Rust, ACID embedded KV database (`Database` is internally
//! `Send + Sync`). Records are JSON-encoded under three tables: `keys`,
//! `credentials`, and a `meta` table holding the monotonic revision counter.
//! Each mutation bumps the revision inside the same write transaction, so the
//! counter is consistent with the data.
//!
//! redb operations are synchronous. The store sits behind the [`TtlCache`](crate::cache::TtlCache),
//! so the hot request path does not touch it; mutations and cache-miss reloads
//! run on the admin / boot path where a brief synchronous file operation is
//! acceptable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};

use anyhow::{Context, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use redb::{Database, ReadableTable, TableDefinition};

use crate::record::{CredentialRecord, KeyRecord};
use crate::{KeyPolicyCasResult, KeyStore};

const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
const CREDS: TableDefinition<&str, &[u8]> = TableDefinition::new("credentials");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const REVISION_KEY: &str = "revision";

/// Stores this process currently holds, keyed by resolved database path.
///
/// See [`EmbeddedKeyStore::open_shared`] for why one handle per file per
/// process is a requirement rather than an optimization.
static OPEN_STORES: LazyLock<Mutex<HashMap<PathBuf, Weak<EmbeddedKeyStore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve `path` to the key the registry compares on, so two spellings of
/// one file (a relative path and its absolute form, a symlinked directory) do
/// not look like two files and re-open the same database.
///
/// The database file may not exist yet on a first open, in which case
/// `canonicalize` on the file itself fails and the parent directory carries
/// the resolution. Falling back to the path as written is correct but weaker:
/// a missed match only costs the "already open" error the caller would have
/// hit anyway.
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

/// A redb-backed key store. The database file is created at the given path.
pub struct EmbeddedKeyStore {
    db: Database,
}

impl EmbeddedKeyStore {
    /// Open (or create) the store at `path`, ensuring all tables exist.
    ///
    /// The file is pre-created owner-only before redb is handed the path.
    /// redb calls `File::create` itself, which asks for `0o666` and lets the
    /// umask decide, so the database holding every encrypted upstream
    /// credential landed at `0o644` under the near-universal `0o022`. redb
    /// opens an existing file rather than replacing it, so creating it at
    /// `0o600` first is enough, and it is the same order the settlement
    /// database uses for SQLite.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        sbproxy_util::secure_fs::ensure_file_owner_only(path)
            .with_context(|| format!("create keystore database at {}", path.display()))?;
        let db = Database::create(path)
            .with_context(|| format!("open keystore database at {}", path.display()))?;
        let write_txn = db.begin_write().context("begin init transaction")?;
        {
            write_txn.open_table(KEYS).context("open keys table")?;
            write_txn
                .open_table(CREDS)
                .context("open credentials table")?;
            write_txn.open_table(META).context("open meta table")?;
        }
        write_txn.commit().context("commit init transaction")?;
        Ok(Self { db })
    }

    /// Open the store at `path`, reusing the handle this process already holds
    /// for that file when there is one.
    ///
    /// redb locks the database file exclusively, so a second [`Self::open`] of
    /// a path this process is already holding fails with `Database already
    /// open. Cannot acquire lock.` That is not hypothetical: a config reload
    /// builds a candidate key plane while the live generation still owns its
    /// store, so an unconditional re-open makes every reload of a config with
    /// an embedded keystore fail and leaves the node on the old config. One
    /// redb handle per file per process is the invariant, and it belongs to
    /// the type that owns the handle rather than to each caller that might
    /// open one.
    ///
    /// Sharing is safe, and is what the other backends already do: `Database`
    /// is `Send + Sync` and every mutation runs in its own ACID transaction,
    /// so two generations pointed at one file are two views of one system of
    /// record, which is what they are meant to be. The registry holds [`Weak`]
    /// references, so the file closes once the last generation referencing it
    /// is dropped and a later open reads it afresh.
    pub fn open_shared(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref();
        let key = registry_key(path);
        let mut live = OPEN_STORES.lock();
        if let Some(existing) = live.get(&key).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        let store = Arc::new(Self::open(path)?);
        // Forget stores nobody holds, so a long-lived process that reloads
        // through a series of paths does not accumulate dead entries.
        live.retain(|_, handle| handle.strong_count() > 0);
        live.insert(key, Arc::downgrade(&store));
        Ok(store)
    }

    /// Bump the revision counter inside an already-open write transaction.
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
impl KeyStore for EmbeddedKeyStore {
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(KEYS).context("open keys table")?;
        match table.get(key_id).context("get key")? {
            Some(guard) => {
                let rec = serde_json::from_slice(guard.value()).context("decode key record")?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(KEYS).context("open keys table")?;
        let mut out = Vec::new();
        for entry in table.iter().context("iter keys")? {
            let (_, v) = entry.context("read key entry")?;
            out.push(serde_json::from_slice(v.value()).context("decode key record")?);
        }
        Ok(out)
    }

    async fn put_key(&self, record: KeyRecord) -> Result<()> {
        let bytes = serde_json::to_vec(&record).context("encode key record")?;
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(KEYS).context("open keys table")?;
            table
                .insert(record.key_id.as_str(), bytes.as_slice())
                .context("insert key")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit put_key")
    }

    async fn put_key_if_revision(
        &self,
        mut record: KeyRecord,
        expected_revision: u64,
    ) -> Result<KeyPolicyCasResult> {
        let txn = self.db.begin_write().context("begin policy CAS write")?;
        let policy_revision = {
            let mut table = txn.open_table(KEYS).context("open keys table")?;
            let current = match table
                .get(record.key_id.as_str())
                .context("get key for CAS")?
            {
                Some(value) => serde_json::from_slice::<KeyRecord>(value.value())
                    .context("decode key record for CAS")?,
                None => return Ok(KeyPolicyCasResult::NotFound),
            };
            if current.policy_revision != expected_revision {
                return Ok(KeyPolicyCasResult::Conflict {
                    actual_revision: current.policy_revision,
                });
            }

            let policy_revision = crate::next_policy_revision(expected_revision)?;
            record.policy_revision = policy_revision;
            let bytes = serde_json::to_vec(&record).context("encode key record for CAS")?;
            table
                .insert(record.key_id.as_str(), bytes.as_slice())
                .context("replace key with CAS")?;
            policy_revision
        };
        Self::bump_revision(&txn)?;
        txn.commit().context("commit key policy CAS")?;
        Ok(KeyPolicyCasResult::Applied { policy_revision })
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(KEYS).context("open keys table")?;
            table.remove(key_id).context("remove key")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit delete_key")
    }

    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(CREDS).context("open credentials table")?;
        match table.get(id).context("get credential")? {
            Some(guard) => {
                let rec =
                    serde_json::from_slice(guard.value()).context("decode credential record")?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(CREDS).context("open credentials table")?;
        let mut out = Vec::new();
        for entry in table.iter().context("iter credentials")? {
            let (_, v) = entry.context("read credential entry")?;
            out.push(serde_json::from_slice(v.value()).context("decode credential record")?);
        }
        Ok(out)
    }

    async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
        let bytes = serde_json::to_vec(&record).context("encode credential record")?;
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(CREDS).context("open credentials table")?;
            table
                .insert(record.id.as_str(), bytes.as_slice())
                .context("insert credential")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit put_credential")
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write().context("begin write")?;
        {
            let mut table = txn.open_table(CREDS).context("open credentials table")?;
            table.remove(id).context("remove credential")?;
        }
        Self::bump_revision(&txn)?;
        txn.commit().context("commit delete_credential")
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
    use crate::record::RecordStatus;
    use crate::KeyPolicyCasResult;
    use chrono::{DateTime, Utc};
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
            "{}/sbproxy_keystore_test_{}_{}_{:x}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n,
            nanos
        )
    }

    #[tokio::test]
    async fn put_get_list_delete_and_revision() {
        let path = temp_path();
        let store = EmbeddedKeyStore::open(&path).unwrap();
        assert_eq!(store.revision().await.unwrap(), 0);

        let mut rec = KeyRecord::new("k1", "h1", now());
        rec.name = Some("first".into());
        store.put_key(rec.clone()).await.unwrap();
        assert_eq!(store.revision().await.unwrap(), 1);

        let got = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("first"));

        store
            .put_key(KeyRecord::new("k2", "h2", now()))
            .await
            .unwrap();
        assert_eq!(store.list_keys().await.unwrap().len(), 2);
        assert_eq!(store.revision().await.unwrap(), 2);

        store.delete_key("k1").await.unwrap();
        assert!(store.get_key("k1").await.unwrap().is_none());
        assert_eq!(store.revision().await.unwrap(), 3);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn persists_across_reopen() {
        let path = temp_path();
        {
            let store = EmbeddedKeyStore::open(&path).unwrap();
            let mut rec = KeyRecord::new("persist", "h", now());
            rec.status = RecordStatus::Blocked;
            store.put_key(rec).await.unwrap();
        }
        let store = EmbeddedKeyStore::open(&path).unwrap();
        let got = store.get_key("persist").await.unwrap().unwrap();
        assert_eq!(got.status, RecordStatus::Blocked);
        assert_eq!(store.revision().await.unwrap(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// WOR-2561: an override is durable state, and its expiry is a stored
    /// instant read lazily, so a restart changes nothing. The reopened store
    /// hands back the same record, and the record itself decides whether the
    /// raise still applies: honored while unexpired, ignored once past.
    #[tokio::test]
    async fn a_persisted_budget_override_survives_reopen_and_expires_by_the_clock() {
        use crate::record::{BudgetOverride, RecordBudget};

        let path = temp_path();
        let expires_at = now() + chrono::Duration::seconds(60);
        {
            let store = EmbeddedKeyStore::open(&path).unwrap();
            let mut rec = KeyRecord::new("boosted", "h", now());
            rec.budget = Some(RecordBudget {
                max_tokens: Some(1_000),
                max_cost_usd: None,
            });
            rec.budget_override = Some(BudgetOverride {
                max_tokens_increase: Some(500),
                max_cost_usd_increase: None,
                expires_at,
                granted_by: "casey".into(),
                granted_at: now(),
                reason: None,
            });
            store.put_key(rec).await.unwrap();
        }

        // "Restart": a fresh handle over the same file.
        let store = EmbeddedKeyStore::open(&path).unwrap();
        let got = store.get_key("boosted").await.unwrap().unwrap();
        let grant = got.budget_override.as_ref().expect("override persisted");
        assert_eq!(grant.granted_by, "casey");
        assert_eq!(grant.expires_at, expires_at);

        // Unexpired at read time: the raise is honored.
        assert_eq!(got.effective_budget(now()).unwrap().max_tokens, Some(1_500));
        // Past the stored expiry: the same persisted record yields the base
        // cap, with no sweeper having touched the store.
        assert_eq!(
            got.effective_budget(expires_at).unwrap().max_tokens,
            Some(1_000)
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn key_policy_cas_is_transactional_and_monotonic() {
        let path = temp_path();
        let store = EmbeddedKeyStore::open(&path).unwrap();
        store
            .put_key(KeyRecord::new("k1", "hash", now()))
            .await
            .unwrap();

        let mut first = store.get_key("k1").await.unwrap().unwrap();
        first.blocked_providers = vec!["vertex".into()];
        assert_eq!(
            store.put_key_if_revision(first, 1).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );

        let mut stale = store.get_key("k1").await.unwrap().unwrap();
        stale.blocked_providers = vec!["bedrock".into()];
        assert_eq!(
            store.put_key_if_revision(stale, 1).await.unwrap(),
            KeyPolicyCasResult::Conflict { actual_revision: 2 }
        );

        let stored = store.get_key("k1").await.unwrap().unwrap();
        assert_eq!(stored.policy_revision, 2);
        assert_eq!(stored.blocked_providers, ["vertex"]);
        assert_eq!(store.revision().await.unwrap(), 2);
        std::fs::remove_file(&path).ok();
    }

    /// A config reload opens the candidate generation's store while the live
    /// generation still holds its own, and redb locks the file exclusively.
    /// `open` fails there; `open_shared` hands back the live handle and the
    /// two generations read one system of record.
    #[tokio::test]
    async fn open_shared_reuses_the_handle_this_process_already_holds() {
        let path = temp_path();
        let live = EmbeddedKeyStore::open_shared(&path).unwrap();

        assert!(
            EmbeddedKeyStore::open(&path).is_err(),
            "redb should refuse a second exclusive open, which is what makes \
             open_shared necessary rather than merely cheaper"
        );

        let candidate = EmbeddedKeyStore::open_shared(&path).expect("second open_shared");
        assert!(
            Arc::ptr_eq(&live, &candidate),
            "both generations must share one handle"
        );

        live.put_key(KeyRecord::new("k1", "hash", now()))
            .await
            .unwrap();
        assert!(candidate.get_key("k1").await.unwrap().is_some());

        // Another spelling of the same file resolves to the same handle.
        let dotted = Path::new(&path)
            .parent()
            .unwrap()
            .join(".")
            .join(Path::new(&path).file_name().unwrap());
        let via_dotted = EmbeddedKeyStore::open_shared(&dotted).expect("dotted open_shared");
        assert!(Arc::ptr_eq(&live, &via_dotted));

        // Once every generation is gone the file is closed, so a later boot
        // opens it afresh rather than inheriting a handle nobody holds.
        drop(candidate);
        drop(via_dotted);
        drop(live);
        let reopened = EmbeddedKeyStore::open_shared(&path).expect("reopen after drop");
        assert_eq!(reopened.revision().await.unwrap(), 1);
        drop(reopened);

        std::fs::remove_file(&path).ok();
    }
}
