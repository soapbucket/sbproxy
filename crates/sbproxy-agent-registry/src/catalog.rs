//! The in-memory catalog, and the last-good copy that survives a restart.
//!
//! # Two layers, one job
//!
//! Reads go through an `ArcSwap<Catalog>`: a refresh builds a whole new
//! catalog and swaps the pointer, so a reader either sees the old catalog
//! or the new one and never a half-rebuilt map. That is the same shape
//! `sbproxy-core` and `sbproxy-modules` already use for hot-swapped state.
//!
//! Behind it sits the durable copy. Every verified refresh writes the
//! catalog into the shared embedded store, and boot loads that copy before
//! anything reads. The enterprise implementation used a Postgres table for
//! exactly this; the reason it needed one has nothing to do with Postgres
//! and everything to do with the restart, so an embedded store answers it
//! without adding a service to the deployment.
//!
//! # The cached copy is not re-verified
//!
//! What the store holds is the catalog a signature already vouched for, not
//! the signed document. Re-verifying on load would need the feed bytes and
//! the key directory kept alongside it, and the trust boundary would still
//! be the same file: an attacker who can rewrite the store file can rewrite
//! whatever is next to it. The store is created owner-only for that reason,
//! and the envelope's `expires_at` is carried with it so a cached catalog
//! still expires on the publisher's schedule rather than living forever.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sbproxy_platform::storage::{KvNamespace, PersistentKv};

use crate::error::{RegistryError, Result};
use crate::feed::{AgentFeed, FeedEntry};

/// Namespace holding one JSON entry per catalog agent.
const CATALOG_NAMESPACE: &str = "agent_catalog";
/// Namespace holding the one-record feed envelope alongside it.
const ENVELOPE_NAMESPACE: &str = "agent_catalog_envelope";
/// The single key inside [`ENVELOPE_NAMESPACE`] holding the live envelope.
const ENVELOPE_KEY: &str = "current";
/// Key written before a catalog swap starts and removed once it has
/// finished.
///
/// `PersistentKv` has no batch write, so `apply` is a sequence of
/// independent transactions and a crash or a full disk part-way through
/// leaves the store holding some of the new generation under the old
/// generation's envelope. This marker is what makes that state
/// recognizable: a restore that finds it refuses the whole copy rather
/// than serving a mixture stamped with a `generated_at` that never
/// described it. The boot refresh re-applies from the feed immediately
/// afterwards, so the cost of refusing is one refresh rather than a
/// wrong catalog nobody can detect.
const ENVELOPE_IN_PROGRESS_KEY: &str = "swap_in_progress";

/// The feed envelope, kept next to the cached entries so a restored catalog
/// still knows when the publisher meant it to expire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CachedEnvelope {
    generated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// Digest of the verified feed bytes this generation came from.
    ///
    /// What makes a refresh that finds an unchanged file free. `default`
    /// rather than required so a store written before this field existed
    /// restores rather than failing; the first refresh then fills it in.
    #[serde(default)]
    digest: Option<String>,
}

/// What a catalog apply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogApplied {
    /// The feed was byte-identical to the one already applied, so nothing
    /// was written. Carries the entry count still being served.
    Unchanged(usize),
    /// The catalog was replaced. Carries the new entry count.
    Replaced(usize),
}

impl CatalogApplied {
    /// How many entries the catalog holds either way.
    pub fn entries(self) -> usize {
        match self {
            Self::Unchanged(count) | Self::Replaced(count) => count,
        }
    }
}

/// What a catalog reports to a readiness endpoint.
///
/// Three states rather than a bool, because "no catalog has ever been
/// applied" and "the catalog we have has expired" are different operator
/// actions: the first is a feed that has never verified, the second is a
/// publisher who has stopped republishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogHealth {
    /// No verified catalog has been applied since boot.
    NoCatalog,
    /// The catalog in memory is past the publisher's `expires_at`.
    Expired,
    /// Serving this many entries.
    Serving(usize),
}

/// A read-only snapshot of the catalog.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    entries: HashMap<String, FeedEntry>,
    generated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl Catalog {
    /// Build a catalog from a feed whose signature has already verified.
    ///
    /// This type does not verify. Taking an [`AgentFeed`] rather than raw
    /// bytes is what keeps that honest: the only way to get one is through
    /// [`crate::feed::verify_feed`].
    pub(crate) fn from_feed(feed: AgentFeed) -> Self {
        let mut entries = HashMap::with_capacity(feed.entries.len());
        for entry in feed.entries {
            entries.insert(entry.agent_id.clone(), entry);
        }
        Self {
            entries,
            generated_at: Some(feed.generated_at),
            expires_at: Some(feed.expires_at),
        }
    }

    /// The entry for `agent_id`, if the catalog names it.
    pub fn get(&self, agent_id: &str) -> Option<&FeedEntry> {
        self.entries.get(agent_id)
    }

    /// Every entry, in agent-id order so a listing endpoint is stable
    /// between calls.
    pub fn sorted_entries(&self) -> Vec<&FeedEntry> {
        let mut entries: Vec<&FeedEntry> = self.entries.values().collect();
        entries.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        entries
    }

    /// How many agents the catalog names.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog names no agents, which is what an unconfigured
    /// or never-refreshed registry looks like.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// What this catalog reports to a readiness endpoint.
    ///
    /// Here rather than at the call site because the three states are a
    /// claim `docs/agent-registry.md` makes to operators, and a mapping
    /// that exists only inside a closure in `run()` is one no test can
    /// reach.
    pub fn health(&self, now: DateTime<Utc>) -> CatalogHealth {
        if self.is_empty() {
            CatalogHealth::NoCatalog
        } else if self.is_expired(now) {
            CatalogHealth::Expired
        } else {
            CatalogHealth::Serving(self.len())
        }
    }

    /// Whether `now` is past the publisher's expiry.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }

    /// When the publisher built the feed this catalog came from.
    pub fn generated_at(&self) -> Option<DateTime<Utc>> {
        self.generated_at
    }

    /// When the publisher's expiry falls.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
}

/// The live catalog pointer plus its durable copy.
pub struct CatalogStore {
    live: ArcSwap<Catalog>,
    store: Arc<dyn PersistentKv>,
    entries: KvNamespace,
    envelope: KvNamespace,
    /// Digest of the feed the live catalog came from, so a refresh that
    /// finds the same file costs a read and a verify rather than a full
    /// rewrite of every entry.
    ///
    /// An `ArcSwapOption` for the same reason `live` is an `ArcSwap`: the
    /// read is on every refresh and the write is once per generation.
    applied_digest: arc_swap::ArcSwapOption<String>,
}

impl CatalogStore {
    /// Build a catalog store over the shared embedded store, starting
    /// empty. Call [`Self::restore`] to load the last-good copy.
    pub fn new(store: Arc<dyn PersistentKv>) -> Result<Self> {
        let namespace = |name: &str| {
            KvNamespace::new(name).map_err(|error| RegistryError::Backend(error.to_string()))
        };
        Ok(Self {
            live: ArcSwap::from_pointee(Catalog::default()),
            store,
            entries: namespace(CATALOG_NAMESPACE)?,
            envelope: namespace(ENVELOPE_NAMESPACE)?,
            applied_digest: arc_swap::ArcSwapOption::from(None),
        })
    }

    /// The current snapshot. Cheap: one atomic load and an `Arc` clone.
    pub fn snapshot(&self) -> Arc<Catalog> {
        self.live.load_full()
    }

    /// Load the last verified catalog from the store into the live pointer.
    ///
    /// Returns how many entries were restored. A store with no envelope is
    /// a first boot rather than an error, and answers zero.
    pub async fn restore(&self) -> Result<usize> {
        if self
            .store
            .get(&self.envelope, ENVELOPE_IN_PROGRESS_KEY)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
            .is_some()
        {
            tracing::warn!(
                "the cached agent catalog is a partially written generation and was not \
                 restored; the next feed refresh replaces it"
            );
            return Ok(0);
        }
        let Some(envelope_entry) = self
            .store
            .get(&self.envelope, ENVELOPE_KEY)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
        else {
            return Ok(0);
        };
        let envelope: CachedEnvelope =
            serde_json::from_slice(&envelope_entry.value).map_err(|error| {
                RegistryError::Backend(format!("cached feed envelope is unreadable: {error}"))
            })?;

        let stored = self
            .store
            .list(&self.entries)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?;
        let mut entries = HashMap::with_capacity(stored.len());
        for (agent_id, record) in stored {
            let entry: FeedEntry = serde_json::from_slice(&record.value).map_err(|error| {
                RegistryError::Backend(format!("cached catalog entry is unreadable: {error}"))
            })?;
            entries.insert(agent_id, entry);
        }

        let restored = entries.len();
        // Adopt the stored digest too, so the first refresh after a restart
        // is free when the publisher has not republished. A store written
        // before the field existed restores `None` and pays one rewrite.
        self.applied_digest
            .store(envelope.digest.clone().map(Arc::new));
        self.live.store(Arc::new(Catalog {
            entries,
            generated_at: Some(envelope.generated_at),
            expires_at: Some(envelope.expires_at),
        }));
        Ok(restored)
    }

    /// Swap in a verified feed and write it through to the store.
    ///
    /// The write is a full replacement: entries the new feed dropped are
    /// deleted rather than left behind. An additive-only cache is how a
    /// withdrawn agent keeps its catalog entry forever, which is the one
    /// thing a revocation has to be able to undo. The enterprise Postgres
    /// adapter carried that exact caveat in a comment; this does not need
    /// one.
    ///
    /// # Why the digest short-circuit exists
    ///
    /// A full replacement of a 10,000-entry catalog is 10,000 fsynced redb
    /// transactions plus the deletes, the envelope, and the marker. The
    /// refresh timer runs on the operator's staleness tolerance, not on
    /// whether the publisher republished, so without this the proxy paid
    /// that whole write every interval for a file that had not changed.
    /// `digest` is over the verified feed bytes, so an unchanged file is a
    /// read and a signature check and nothing else.
    pub async fn apply(&self, feed: AgentFeed, digest: &str) -> Result<CatalogApplied> {
        if self
            .applied_digest
            .load()
            .as_deref()
            .is_some_and(|applied| applied.as_str() == digest)
        {
            return Ok(CatalogApplied::Unchanged(self.live.load().len()));
        }
        let catalog = Catalog::from_feed(feed);

        self.store
            .put(&self.envelope, ENVELOPE_IN_PROGRESS_KEY, b"1")
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?;

        let existing: Vec<String> = self
            .store
            .list(&self.entries)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?
            .into_iter()
            .map(|(agent_id, _)| agent_id)
            .collect();
        for agent_id in existing {
            if !catalog.entries.contains_key(&agent_id) {
                self.store
                    .delete(&self.entries, &agent_id)
                    .await
                    .map_err(|error| RegistryError::Backend(error.to_string()))?;
            }
        }
        for (agent_id, entry) in &catalog.entries {
            let bytes = serde_json::to_vec(entry).map_err(|error| {
                RegistryError::Backend(format!("could not encode catalog entry: {error}"))
            })?;
            self.store
                .put(&self.entries, agent_id, &bytes)
                .await
                .map_err(|error| RegistryError::Backend(error.to_string()))?;
        }

        if let (Some(generated_at), Some(expires_at)) = (catalog.generated_at, catalog.expires_at) {
            let bytes = serde_json::to_vec(&CachedEnvelope {
                generated_at,
                expires_at,
                digest: Some(digest.to_string()),
            })
            .map_err(|error| {
                RegistryError::Backend(format!("could not encode feed envelope: {error}"))
            })?;
            self.store
                .put(&self.envelope, ENVELOPE_KEY, &bytes)
                .await
                .map_err(|error| RegistryError::Backend(error.to_string()))?;
        }

        self.store
            .delete(&self.envelope, ENVELOPE_IN_PROGRESS_KEY)
            .await
            .map_err(|error| RegistryError::Backend(error.to_string()))?;

        let applied = catalog.len();
        self.live.store(Arc::new(catalog));
        // After the marker is cleared, so a crash mid-apply leaves the
        // digest unset and the next refresh rewrites rather than skipping.
        self.applied_digest
            .store(Some(Arc::new(digest.to_string())));
        Ok(CatalogApplied::Replaced(applied))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::FeedSignature;
    use sbproxy_platform::storage::EmbeddedKvStore;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed instant")
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/sbproxy_agent_catalog_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n
        )
    }

    fn entry(agent_id: &str) -> FeedEntry {
        FeedEntry {
            agent_id: agent_id.into(),
            vendor: "Acme".into(),
            purpose: "search".into(),
            expected_user_agents: vec!["AcmeBot/1.0".into()],
            expected_reverse_dns_suffixes: vec![],
            expected_keyids: vec![],
            reputation_score: 70,
            flags: vec![],
        }
    }

    fn feed(agent_ids: &[&str]) -> AgentFeed {
        AgentFeed {
            format_version: 1,
            generated_at: now(),
            expires_at: now() + chrono::Duration::hours(24),
            entries: agent_ids.iter().map(|id| entry(id)).collect(),
            signature: FeedSignature {
                kid: "feed-1".into(),
                sig: String::new(),
            },
        }
    }

    fn catalog_store(path: &str) -> CatalogStore {
        let store = EmbeddedKvStore::open(path, "agent_registry").expect("open store");
        CatalogStore::new(Arc::new(store)).expect("catalog store")
    }

    /// The whole reason the enterprise version reached for Postgres: a
    /// restart while the publisher is unreachable still has to serve the
    /// last catalog a signature vouched for.
    #[tokio::test]
    async fn the_last_verified_catalog_survives_a_restart() {
        let path = temp_path();
        {
            let store = catalog_store(&path);
            assert_eq!(store.restore().await.expect("first boot"), 0);
            assert_eq!(
                store
                    .apply(feed(&["acme-1", "acme-2"]), "digest-a")
                    .await
                    .expect("apply")
                    .entries(),
                2
            );
        }

        let store = catalog_store(&path);
        assert!(store.snapshot().is_empty(), "a fresh handle starts empty");
        assert_eq!(store.restore().await.expect("restore"), 2);
        let snapshot = store.snapshot();
        assert!(snapshot.get("acme-1").is_some());
        assert_eq!(
            snapshot.expires_at(),
            Some(now() + chrono::Duration::hours(24))
        );
        assert!(!snapshot.is_expired(now()));
        assert!(snapshot.is_expired(now() + chrono::Duration::hours(25)));

        std::fs::remove_file(&path).ok();
    }

    /// A cache that only ever adds is how a withdrawn agent keeps its
    /// catalog entry forever. The refresh has to delete what the new feed
    /// dropped, and the deletion has to survive the restart too.
    #[tokio::test]
    async fn an_agent_dropped_from_the_feed_is_dropped_from_the_cache() {
        let path = temp_path();
        {
            let store = catalog_store(&path);
            store
                .apply(feed(&["acme-1", "acme-2"]), "digest-a")
                .await
                .expect("apply");
            store
                .apply(feed(&["acme-1"]), "digest-b")
                .await
                .expect("reapply");
            assert!(store.snapshot().get("acme-2").is_none());
        }

        let store = catalog_store(&path);
        assert_eq!(store.restore().await.expect("restore"), 1);
        assert!(
            store.snapshot().get("acme-2").is_none(),
            "a withdrawn agent must not come back on restart"
        );

        std::fs::remove_file(&path).ok();
    }

    /// `apply` is a sequence of independent transactions, so a crash or a
    /// full disk part-way through leaves the store holding some of the new
    /// generation under the old generation's envelope. Serving that mixture
    /// stamped with a `generated_at` that never described it is the failure
    /// the marker exists to make recognizable.
    #[tokio::test]
    async fn a_partially_written_generation_is_refused_rather_than_restored() {
        let path = temp_path();
        {
            let store = catalog_store(&path);
            store
                .apply(feed(&["acme-1"]), "digest-a")
                .await
                .expect("apply");
        }

        // Simulate the crash: the marker is present and the entries are a
        // mixture, exactly as an interrupted apply leaves them.
        let raw: Arc<dyn PersistentKv> =
            Arc::new(EmbeddedKvStore::open(&path, "agent_registry").expect("open"));
        let envelope = KvNamespace::new(ENVELOPE_NAMESPACE).expect("ns");
        raw.put(&envelope, ENVELOPE_IN_PROGRESS_KEY, b"1")
            .await
            .expect("mark");
        drop(raw);

        let store = catalog_store(&path);
        assert_eq!(
            store.restore().await.expect("restore"),
            0,
            "a partial generation must not be served"
        );
        assert!(store.snapshot().is_empty());

        // A successful apply clears the marker, so the next restore works.
        store
            .apply(feed(&["acme-1", "acme-2"]), "digest-a")
            .await
            .expect("apply");
        drop(store);
        let store = catalog_store(&path);
        assert_eq!(store.restore().await.expect("restore"), 2);

        std::fs::remove_file(&path).ok();
    }

    /// The refresh timer runs on the operator's staleness tolerance, not
    /// on whether the publisher republished, so on a healthy deployment
    /// almost every tick finds the same file. Rewriting a 10,000-entry
    /// catalog then costs 10,000 fsynced transactions plus the deletes,
    /// the envelope, and the marker, every interval, for nothing.
    #[tokio::test]
    async fn an_unchanged_feed_is_not_rewritten() {
        let path = temp_path();
        let store = catalog_store(&path);

        assert_eq!(
            store
                .apply(feed(&["acme-1", "acme-2"]), "digest-a")
                .await
                .expect("first apply"),
            CatalogApplied::Replaced(2)
        );

        // Same digest, so nothing is written and the count still answers.
        assert_eq!(
            store
                .apply(feed(&["acme-1", "acme-2"]), "digest-a")
                .await
                .expect("second apply"),
            CatalogApplied::Unchanged(2)
        );

        // A republished feed is applied.
        assert_eq!(
            store
                .apply(feed(&["acme-1"]), "digest-b")
                .await
                .expect("third apply"),
            CatalogApplied::Replaced(1)
        );
        assert_eq!(store.snapshot().len(), 1);

        // The digest is stored with the envelope, so a restart does not
        // pay one rewrite before it can start skipping.
        drop(store);
        let reopened = catalog_store(&path);
        assert_eq!(reopened.restore().await.expect("restore"), 1);
        assert_eq!(
            reopened
                .apply(feed(&["acme-1"]), "digest-b")
                .await
                .expect("post-restart apply"),
            CatalogApplied::Unchanged(1)
        );

        std::fs::remove_file(&path).ok();
    }

    /// `/readyz` already publishes a component called `agent_registry`,
    /// which is WOR-1743's agent-class resolver and has nothing to do with
    /// this block. The catalog reports under its own name, and these three
    /// states are what `docs/agent-registry.md` tells an operator to read.
    #[test]
    fn the_catalog_reports_three_distinct_states_to_a_readiness_endpoint() {
        assert_eq!(Catalog::default().health(now()), CatalogHealth::NoCatalog);

        let serving = Catalog::from_feed(feed(&["acme-1", "acme-2"]));
        assert_eq!(serving.health(now()), CatalogHealth::Serving(2));

        // Past the publisher's own expiry, which is a publisher that
        // stopped republishing rather than a feed that never verified.
        assert_eq!(
            serving.health(serving.expires_at().expect("the feed set one")),
            CatalogHealth::Expired
        );
    }

    #[tokio::test]
    async fn sorted_entries_is_stable_between_calls() {
        let path = temp_path();
        let store = catalog_store(&path);
        store
            .apply(feed(&["zeta", "alpha", "mid"]), "digest-a")
            .await
            .expect("apply");
        let snapshot = store.snapshot();
        let ids: Vec<&str> = snapshot
            .sorted_entries()
            .iter()
            .map(|entry| entry.agent_id.as_str())
            .collect();
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
        std::fs::remove_file(&path).ok();
    }
}
