//! In-memory store for compiled NL-to-Cedar policies (WOR-203 PR 3a).
//!
//! Holds [`CompiledPolicy`] records keyed by `policy_id`. The store
//! is the persistence-layer surface described in
//! `adr-policy-compilation.md` (NLC pillar C). The OSS build keeps
//! everything in process memory; the enterprise tier wraps the same
//! struct shape with a durable backing store.
//!
//! Cedar source is stored as bytes; the OSS build does not evaluate
//! it. The Cedar evaluator and the audit-replay tooling live in the
//! enterprise crate set.
//!
//! Concurrency: the store is held behind a `tokio::sync::RwLock`
//! around a `HashMap<Uuid, CompiledPolicy>`. Reads (`get`) take a
//! shared read lock; writes (`insert`) take an exclusive write lock.
//! `CompiledPolicy` is `Clone`, so callers receive an owned copy and
//! never hold the lock across `.await` boundaries on the value.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

/// A compiled, pinned NL-to-Cedar policy.
///
/// Field semantics follow `adr-policy-compilation.md`. The
/// `content_hash` is the hex-encoded SHA-256 of `cedar_source`; the
/// hashing itself is the compiler's responsibility (PR 3b) and the
/// store stores the precomputed value verbatim.
///
/// `compiler_version` is a semver string of the prompt version that
/// produced this Cedar (not the LLM's model version; see the ADR).
///
/// The struct is `Clone` so the store can hand out owned copies on
/// `get` without holding the read lock across the caller's await
/// points.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Stable identifier for this compiled policy version. A
    /// recompilation produces a new `policy_id`.
    pub policy_id: Uuid,
    /// The original NL input, stored verbatim for audit replay.
    pub nl_source: String,
    /// The compiled Cedar policy document.
    pub cedar_source: String,
    /// Semver string of the compiler prompt version.
    pub compiler_version: String,
    /// SHA-256 of `cedar_source`, hex-encoded. Used for drift
    /// detection on compiler upgrades.
    pub content_hash: String,
    /// When the author acknowledged and pinned this policy.
    pub pinned_at: DateTime<Utc>,
    /// Subject identifier of the author who pinned.
    pub pinned_by: String,
}

/// In-memory store of pinned [`CompiledPolicy`] records.
///
/// Cheap to clone (the inner state is `Arc`-shared), so the store is
/// typically constructed once at startup and cloned into every task
/// that needs read or write access.
#[derive(Debug, Clone, Default)]
pub struct CompiledPolicyStore {
    inner: Arc<RwLock<HashMap<Uuid, CompiledPolicy>>>,
}

impl CompiledPolicyStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite the policy keyed by `policy.policy_id`.
    ///
    /// Returns the `policy_id` for caller convenience (callers
    /// frequently need it to log or reference the freshly-inserted
    /// record).
    pub async fn insert(&self, policy: CompiledPolicy) -> Uuid {
        let id = policy.policy_id;
        let mut guard = self.inner.write().await;
        guard.insert(id, policy);
        id
    }

    /// Fetch a clone of the stored policy.
    ///
    /// Returns `None` if the id is not present.
    pub async fn get(&self, id: Uuid) -> Option<CompiledPolicy> {
        let guard = self.inner.read().await;
        guard.get(&id).cloned()
    }

    /// Number of policies currently stored. Exposed for diagnostics
    /// and tests; production callers should prefer the verdict event
    /// stream over polling counts.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// True when the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(nl: &str) -> CompiledPolicy {
        CompiledPolicy {
            policy_id: Uuid::new_v4(),
            nl_source: nl.to_string(),
            cedar_source: "permit(principal, action, resource);".to_string(),
            compiler_version: "1.0.0".to_string(),
            content_hash: "deadbeef".to_string(),
            pinned_at: Utc::now(),
            pinned_by: "rick@example.com".to_string(),
        }
    }

    #[tokio::test]
    async fn insert_then_get_round_trip() {
        let store = CompiledPolicyStore::new();
        let policy = sample("allow User to read Invoice");
        let id = policy.policy_id;
        let returned = store.insert(policy.clone()).await;
        assert_eq!(returned, id);

        let got = store.get(id).await.expect("policy is present");
        assert_eq!(got.policy_id, id);
        assert_eq!(got.nl_source, "allow User to read Invoice");
        assert_eq!(got.compiler_version, "1.0.0");
        assert_eq!(got.content_hash, "deadbeef");
        assert_eq!(got.pinned_by, "rick@example.com");
    }

    #[tokio::test]
    async fn get_unknown_id_returns_none() {
        let store = CompiledPolicyStore::new();
        let unknown = Uuid::new_v4();
        assert!(store.get(unknown).await.is_none());
    }

    #[tokio::test]
    async fn concurrent_inserts_do_not_deadlock() {
        let store = CompiledPolicyStore::new();
        let mut handles = Vec::new();
        for i in 0..4 {
            let store = store.clone();
            let policy = sample(&format!("allow User_{i} to read Invoice"));
            let expected_id = policy.policy_id;
            handles.push(tokio::spawn(async move {
                let got = store.insert(policy).await;
                assert_eq!(got, expected_id);
                expected_id
            }));
        }
        let mut ids = Vec::new();
        for h in handles {
            ids.push(h.await.expect("task completed"));
        }
        assert_eq!(ids.len(), 4);
        assert_eq!(store.len().await, 4);
        for id in ids {
            assert!(store.get(id).await.is_some(), "id {id} missing after race");
        }
    }
}
