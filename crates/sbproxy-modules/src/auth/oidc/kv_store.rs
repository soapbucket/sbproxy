//! WOR-892 follow-up: KV-backed implementation of
//! [`super::store::SessionStore`].
//!
//! PR #359 shipped the `SessionStore` trait plus an in-memory
//! reference impl. This module wraps any
//! [`sbproxy_platform::storage::KVStore`] (redb, file, redis,
//! memory) as a `SessionStore` so an operator picks the backend at
//! deploy time without the OIDC layer hard-coding redb.
//!
//! The redb backend is the documented default for production
//! (single-process embedded ACID KV, no operational overhead); the
//! redis backend is for multi-replica deployments where every
//! instance must agree on revocation state immediately. Both reach
//! the OIDC layer through this one adapter.
//!
//! Three design notes worth pinning:
//!
//! 1. **Per-tenant key prefix.** The wrapper takes a `prefix`
//!    (operator-supplied) and namespaces every key as
//!    `<prefix>/oidc/sess/<session_id>`. Multi-tenant operators
//!    share one KV instance across origins this way without ever
//!    being able to read each other's session ids.
//! 2. **JSON, not CBOR.** The cookie path uses CBOR because cookie
//!    size matters. The KV path uses JSON because operator-side
//!    debugging (a stale session, a poisoned record, an audit
//!    trail) wants human-readable inspection over `redb-cli` or
//!    `redis-cli`. The cost difference is irrelevant server-side.
//! 3. **`evict_idle` is O(N).** It pulls every key under the
//!    prefix, decodes, checks `last_seen_unix`, and deletes the
//!    stale ones. Acceptable for the expected scale (tens of
//!    thousands of live sessions); a backend-specific bulk-delete
//!    is a later refinement.

use std::sync::Arc;

use anyhow::{Context, Result};
use sbproxy_platform::storage::KVStore;

use super::store::{SessionRecord, SessionStore};

/// Wrap any [`KVStore`] as a [`SessionStore`]. Operator picks the
/// backend (redb / file / redis / memory) when constructing the
/// `KVStore`; this layer is backend-agnostic.
pub struct KvSessionStore {
    store: Arc<dyn KVStore>,
    prefix: String,
}

impl KvSessionStore {
    /// Construct over a `KVStore` instance. The `prefix` is folded
    /// into every key so a multi-tenant operator can share one
    /// backing store across origins without one origin enumerating
    /// another's session ids.
    pub fn new(store: Arc<dyn KVStore>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
        }
    }

    fn key(&self, session_id: &str) -> String {
        format!("{}/oidc/sess/{}", self.prefix, session_id)
    }

    fn scan_root(&self) -> String {
        format!("{}/oidc/sess/", self.prefix)
    }
}

impl SessionStore for KvSessionStore {
    fn put(&self, session_id: &str, record: SessionRecord) -> Result<()> {
        let bytes = serde_json::to_vec(&record).context("encode session record")?;
        self.store
            .put(self.key(session_id).as_bytes(), &bytes)
            .context("kv put session")
    }

    fn get(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        let raw = self
            .store
            .get(self.key(session_id).as_bytes())
            .context("kv get session")?;
        let Some(bytes) = raw else {
            return Ok(None);
        };
        let decoded: SessionRecord =
            serde_json::from_slice(&bytes).context("decode session record")?;
        Ok(Some(decoded))
    }

    fn touch(&self, session_id: &str, now_unix: u64) -> Result<()> {
        // Read-modify-write. The KVStore trait does not expose a
        // compare-and-swap; for the common case (one process per
        // session_id at a time, since each session is one user's
        // cookie) the race is benign: two interleaved touches
        // converge to the larger `now_unix`. A future revision can
        // hoist this into the trait if it matters.
        let Some(mut record) = self.get(session_id)? else {
            return Ok(());
        };
        record.last_seen_unix = now_unix;
        self.put(session_id, record)
    }

    fn delete(&self, session_id: &str) -> Result<()> {
        self.store
            .delete(self.key(session_id).as_bytes())
            .context("kv delete session")
    }

    fn evict_idle(&self, now_unix: u64, idle_secs: u64) -> Result<usize> {
        let root = self.scan_root();
        let pairs = self
            .store
            .scan_prefix(root.as_bytes())
            .context("kv scan sessions")?;
        let mut evicted = 0usize;
        for (key, value) in pairs {
            let Ok(record) = serde_json::from_slice::<SessionRecord>(&value) else {
                // A corrupted record is itself "stale" by operator
                // intent; an undecodable session can never be served
                // to anyone, so dropping it is the safe move.
                self.store.delete(&key).ok();
                evicted += 1;
                continue;
            };
            if record.is_idle(now_unix, idle_secs) {
                self.store.delete(&key).ok();
                evicted += 1;
            }
        }
        Ok(evicted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::storage::MemoryKVStore;

    use super::super::session::SessionClaims;

    fn store() -> KvSessionStore {
        KvSessionStore::new(Arc::new(MemoryKVStore::new(1024)), "tenant-A")
    }

    fn sample_claims(sub: &str, iat: u64) -> SessionClaims {
        SessionClaims {
            sub: sub.to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: "sbproxy".to_string(),
            iat,
            exp: iat + 3600,
            trust_headers: Vec::new(),
        }
    }

    fn sample_record(sub: &str, iat: u64) -> SessionRecord {
        SessionRecord::new(sample_claims(sub, iat), Some("rt".into()), iat)
    }

    #[test]
    fn put_then_get_round_trips_through_kv() {
        let s = store();
        let record = sample_record("user-42", 1_000);
        s.put("sess-A", record.clone()).unwrap();
        assert_eq!(s.get("sess-A").unwrap(), Some(record));
    }

    #[test]
    fn get_returns_none_for_unknown_session_id() {
        let s = store();
        assert!(s.get("nope").unwrap().is_none());
    }

    #[test]
    fn touch_bumps_last_seen_only() {
        let s = store();
        s.put("sess-A", sample_record("user-42", 1_000)).unwrap();
        s.touch("sess-A", 5_000).unwrap();
        let fetched = s.get("sess-A").unwrap().unwrap();
        assert_eq!(fetched.last_seen_unix, 5_000);
        assert_eq!(fetched.claims.sub, "user-42");
    }

    #[test]
    fn touch_on_missing_id_is_silent_noop() {
        let s = store();
        s.touch("never", 10).unwrap();
        assert!(s.get("never").unwrap().is_none());
    }

    #[test]
    fn delete_removes_session() {
        let s = store();
        s.put("sess-A", sample_record("user-42", 1_000)).unwrap();
        s.delete("sess-A").unwrap();
        assert!(s.get("sess-A").unwrap().is_none());
    }

    #[test]
    fn delete_is_idempotent_on_unknown_session() {
        let s = store();
        s.delete("never").unwrap();
        s.delete("never").unwrap();
    }

    #[test]
    fn keys_are_prefixed_for_tenant_isolation() {
        let backing = Arc::new(MemoryKVStore::new(1024));
        let tenant_a = KvSessionStore::new(Arc::clone(&backing) as Arc<dyn KVStore>, "tenant-A");
        let tenant_b = KvSessionStore::new(Arc::clone(&backing) as Arc<dyn KVStore>, "tenant-B");
        tenant_a
            .put("same-id", sample_record("alice", 1_000))
            .unwrap();
        tenant_b
            .put("same-id", sample_record("bob", 1_000))
            .unwrap();
        assert_eq!(
            tenant_a.get("same-id").unwrap().unwrap().claims.sub,
            "alice"
        );
        assert_eq!(tenant_b.get("same-id").unwrap().unwrap().claims.sub, "bob");
    }

    #[test]
    fn evict_idle_drops_stale_records_only() {
        let s = store();
        s.put("fresh", sample_record("u1", 9_950)).unwrap();
        s.put("stale", sample_record("u2", 5_000)).unwrap();
        let n = s.evict_idle(10_000, 100).unwrap();
        assert_eq!(n, 1);
        assert!(s.get("fresh").unwrap().is_some());
        assert!(s.get("stale").unwrap().is_none());
    }

    #[test]
    fn evict_idle_drops_corrupted_records_too() {
        // Backing store directly contains a garbage value under the
        // expected key. evict_idle treats undecodable records as
        // stale: they can never be served, so they must be cleaned.
        let backing = Arc::new(MemoryKVStore::new(1024));
        backing
            .put(b"tenant-A/oidc/sess/garbage", b"not valid json")
            .unwrap();
        let s = KvSessionStore::new(backing as Arc<dyn KVStore>, "tenant-A");
        let n = s.evict_idle(10_000, 100).unwrap();
        assert_eq!(n, 1);
        assert!(s.get("garbage").unwrap().is_none());
    }

    #[test]
    fn evict_idle_on_empty_store_returns_zero() {
        let s = store();
        assert_eq!(s.evict_idle(10_000, 100).unwrap(), 0);
    }

    #[test]
    fn put_overwrites_existing() {
        let s = store();
        s.put("sess-A", sample_record("original", 1_000)).unwrap();
        s.put("sess-A", sample_record("replaced", 2_000)).unwrap();
        let fetched = s.get("sess-A").unwrap().unwrap();
        assert_eq!(fetched.claims.sub, "replaced");
    }
}
