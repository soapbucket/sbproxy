//! WOR-892 follow-up: optional server-side session store for the
//! OIDC auth provider.
//!
//! By default sbproxy stores all session state inside the sealed
//! cookie itself (`SessionClaims` → AEAD → base64url). That is
//! stateless and survives proxy restarts; it also means there is no
//! place to revoke a single user's session without rotating the
//! cookie secret (which logs out every user).
//!
//! This module adds an OPTIONAL server-side store with two
//! capabilities:
//!
//! 1. **Server-side revocation.** Operator can revoke
//!    `session_id` X without touching anyone else's cookies.
//! 2. **Refresh-token persistence across restarts.** With cookie-
//!    only state the refresh token would have to live inside the
//!    cookie too (large + leakable). The store lets the cookie carry
//!    only the opaque `session_id` while the refresh token lives
//!    server-side and is never sent to the user-agent.
//!
//! The store API is a small trait so the live implementation (redb)
//! and the test implementation (in-memory) can swap freely. The
//! redb-backed implementation will land in `sbproxy-core` (close to
//! where the session is read on the request path) once the
//! request-path wiring lands; this PR ships the trait, the typed
//! record, the in-memory implementation, and the eviction policy.
//!
//! Three deliberate boundaries kept this PR small:
//!
//! 1. No request-path wiring. The trait is reachable; the call into
//!    it from `handle_oidc_callback` and the request-time session
//!    check land in `sbproxy-core` next.
//! 2. No redb impl in this crate. `sbproxy-modules` should not carry
//!    a redb dep just for this; the redb impl lives next to the
//!    other persistence wiring in `sbproxy-core`.
//! 3. No `async`. Session-store reads happen synchronously on the
//!    request hot path; the redb impl is sync-internally and the
//!    in-memory impl trivially so. Anything that genuinely needs
//!    async (a Redis-backed store, say) wraps the sync trait.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::session::SessionClaims;

/// One server-side session record. Carries the same `SessionClaims`
/// the cookie does, plus the optional refresh token that should
/// never leave the server, plus a wall-clock `last_seen_unix` so the
/// store can evict idle sessions on a schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Claims as projected from the ID token at login time. Same
    /// shape that the cookie carries.
    pub claims: SessionClaims,
    /// Refresh token from the IdP, when one was issued. Lives only
    /// here; the cookie never carries it.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Wall-clock unix seconds of the last request that referenced
    /// this session. Updated by `touch`; consulted by `evict_idle`.
    pub last_seen_unix: u64,
}

impl SessionRecord {
    /// Build a fresh record from login-time claims + optional refresh.
    pub fn new(claims: SessionClaims, refresh_token: Option<String>, now_unix: u64) -> Self {
        Self {
            claims,
            refresh_token,
            last_seen_unix: now_unix,
        }
    }

    /// True when `last_seen_unix` is older than `now - idle_secs`.
    /// Driven by an external clock so tests stay deterministic.
    pub fn is_idle(&self, now_unix: u64, idle_secs: u64) -> bool {
        now_unix.saturating_sub(self.last_seen_unix) > idle_secs
    }
}

/// Server-side session store. Synchronous on purpose — the redb
/// backend is sync-internal and the per-request lookup is on the
/// hot path. An async backend (Redis, DynamoDB) wraps this trait.
pub trait SessionStore: Send + Sync {
    /// Insert (or overwrite) a session record under `session_id`.
    fn put(&self, session_id: &str, record: SessionRecord) -> Result<()>;
    /// Fetch a session by id. Returns `Ok(None)` when not present;
    /// the caller treats that as "unauthenticated" rather than as
    /// an error.
    fn get(&self, session_id: &str) -> Result<Option<SessionRecord>>;
    /// Bump `last_seen_unix` to `now_unix` for `session_id`. No-op
    /// when the id is not present; useful for the request hot path
    /// where the `get` already happened and we just need to record
    /// that the session is still in use.
    fn touch(&self, session_id: &str, now_unix: u64) -> Result<()>;
    /// Delete a session. Used by `/oidc/logout` and by operator
    /// revocation. Idempotent.
    fn delete(&self, session_id: &str) -> Result<()>;
    /// Drop every record whose `last_seen_unix` is older than
    /// `now_unix - idle_secs`. Returns the count evicted. Called on
    /// a background timer; backend-specific implementations may
    /// override with a more efficient bulk delete.
    fn evict_idle(&self, now_unix: u64, idle_secs: u64) -> Result<usize>;
}

/// In-memory session store. Used in tests and as a dev-loop default;
/// loses state across restarts, by design.
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    inner: Mutex<HashMap<String, SessionRecord>>,
}

impl InMemorySessionStore {
    /// Build an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for InMemorySessionStore {
    fn put(&self, session_id: &str, record: SessionRecord) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("session store mutex poisoned: {e}"))?;
        guard.insert(session_id.to_string(), record);
        Ok(())
    }

    fn get(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("session store mutex poisoned: {e}"))?;
        Ok(guard.get(session_id).cloned())
    }

    fn touch(&self, session_id: &str, now_unix: u64) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("session store mutex poisoned: {e}"))?;
        if let Some(record) = guard.get_mut(session_id) {
            record.last_seen_unix = now_unix;
        }
        Ok(())
    }

    fn delete(&self, session_id: &str) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("session store mutex poisoned: {e}"))?;
        guard.remove(session_id);
        Ok(())
    }

    fn evict_idle(&self, now_unix: u64, idle_secs: u64) -> Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("session store mutex poisoned: {e}"))?;
        let before = guard.len();
        guard.retain(|_, record| !record.is_idle(now_unix, idle_secs));
        Ok(before - guard.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(sub: &str, iat: u64) -> SessionClaims {
        SessionClaims {
            sub: sub.to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: "sbproxy".to_string(),
            iat,
            exp: iat + 3600,
        }
    }

    fn sample_record(sub: &str, iat: u64) -> SessionRecord {
        SessionRecord::new(sample_claims(sub, iat), Some("rt-value".into()), iat)
    }

    #[test]
    fn put_then_get_returns_inserted_record() {
        let store = InMemorySessionStore::new();
        let record = sample_record("user-42", 1_000);
        store.put("sess-A", record.clone()).unwrap();
        assert_eq!(store.get("sess-A").unwrap(), Some(record));
    }

    #[test]
    fn get_returns_none_for_unknown_session() {
        let store = InMemorySessionStore::new();
        assert!(store.get("nope").unwrap().is_none());
    }

    #[test]
    fn touch_bumps_last_seen_only() {
        let store = InMemorySessionStore::new();
        let record = sample_record("user-42", 1_000);
        store.put("sess-A", record.clone()).unwrap();
        store.touch("sess-A", 2_000).unwrap();
        let fetched = store.get("sess-A").unwrap().unwrap();
        assert_eq!(fetched.last_seen_unix, 2_000);
        assert_eq!(fetched.claims, record.claims);
        assert_eq!(fetched.refresh_token, record.refresh_token);
    }

    #[test]
    fn touch_on_missing_id_is_silent_noop() {
        let store = InMemorySessionStore::new();
        store.touch("never-existed", 5_000).unwrap();
        assert!(store.get("never-existed").unwrap().is_none());
    }

    #[test]
    fn delete_removes_only_named_session() {
        let store = InMemorySessionStore::new();
        store.put("sess-A", sample_record("user-A", 1_000)).unwrap();
        store.put("sess-B", sample_record("user-B", 1_000)).unwrap();
        store.delete("sess-A").unwrap();
        assert!(store.get("sess-A").unwrap().is_none());
        assert!(store.get("sess-B").unwrap().is_some());
    }

    #[test]
    fn delete_is_idempotent_for_unknown_session() {
        let store = InMemorySessionStore::new();
        store.delete("never-existed").unwrap();
        store.delete("never-existed").unwrap();
    }

    #[test]
    fn evict_idle_drops_only_stale_sessions() {
        let store = InMemorySessionStore::new();
        // `fresh` was last seen 50s ago at now=10_000, `stale` 5000s
        // ago. With idle_secs=100 only the second should drop.
        store
            .put("fresh", sample_record("user-fresh", 9_950))
            .unwrap();
        store
            .put("stale", sample_record("user-stale", 5_000))
            .unwrap();
        let evicted = store.evict_idle(10_000, 100).unwrap();
        assert_eq!(evicted, 1);
        assert!(store.get("fresh").unwrap().is_some());
        assert!(store.get("stale").unwrap().is_none());
    }

    #[test]
    fn is_idle_returns_false_within_window() {
        let record = sample_record("u", 1_000);
        assert!(!record.is_idle(1_050, 100));
    }

    #[test]
    fn is_idle_returns_true_past_window() {
        let record = sample_record("u", 1_000);
        assert!(record.is_idle(1_200, 100));
    }

    #[test]
    fn is_idle_handles_now_before_last_seen_without_panic() {
        // Wall-clock skew can produce a `now` smaller than
        // `last_seen_unix` (NTP step back, container migration).
        // saturating_sub must NOT panic, and the record must be
        // treated as fresh, not as billion-seconds-old idle.
        let record = sample_record("u", 5_000);
        assert!(!record.is_idle(1_000, 100));
    }

    #[test]
    fn put_overwrites_existing_session() {
        let store = InMemorySessionStore::new();
        store
            .put("sess-A", sample_record("user-original", 1_000))
            .unwrap();
        store
            .put("sess-A", sample_record("user-replaced", 2_000))
            .unwrap();
        let fetched = store.get("sess-A").unwrap().unwrap();
        assert_eq!(fetched.claims.sub, "user-replaced");
    }

    #[test]
    fn evict_idle_on_empty_store_returns_zero() {
        let store = InMemorySessionStore::new();
        assert_eq!(store.evict_idle(10_000, 100).unwrap(), 0);
    }
}
