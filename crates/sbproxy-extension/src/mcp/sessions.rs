//! MCP session store for the streamable HTTP transport (WOR-1642).
//!
//! The 2025-06-18 revision lets a server assign a session id during
//! `initialize` via the `Mcp-Session-Id` header; the client must then
//! carry the id on every later request, `DELETE` ends the session,
//! and an unknown or expired id gets 404 so the client knows to
//! re-initialize.
//!
//! The store is in-memory with a sliding idle TTL: sessions are a
//! transport-affinity concept, not durable state, and a proxy restart
//! invalidating them is exactly the 404-then-reinitialize flow the
//! spec prescribes. Expired entries are pruned opportunistically on
//! access, so the map never grows past the live-session set plus the
//! not-yet-touched expired tail.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory session table with a sliding idle TTL.
pub struct SessionStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, Instant>>,
}

impl SessionStore {
    /// Create a store whose sessions expire after `ttl` of inactivity.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session and return its id (UUID v4, which
    /// satisfies the spec's visible-ASCII requirement and is not
    /// guessable).
    pub fn create(&self) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);
        map.insert(id.clone(), Instant::now() + self.ttl);
        id
    }

    /// True when the id names a live session. A successful check
    /// renews the sliding TTL.
    pub fn validate(&self, id: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(expiry) if *expiry > Instant::now() => {
                *expiry = Instant::now() + self.ttl;
                true
            }
            Some(_) => {
                map.remove(id);
                false
            }
            None => false,
        }
    }

    /// End a session. True when the id named a live session.
    pub fn end(&self, id: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.remove(id) {
            Some(expiry) => expiry > Instant::now(),
            None => false,
        }
    }

    /// Live-session count (post-prune), for tests and introspection.
    pub fn len(&self) -> usize {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::prune(&mut map);
        map.len()
    }

    /// True when no live sessions exist.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn prune(map: &mut HashMap<String, Instant>) {
        let now = Instant::now();
        map.retain(|_, expiry| *expiry > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_validate_then_end() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        assert!(store.validate(&id));
        assert!(store.end(&id));
        assert!(!store.validate(&id), "ended session must not validate");
        assert!(!store.end(&id), "double end is a miss");
    }

    #[test]
    fn unknown_id_is_invalid() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.validate("nope"));
        assert!(!store.end("nope"));
    }

    #[test]
    fn expired_session_is_invalid_and_pruned() {
        let store = SessionStore::new(Duration::from_millis(10));
        let id = store.create();
        std::thread::sleep(Duration::from_millis(30));
        assert!(!store.validate(&id));
        assert!(store.is_empty(), "expired entries must be pruned");
    }

    #[test]
    fn validate_renews_the_sliding_ttl() {
        let store = SessionStore::new(Duration::from_millis(80));
        let id = store.create();
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(40));
            assert!(store.validate(&id), "touches inside the ttl must renew");
        }
    }

    #[test]
    fn ids_are_unique_and_ascii() {
        let store = SessionStore::new(Duration::from_secs(60));
        let a = store.create();
        let b = store.create();
        assert_ne!(a, b);
        assert!(a.is_ascii());
        assert_eq!(store.len(), 2);
    }
}
