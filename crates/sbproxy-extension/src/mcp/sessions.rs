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

/// Session-level risk signals used by guardrails that need memory
/// across multiple MCP requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionRisk {
    /// The session has invoked at least one tool.
    pub tool_access: bool,
    /// The session has invoked a tool classified as private-data
    /// access.
    pub private_data: bool,
    /// The session has invoked a tool classified as external
    /// communication.
    pub external_comm: bool,
}

impl SessionRisk {
    /// The Archestra "lethal trifecta": tool access plus private data
    /// plus external communication in one active session.
    pub fn is_lethal_trifecta(self) -> bool {
        self.tool_access && self.private_data && self.external_comm
    }

    fn merge(&mut self, other: SessionRisk) {
        self.tool_access |= other.tool_access;
        self.private_data |= other.private_data;
        self.external_comm |= other.external_comm;
    }
}

#[derive(Debug, Clone)]
struct SessionEntry {
    expires_at: Instant,
    risk: SessionRisk,
    /// Version requirements declared at `initialize` via
    /// `_meta.tool_requirements` (the rollout plane's session rung).
    /// `Arc` so reads hand back a cheap clone under the lock.
    tool_requirements: Option<std::sync::Arc<HashMap<String, String>>>,
}

/// In-memory session table with a sliding idle TTL.
pub struct SessionStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, SessionEntry>>,
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
        map.insert(
            id.clone(),
            SessionEntry {
                expires_at: Instant::now() + self.ttl,
                risk: SessionRisk::default(),
                tool_requirements: None,
            },
        );
        id
    }

    /// Attach the rollout plane's per-session version requirements
    /// (`{tool: semver range}`) to a live session. True on success;
    /// false when the session is unknown or expired. Renews the
    /// sliding TTL like every other successful access.
    pub fn set_tool_requirements(&self, id: &str, reqs: HashMap<String, String>) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.tool_requirements = Some(std::sync::Arc::new(reqs));
                true
            }
            Some(_) => {
                map.remove(id);
                false
            }
            None => false,
        }
    }

    /// Version requirements declared on a live session, when any.
    /// Renews the sliding TTL.
    pub fn tool_requirements(&self, id: &str) -> Option<std::sync::Arc<HashMap<String, String>>> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.tool_requirements.clone()
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// True when the id names a live session. A successful check
    /// renews the sliding TTL.
    pub fn validate(&self, id: &str) -> bool {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
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
            Some(entry) => entry.expires_at > Instant::now(),
            None => false,
        }
    }

    /// Merge risk signals into a live session and return its new
    /// aggregate state. `None` means the session is unknown or expired.
    pub fn record_risk(&self, id: &str, risk: SessionRisk) -> Option<SessionRisk> {
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > Instant::now() => {
                entry.expires_at = Instant::now() + self.ttl;
                entry.risk.merge(risk);
                Some(entry.risk)
            }
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
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

    fn prune(map: &mut HashMap<String, SessionEntry>) {
        let now = Instant::now();
        map.retain(|_, entry| entry.expires_at > now);
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

    #[test]
    fn risk_accumulates_within_one_live_session() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        let first = store
            .record_risk(
                &id,
                SessionRisk {
                    tool_access: true,
                    private_data: true,
                    external_comm: false,
                },
            )
            .expect("live session");
        assert!(!first.is_lethal_trifecta());

        let second = store
            .record_risk(
                &id,
                SessionRisk {
                    tool_access: true,
                    private_data: false,
                    external_comm: true,
                },
            )
            .expect("live session");
        assert!(second.is_lethal_trifecta());
    }

    #[test]
    fn tool_requirements_roundtrip() {
        let store = SessionStore::new(Duration::from_secs(60));
        let id = store.create();
        assert!(store.tool_requirements(&id).is_none());
        let reqs = std::collections::HashMap::from([("search".to_string(), "^1".to_string())]);
        assert!(store.set_tool_requirements(&id, reqs.clone()));
        let got = store.tool_requirements(&id).expect("live session");
        assert_eq!(got.as_ref(), &reqs);
    }

    #[test]
    fn tool_requirements_unknown_session_is_rejected() {
        let store = SessionStore::new(Duration::from_secs(60));
        assert!(!store.set_tool_requirements(
            "nope",
            std::collections::HashMap::from([("a".to_string(), "^1".to_string())])
        ));
        assert!(store.tool_requirements("nope").is_none());
    }
}
