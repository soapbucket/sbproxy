//! AI session tracking and conversation memory.
//!
//! Stores conversation history per session, allowing the AI gateway
//! to inject context from prior turns when forwarding chat requests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::types::Message;

/// A single conversation session with message history and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSession {
    /// Unique identifier for the session.
    pub session_id: String,
    /// Ordered conversation history for the session.
    pub messages: Vec<Message>,
    /// Monotonic counter value at session creation.
    pub created_at: u64,
    /// Monotonic counter value of the most recent activity. Eviction prefers the smallest value.
    pub last_active: u64,
    /// User-supplied tags and metadata associated with the session.
    pub metadata: HashMap<String, String>,
}

/// Thread-safe in-memory store for conversation sessions.
///
/// When the store is at capacity, the session with the oldest
/// `last_active` value is evicted to make room for new entries.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, ConversationSession>>,
    max_sessions: usize,
    monotonic_clock: AtomicU64,
}

impl SessionStore {
    /// Create a new store with the given capacity limit.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            monotonic_clock: AtomicU64::new(0),
        }
    }

    fn tick(&self) -> u64 {
        self.monotonic_clock.fetch_add(1, Ordering::Relaxed)
    }

    /// Return an existing session or create a fresh one.
    ///
    /// Refreshes `last_active` on every call so that frequently-accessed
    /// sessions remain in the store under capacity-based eviction.
    pub fn get_or_create(&self, session_id: &str) -> ConversationSession {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_active = self.tick();
            return session.clone();
        }

        let now = self.tick();
        let session = ConversationSession {
            session_id: session_id.to_string(),
            messages: Vec::new(),
            created_at: now,
            last_active: now,
            metadata: HashMap::new(),
        };

        // Evict the entry with the smallest last_active if at capacity.
        if sessions.len() >= self.max_sessions {
            if let Some(oldest_key) = sessions
                .iter()
                .min_by_key(|(_, s)| s.last_active)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest_key);
            }
        }

        sessions.insert(session_id.to_string(), session.clone());
        session
    }

    /// Append messages to an existing session. Creates the session if missing.
    pub fn append_messages(&self, session_id: &str, messages: &[Message]) {
        let now = self.tick();
        let mut sessions = self.sessions.lock().unwrap();

        let session =
            sessions
                .entry(session_id.to_string())
                .or_insert_with(|| ConversationSession {
                    session_id: session_id.to_string(),
                    messages: Vec::new(),
                    created_at: now,
                    last_active: now,
                    metadata: HashMap::new(),
                });

        session.messages.extend(messages.iter().cloned());
        session.last_active = now;
    }

    /// Return the message history for a session, or `None` if the session does not exist.
    ///
    /// Refreshes `last_active` on every call.
    pub fn get_history(&self, session_id: &str) -> Option<Vec<Message>> {
        let now = self.tick();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.get_mut(session_id).map(|s| {
            s.last_active = now;
            s.messages.clone()
        })
    }

    /// Remove a session entirely.
    pub fn clear(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: &str, content: &str) -> Message {
        Message {
            role: role.to_string(),
            content: serde_json::json!(content),
        }
    }

    #[test]
    fn get_or_create_returns_new_session() {
        let store = SessionStore::new(10);
        let session = store.get_or_create("s1");
        assert_eq!(session.session_id, "s1");
        assert!(session.messages.is_empty());
    }

    #[test]
    fn get_or_create_returns_existing_session() {
        let store = SessionStore::new(10);
        store.append_messages("s1", &[msg("user", "hello")]);
        let session = store.get_or_create("s1");
        assert_eq!(session.messages.len(), 1);
    }

    #[test]
    fn append_and_get_history() {
        let store = SessionStore::new(10);
        store.append_messages("s1", &[msg("user", "hi")]);
        store.append_messages("s1", &[msg("assistant", "hello")]);
        let history = store.get_history("s1").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].role, "user");
        assert_eq!(history[1].role, "assistant");
    }

    #[test]
    fn clear_removes_session() {
        let store = SessionStore::new(10);
        store.append_messages("s1", &[msg("user", "hi")]);
        store.clear("s1");
        assert!(store.get_history("s1").is_none());
    }

    #[test]
    fn evicts_oldest_when_at_capacity() {
        let store = SessionStore::new(2);
        store.get_or_create("old");
        store.get_or_create("newer");
        store.get_or_create("newest");
        assert!(store.get_history("old").is_none());
        assert!(store.get_history("newer").is_some());
        assert!(store.get_history("newest").is_some());
    }

    #[test]
    fn frequently_accessed_old_session_survives_unused_new_session() {
        // Regression: with `last_active`-based eviction, an actively-used
        // session must outlive a freshly-inserted but never-touched one.
        let store = SessionStore::new(2);
        store.get_or_create("hot");
        store.get_or_create("cold");

        // Touch "hot" so its last_active is now newer than "cold".
        let _ = store.get_or_create("hot");

        // Inserting a third session should evict "cold" (oldest last_active),
        // not "hot".
        store.get_or_create("brand_new");

        assert!(
            store.get_history("hot").is_some(),
            "hot session was evicted despite being most recently accessed"
        );
        assert!(
            store.get_history("cold").is_none(),
            "cold session was not evicted despite being least recently accessed"
        );
        assert!(store.get_history("brand_new").is_some());
    }
}
