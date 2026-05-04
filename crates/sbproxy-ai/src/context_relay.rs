//! Context relay: session continuity across provider/account rotation.
//!
//! When the proxy rotates between providers (e.g. OpenAI -> Anthropic) or
//! between API keys, the conversation history must be carried along.
//! `ContextRelay` is a lightweight thread-safe store for that history.

use std::collections::HashMap;
use std::sync::Mutex;

/// Thread-safe store that maps session IDs to their conversation messages.
///
/// Messages are stored as raw JSON values so that provider-specific formats
/// can be preserved without deserialization overhead.
pub struct ContextRelay {
    /// session_id -> conversation messages
    sessions: Mutex<HashMap<String, Vec<serde_json::Value>>>,
}

impl ContextRelay {
    /// Create a new, empty `ContextRelay`.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Persist messages for `session_id`, replacing any prior history.
    pub fn store_messages(&self, session_id: &str, messages: Vec<serde_json::Value>) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.to_string(), messages);
    }

    /// Retrieve the message history for `session_id`.
    ///
    /// Returns `None` when no history has been stored for that ID.
    pub fn get_messages(&self, session_id: &str) -> Option<Vec<serde_json::Value>> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    /// Delete the stored history for `session_id`.
    pub fn clear_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }

    /// Return the number of sessions currently stored.
    pub fn session_count(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.len()
    }
}

impl Default for ContextRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_messages() -> Vec<serde_json::Value> {
        vec![
            json!({"role": "user", "content": "Hello"}),
            json!({"role": "assistant", "content": "Hi there!"}),
        ]
    }

    #[test]
    fn store_and_get_roundtrip() {
        let relay = ContextRelay::new();
        relay.store_messages("sess-1", make_messages());
        let retrieved = relay.get_messages("sess-1").expect("should have messages");
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0]["role"], "user");
    }

    #[test]
    fn missing_session_returns_none() {
        let relay = ContextRelay::new();
        assert!(relay.get_messages("nonexistent").is_none());
    }

    #[test]
    fn clear_session_removes_history() {
        let relay = ContextRelay::new();
        relay.store_messages("sess-2", make_messages());
        relay.clear_session("sess-2");
        assert!(relay.get_messages("sess-2").is_none());
    }

    #[test]
    fn clear_nonexistent_session_is_noop() {
        let relay = ContextRelay::new();
        relay.clear_session("ghost-session"); // should not panic
    }

    #[test]
    fn session_count_tracks_inserts_and_clears() {
        let relay = ContextRelay::new();
        assert_eq!(relay.session_count(), 0);
        relay.store_messages("a", make_messages());
        assert_eq!(relay.session_count(), 1);
        relay.store_messages("b", make_messages());
        assert_eq!(relay.session_count(), 2);
        relay.clear_session("a");
        assert_eq!(relay.session_count(), 1);
    }

    #[test]
    fn storing_again_replaces_history() {
        let relay = ContextRelay::new();
        relay.store_messages("s", make_messages());
        relay.store_messages("s", vec![json!({"role": "user", "content": "new"})]);
        let msgs = relay.get_messages("s").unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["content"], "new");
    }

    #[test]
    fn multiple_independent_sessions() {
        let relay = ContextRelay::new();
        relay.store_messages("s1", vec![json!({"role": "user", "content": "session 1"})]);
        relay.store_messages("s2", vec![json!({"role": "user", "content": "session 2"})]);
        let s1 = relay.get_messages("s1").unwrap();
        let s2 = relay.get_messages("s2").unwrap();
        assert_eq!(s1[0]["content"], "session 1");
        assert_eq!(s2[0]["content"], "session 2");
    }
}
