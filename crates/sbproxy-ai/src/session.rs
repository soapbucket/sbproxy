//! AI session tracking and conversation memory.
//!
//! Stores conversation history per session, allowing the AI gateway
//! to inject context from prior turns when forwarding chat requests.
//! Also holds a generic artifact mirror for OpenAI Assistants v2
//! state (assistants, threads, runs, messages, assistant files) so
//! the dispatch path can observe stateful upstream entities without
//! introducing a second storage primitive.

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
///
/// Also holds an artifact mirror for stateful OpenAI Assistants
/// API entities (assistants, threads, runs, messages, assistant
/// files). The mirror is keyed by namespaced ID strings (e.g.
/// `assistant:asst_abc`, `thread:thread_xyz/runs/run_abc`) and
/// values are the upstream JSON bodies. Eviction does not apply
/// to artifacts; operators can clear individual entries via
/// `delete_artifact` or wholesale via `clear_artifacts`.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, ConversationSession>>,
    max_sessions: usize,
    monotonic_clock: AtomicU64,
    artifacts: Mutex<HashMap<String, serde_json::Value>>,
}

impl SessionStore {
    /// Create a new store with the given capacity limit.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            monotonic_clock: AtomicU64::new(0),
            artifacts: Mutex::new(HashMap::new()),
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

    // --- Assistants / Threads artifact mirror (Phase 3b) ---

    /// Store an arbitrary artifact under a namespaced key. The key
    /// is the caller's responsibility (see the typed helpers below
    /// for the standard namespacing).
    pub fn put_artifact(&self, key: &str, value: serde_json::Value) {
        let mut artifacts = self.artifacts.lock().unwrap();
        artifacts.insert(key.to_string(), value);
    }

    /// Fetch an artifact by namespaced key. Returns `None` when the
    /// key is absent.
    pub fn get_artifact(&self, key: &str) -> Option<serde_json::Value> {
        let artifacts = self.artifacts.lock().unwrap();
        artifacts.get(key).cloned()
    }

    /// Remove an artifact by namespaced key.
    pub fn delete_artifact(&self, key: &str) {
        let mut artifacts = self.artifacts.lock().unwrap();
        artifacts.remove(key);
    }

    /// Drop every artifact. Conversation sessions are unaffected.
    pub fn clear_artifacts(&self) {
        let mut artifacts = self.artifacts.lock().unwrap();
        artifacts.clear();
    }

    /// Mirror an OpenAI Assistants v2 assistant entity. Keyed by
    /// `assistant:{assistant_id}` so the lookup is O(1).
    pub fn put_assistant(&self, assistant_id: &str, body: serde_json::Value) {
        self.put_artifact(&format!("assistant:{}", assistant_id), body);
    }

    /// Fetch a mirrored assistant by ID.
    pub fn get_assistant(&self, assistant_id: &str) -> Option<serde_json::Value> {
        self.get_artifact(&format!("assistant:{}", assistant_id))
    }

    /// Mirror an assistant file entry. Keyed by
    /// `assistant:{assistant_id}/files/{file_id}`.
    pub fn put_assistant_file(&self, assistant_id: &str, file_id: &str, body: serde_json::Value) {
        self.put_artifact(
            &format!("assistant:{}/files/{}", assistant_id, file_id),
            body,
        );
    }

    /// Fetch a mirrored assistant file.
    pub fn get_assistant_file(
        &self,
        assistant_id: &str,
        file_id: &str,
    ) -> Option<serde_json::Value> {
        self.get_artifact(&format!("assistant:{}/files/{}", assistant_id, file_id))
    }

    /// Mirror a thread entity. Keyed by `thread:{thread_id}`.
    pub fn put_thread(&self, thread_id: &str, body: serde_json::Value) {
        self.put_artifact(&format!("thread:{}", thread_id), body);
    }

    /// Fetch a mirrored thread by ID.
    pub fn get_thread(&self, thread_id: &str) -> Option<serde_json::Value> {
        self.get_artifact(&format!("thread:{}", thread_id))
    }

    /// Append a message to a thread's mirror. Messages are stored in
    /// arrival order under `thread:{thread_id}/messages` as a JSON
    /// array.
    pub fn append_thread_message(&self, thread_id: &str, message: serde_json::Value) {
        let key = format!("thread:{}/messages", thread_id);
        let mut artifacts = self.artifacts.lock().unwrap();
        let entry = artifacts
            .entry(key)
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let serde_json::Value::Array(list) = entry {
            list.push(message);
        }
    }

    /// Read the mirrored message list for a thread.
    pub fn get_thread_messages(&self, thread_id: &str) -> Option<Vec<serde_json::Value>> {
        let artifacts = self.artifacts.lock().unwrap();
        artifacts
            .get(&format!("thread:{}/messages", thread_id))
            .and_then(|v| v.as_array().cloned())
    }

    /// Mirror a thread-run entity. Keyed by
    /// `thread:{thread_id}/runs/{run_id}`.
    pub fn put_run(&self, thread_id: &str, run_id: &str, body: serde_json::Value) {
        self.put_artifact(&format!("thread:{}/runs/{}", thread_id, run_id), body);
    }

    /// Fetch a mirrored thread-run.
    pub fn get_run(&self, thread_id: &str, run_id: &str) -> Option<serde_json::Value> {
        self.get_artifact(&format!("thread:{}/runs/{}", thread_id, run_id))
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

    // --- Artifact mirror (Phase 3b) ---

    #[test]
    fn put_and_get_assistant_round_trips_json_body() {
        let store = SessionStore::new(16);
        let body = serde_json::json!({
            "id": "asst_abc",
            "object": "assistant",
            "model": "gpt-4o",
            "instructions": "You are helpful.",
        });
        store.put_assistant("asst_abc", body.clone());
        assert_eq!(store.get_assistant("asst_abc"), Some(body));
        assert!(store.get_assistant("asst_unknown").is_none());
    }

    #[test]
    fn put_assistant_file_uses_namespaced_key() {
        let store = SessionStore::new(16);
        let file = serde_json::json!({"id": "file_xyz", "assistant_id": "asst_abc"});
        store.put_assistant_file("asst_abc", "file_xyz", file.clone());
        assert_eq!(store.get_assistant_file("asst_abc", "file_xyz"), Some(file));
        // Unrelated assistant and file return None.
        assert!(store.get_assistant_file("asst_abc", "file_other").is_none());
        assert!(store.get_assistant_file("asst_other", "file_xyz").is_none());
    }

    #[test]
    fn put_and_get_thread_and_run_artifacts() {
        let store = SessionStore::new(16);
        let thread = serde_json::json!({"id": "thread_t1", "object": "thread"});
        let run = serde_json::json!({"id": "run_r1", "status": "completed"});
        store.put_thread("thread_t1", thread.clone());
        store.put_run("thread_t1", "run_r1", run.clone());
        assert_eq!(store.get_thread("thread_t1"), Some(thread));
        assert_eq!(store.get_run("thread_t1", "run_r1"), Some(run));
        // Distinct thread or run IDs return None.
        assert!(store.get_thread("thread_t2").is_none());
        assert!(store.get_run("thread_t1", "run_other").is_none());
    }

    #[test]
    fn append_thread_message_preserves_order() {
        let store = SessionStore::new(16);
        let m1 = serde_json::json!({"id": "msg_1", "role": "user", "content": "hi"});
        let m2 = serde_json::json!({"id": "msg_2", "role": "assistant", "content": "hello"});
        let m3 = serde_json::json!({"id": "msg_3", "role": "user", "content": "thanks"});
        store.append_thread_message("thread_t1", m1.clone());
        store.append_thread_message("thread_t1", m2.clone());
        store.append_thread_message("thread_t1", m3.clone());
        let messages = store.get_thread_messages("thread_t1").unwrap();
        assert_eq!(messages, vec![m1, m2, m3]);
    }

    #[test]
    fn delete_artifact_drops_only_the_named_entry() {
        let store = SessionStore::new(16);
        store.put_assistant("asst_a", serde_json::json!({"id": "asst_a"}));
        store.put_assistant("asst_b", serde_json::json!({"id": "asst_b"}));
        store.delete_artifact("assistant:asst_a");
        assert!(store.get_assistant("asst_a").is_none());
        assert!(store.get_assistant("asst_b").is_some());
    }

    #[test]
    fn clear_artifacts_does_not_affect_conversation_sessions() {
        let store = SessionStore::new(16);
        // Stuff both stores.
        store.append_messages("s1", &[msg("user", "hello")]);
        store.put_assistant("asst_a", serde_json::json!({"id": "asst_a"}));
        // Wipe artifacts.
        store.clear_artifacts();
        assert!(store.get_assistant("asst_a").is_none());
        // Conversation history is untouched.
        let history = store.get_history("s1").unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn put_artifact_generic_round_trips() {
        let store = SessionStore::new(16);
        let value = serde_json::json!({"arbitrary": ["data", 42]});
        store.put_artifact("custom:key", value.clone());
        assert_eq!(store.get_artifact("custom:key"), Some(value));
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
