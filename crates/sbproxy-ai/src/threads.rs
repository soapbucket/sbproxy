//! Thread and message storage for the Assistants API.
//!
//! Provides an in-memory store for threads and their messages, mirroring the
//! OpenAI Assistants API data model.  This is used for local caching and
//! session continuity; persistent storage should be layered on top.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("{}_{}", prefix, COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// An Assistants API thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    /// Unique thread identifier (e.g. `thread_abc123`).
    pub id: String,
    /// ISO-8601 string of when the thread was created.
    pub created_at: String,
    /// Arbitrary key-value metadata attached to the thread.
    pub metadata: HashMap<String, String>,
}

/// A message within a thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMessage {
    /// Unique message identifier.
    pub id: String,
    /// ID of the thread this message belongs to.
    pub thread_id: String,
    /// Role of the author (`"user"` or `"assistant"`).
    pub role: String,
    /// Text content of the message.
    pub content: String,
    /// ISO-8601 string of when the message was created.
    pub created_at: String,
}

/// Thread-safe in-memory store for threads and messages.
///
/// Threads and messages are stored separately keyed by their IDs.
pub struct ThreadStore {
    threads: Mutex<HashMap<String, Thread>>,
    messages: Mutex<HashMap<String, Vec<ThreadMessage>>>,
}

impl ThreadStore {
    /// Create an empty thread store.
    pub fn new() -> Self {
        Self {
            threads: Mutex::new(HashMap::new()),
            messages: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new thread with optional metadata and return it.
    pub fn create_thread(&self, metadata: HashMap<String, String>) -> Thread {
        let thread = Thread {
            id: new_id("thread"),
            created_at: chrono_like_now(),
            metadata,
        };
        let mut threads = self.threads.lock().expect("lock poisoned");
        threads.insert(thread.id.clone(), thread.clone());
        thread
    }

    /// Retrieve a thread by ID. Returns `None` if not found.
    pub fn get_thread(&self, id: &str) -> Option<Thread> {
        let threads = self.threads.lock().expect("lock poisoned");
        threads.get(id).cloned()
    }

    /// Append a message to a thread. Returns an error if the thread does not exist.
    pub fn add_message(&self, thread_id: &str, role: &str, content: &str) -> Result<ThreadMessage> {
        {
            let threads = self.threads.lock().expect("lock poisoned");
            if !threads.contains_key(thread_id) {
                return Err(anyhow!("thread '{}' not found", thread_id));
            }
        }

        let msg = ThreadMessage {
            id: new_id("msg"),
            thread_id: thread_id.to_string(),
            role: role.to_string(),
            content: content.to_string(),
            created_at: chrono_like_now(),
        };

        let mut messages = self.messages.lock().expect("lock poisoned");
        messages
            .entry(thread_id.to_string())
            .or_default()
            .push(msg.clone());

        Ok(msg)
    }

    /// Return all messages for a thread in insertion order.
    ///
    /// Returns an empty vec if the thread exists but has no messages, or if the
    /// thread ID is unknown.
    pub fn list_messages(&self, thread_id: &str) -> Vec<ThreadMessage> {
        let messages = self.messages.lock().expect("lock poisoned");
        messages.get(thread_id).cloned().unwrap_or_default()
    }
}

impl Default for ThreadStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- Helpers ---

/// Returns the current time as a simple ISO-8601-like string without pulling
/// in the `chrono` crate (which is not in the workspace dependencies).
fn chrono_like_now() -> String {
    format!("{}s", now_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_thread() {
        let store = ThreadStore::new();
        let mut meta = HashMap::new();
        meta.insert("project".to_string(), "demo".to_string());

        let thread = store.create_thread(meta.clone());
        assert!(!thread.id.is_empty());
        assert_eq!(
            thread.metadata.get("project").map(|s| s.as_str()),
            Some("demo")
        );

        let got = store.get_thread(&thread.id).expect("thread should exist");
        assert_eq!(got.id, thread.id);
    }

    #[test]
    fn get_nonexistent_thread_returns_none() {
        let store = ThreadStore::new();
        assert!(store.get_thread("thread_missing").is_none());
    }

    #[test]
    fn add_and_list_messages() {
        let store = ThreadStore::new();
        let thread = store.create_thread(HashMap::new());

        let m1 = store.add_message(&thread.id, "user", "Hello").unwrap();
        let m2 = store
            .add_message(&thread.id, "assistant", "Hi there!")
            .unwrap();

        assert_eq!(m1.role, "user");
        assert_eq!(m1.content, "Hello");
        assert_eq!(m2.role, "assistant");

        let msgs = store.list_messages(&thread.id);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "Hello");
        assert_eq!(msgs[1].content, "Hi there!");
    }

    #[test]
    fn add_message_to_missing_thread_returns_error() {
        let store = ThreadStore::new();
        let result = store.add_message("thread_missing", "user", "hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn list_messages_for_empty_thread() {
        let store = ThreadStore::new();
        let thread = store.create_thread(HashMap::new());
        let msgs = store.list_messages(&thread.id);
        assert!(msgs.is_empty());
    }

    #[test]
    fn multiple_threads_are_isolated() {
        let store = ThreadStore::new();
        let t1 = store.create_thread(HashMap::new());
        let t2 = store.create_thread(HashMap::new());

        store
            .add_message(&t1.id, "user", "Thread 1 message")
            .unwrap();

        assert_eq!(store.list_messages(&t1.id).len(), 1);
        assert_eq!(store.list_messages(&t2.id).len(), 0);
    }
}
