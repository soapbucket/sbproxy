//! Cross-provider response deduplication.
//!
//! When multiple providers are queried in parallel (fan-out), different
//! providers may return identical responses.  This module tracks content
//! hashes so duplicate responses can be detected and suppressed.

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Tracks which provider first returned each unique response.
pub struct ResponseDedup {
    /// Maps content hash to the name of the provider that first returned it.
    hashes: Mutex<HashMap<String, String>>,
}

impl ResponseDedup {
    /// Create a new deduplicator with no recorded responses.
    pub fn new() -> Self {
        Self {
            hashes: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether `response` has already been recorded by another provider.
    ///
    /// Returns the name of the provider that previously returned this response,
    /// or `None` if the response is novel.
    pub fn check(&self, response: &str) -> Option<String> {
        let h = Self::hash(response);
        let hashes = self.hashes.lock().unwrap();
        hashes.get(&h).cloned()
    }

    /// Record that `provider` returned `response`.
    ///
    /// If the same content hash was already recorded by a different provider,
    /// the original attribution is preserved (first-writer-wins).
    pub fn record(&self, response: &str, provider: &str) {
        let h = Self::hash(response);
        let mut hashes = self.hashes.lock().unwrap();
        hashes.entry(h).or_insert_with(|| provider.to_string());
    }

    /// Compute a hex-encoded SHA-256 hash of `content`.
    fn hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Default for ResponseDedup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn novel_response_not_detected() {
        let dedup = ResponseDedup::new();
        assert!(dedup.check("hello world").is_none());
    }

    #[test]
    fn duplicate_response_detected_after_recording() {
        let dedup = ResponseDedup::new();
        dedup.record("hello world", "openai");
        let provider = dedup.check("hello world").unwrap();
        assert_eq!(provider, "openai");
    }

    #[test]
    fn first_writer_wins_on_collision() {
        let dedup = ResponseDedup::new();
        dedup.record("same content", "openai");
        dedup.record("same content", "anthropic"); // should not overwrite
        let provider = dedup.check("same content").unwrap();
        assert_eq!(provider, "openai");
    }

    #[test]
    fn different_responses_stored_independently() {
        let dedup = ResponseDedup::new();
        dedup.record("response A", "openai");
        dedup.record("response B", "anthropic");

        assert_eq!(dedup.check("response A").unwrap(), "openai");
        assert_eq!(dedup.check("response B").unwrap(), "anthropic");
    }

    #[test]
    fn empty_response_can_be_recorded_and_detected() {
        let dedup = ResponseDedup::new();
        assert!(dedup.check("").is_none());
        dedup.record("", "cohere");
        assert_eq!(dedup.check("").unwrap(), "cohere");
    }

    #[test]
    fn check_before_record_returns_none() {
        let dedup = ResponseDedup::new();
        dedup.record("existing", "openai");
        assert!(dedup.check("not recorded yet").is_none());
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = ResponseDedup::hash("test content");
        let h2 = ResponseDedup::hash("test content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_content_produces_different_hashes() {
        let h1 = ResponseDedup::hash("content A");
        let h2 = ResponseDedup::hash("content B");
        assert_ne!(h1, h2);
    }
}
