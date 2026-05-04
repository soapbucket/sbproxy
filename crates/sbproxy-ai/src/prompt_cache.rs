//! Prompt caching support.
//!
//! Passes through Anthropic's `cache_control` field and tracks cache usage.
//! For other providers, implements client-side prompt hashing for deterministic cache keys.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Check if a request body uses Anthropic-style prompt caching.
///
/// Returns true when any of the following contain a `cache_control` field:
/// - Top-level `system` (string or array form)
/// - Any message in `messages`
/// - Any content part within a message
pub fn has_cache_control(body: &serde_json::Value) -> bool {
    // Check top-level system prompt (array form with cache_control)
    if let Some(system) = body.get("system") {
        if system_has_cache_control(system) {
            return true;
        }
    }

    // Check messages array
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for message in messages {
            if message.get("cache_control").is_some() {
                return true;
            }
            // Check content parts
            if let Some(content) = message.get("content").and_then(|c| c.as_array()) {
                for part in content {
                    if part.get("cache_control").is_some() {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Returns true if a system prompt value contains cache_control.
///
/// Anthropic supports two system prompt formats:
/// - String: no cache_control possible
/// - Array of blocks: each block may have cache_control
fn system_has_cache_control(system: &serde_json::Value) -> bool {
    if let Some(blocks) = system.as_array() {
        for block in blocks {
            if block.get("cache_control").is_some() {
                return true;
            }
        }
    }
    false
}

/// Generate a deterministic cache key from a messages array.
///
/// The key is computed as the SHA-256 hex digest of the canonical JSON
/// representation of the messages value. Normalizes the JSON to ensure
/// consistent ordering does not affect the key.
pub fn prompt_cache_key(messages: &serde_json::Value) -> String {
    // Serialize to a canonical string (serde_json produces consistent key order
    // within objects that were deserialized, but we sort keys for robustness)
    let canonical = canonical_json(messages);
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)
}

/// Produce a canonical JSON string with sorted object keys.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(&str, &serde_json::Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            pairs.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = pairs
                .into_iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonical_json(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Look up a cached response for a given cache key.
///
/// Returns `Some(response)` if a cache hit is found, `None` otherwise.
pub fn check_cache(key: &str, cache: &HashMap<String, String>) -> Option<String> {
    cache.get(key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- has_cache_control tests ---

    #[test]
    fn detect_cache_control_in_content_part() {
        let body = json!({
            "model": "claude-sonnet-4-5",
            "messages": [{
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Hello",
                        "cache_control": {"type": "ephemeral"}
                    }
                ]
            }]
        });
        assert!(has_cache_control(&body));
    }

    #[test]
    fn detect_cache_control_on_message() {
        let body = json!({
            "messages": [{
                "role": "user",
                "content": "Hello",
                "cache_control": {"type": "ephemeral"}
            }]
        });
        assert!(has_cache_control(&body));
    }

    #[test]
    fn detect_cache_control_in_system_array() {
        let body = json!({
            "system": [
                {
                    "type": "text",
                    "text": "You are a helpful assistant.",
                    "cache_control": {"type": "ephemeral"}
                }
            ],
            "messages": [{"role": "user", "content": "Hi"}]
        });
        assert!(has_cache_control(&body));
    }

    #[test]
    fn no_cache_control_when_absent() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"}
            ]
        });
        assert!(!has_cache_control(&body));
    }

    #[test]
    fn no_cache_control_on_empty_messages() {
        let body = json!({"messages": []});
        assert!(!has_cache_control(&body));
    }

    #[test]
    fn no_cache_control_on_string_system() {
        let body = json!({
            "system": "You are a helpful assistant.",
            "messages": [{"role": "user", "content": "Hi"}]
        });
        assert!(!has_cache_control(&body));
    }

    // --- prompt_cache_key tests ---

    #[test]
    fn cache_key_is_deterministic_for_same_messages() {
        let messages = json!([
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ]);
        let key1 = prompt_cache_key(&messages);
        let key2 = prompt_cache_key(&messages);
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_messages_produce_different_keys() {
        let messages_a = json!([{"role": "user", "content": "Hello"}]);
        let messages_b = json!([{"role": "user", "content": "Goodbye"}]);

        let key_a = prompt_cache_key(&messages_a);
        let key_b = prompt_cache_key(&messages_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn cache_key_is_hex_sha256_length() {
        let messages = json!([{"role": "user", "content": "test"}]);
        let key = prompt_cache_key(&messages);
        // SHA-256 produces 32 bytes = 64 hex chars
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn same_content_different_key_order_produces_same_key() {
        // Canonical JSON should sort keys, so object key order should not matter
        let messages_a = json!([{"role": "user", "content": "Hi"}]);
        let messages_b = json!([{"content": "Hi", "role": "user"}]);

        let key_a = prompt_cache_key(&messages_a);
        let key_b = prompt_cache_key(&messages_b);
        assert_eq!(key_a, key_b, "object key order should not affect cache key");
    }

    #[test]
    fn longer_conversation_produces_different_key_than_shorter() {
        let short = json!([{"role": "user", "content": "Hello"}]);
        let long = json!([
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi!"},
            {"role": "user", "content": "How are you?"}
        ]);
        assert_ne!(prompt_cache_key(&short), prompt_cache_key(&long));
    }

    // --- check_cache tests ---

    #[test]
    fn cache_hit_returns_response() {
        let mut cache = HashMap::new();
        cache.insert(
            "abc123".to_string(),
            r#"{"choices":[{"message":{"content":"Hello!"}}]}"#.to_string(),
        );

        let result = check_cache("abc123", &cache);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Hello!"));
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache: HashMap<String, String> = HashMap::new();
        assert!(check_cache("nonexistent-key", &cache).is_none());
    }

    #[test]
    fn check_cache_with_generated_key() {
        let messages = json!([{"role": "user", "content": "What is 2+2?"}]);
        let key = prompt_cache_key(&messages);

        let mut cache = HashMap::new();
        cache.insert(key.clone(), "4".to_string());

        assert_eq!(check_cache(&key, &cache), Some("4".to_string()));
        assert!(check_cache("wrong-key", &cache).is_none());
    }

    #[test]
    fn empty_messages_produces_stable_key() {
        let messages = json!([]);
        let key1 = prompt_cache_key(&messages);
        let key2 = prompt_cache_key(&messages);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64);
    }
}
