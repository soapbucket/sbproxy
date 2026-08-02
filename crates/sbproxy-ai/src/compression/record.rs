//! Versioned external summary-state records and canonical message digests.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Current external summary-record schema.
pub const RECORD_SCHEMA_VERSION: u16 = 1;

/// Canonical digest of a complete ordered message slice.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageDigest([u8; 32]);

impl MessageDigest {
    /// Canonicalize and hash the complete original JSON message values.
    pub fn try_for_messages(messages: &[serde_json::Value]) -> Result<Self, MessageDigestError> {
        let canonical =
            serde_json_canonicalizer::to_vec(&serde_json::Value::Array(messages.to_vec()))
                .map_err(|_| MessageDigestError)?;
        Ok(Self(Sha256::digest(canonical).into()))
    }

    /// Hash JSON message values known to be representable as canonical JSON.
    ///
    /// `serde_json::Value` cannot contain non-finite numbers or non-string map
    /// keys, so canonical serialization is infallible for this input domain.
    pub fn for_messages(messages: &[serde_json::Value]) -> Self {
        Self::try_for_messages(messages)
            .expect("serde_json::Value messages always have a canonical JSON representation")
    }

    /// Borrow raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render canonical lowercase hexadecimal.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for MessageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MessageDigest(<digest>)")
    }
}

impl fmt::Display for MessageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for MessageDigest {
    type Err = MessageDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MessageDigestError);
        }
        let decoded = hex::decode(value).map_err(|_| MessageDigestError)?;
        let bytes = decoded
            .try_into()
            .map_err(|_: Vec<u8>| MessageDigestError)?;
        Ok(Self(bytes))
    }
}

impl Serialize for MessageDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for MessageDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Canonical message digest could not be created or parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid compression message digest")]
pub struct MessageDigestError;

/// Live summary state or a versioned deletion marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Summary content is available for safe reuse.
    Live,
    /// Content has been removed and stale live replicas must not win.
    Tombstone,
}

/// Versioned external state for one opaque compression session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionSessionRecord {
    /// Record serialization schema.
    pub schema_version: u16,
    /// Monotonic logical version within the opaque record ID.
    pub logical_version: u64,
    /// Tenant boundary used for admin filtering.
    pub tenant_id: String,
    /// Normalized AI handler hostname used for admin filtering.
    pub origin: String,
    /// Sensitive running summary; omitted only by tombstones.
    pub summary: String,
    /// Number of leading system/developer messages protected verbatim.
    pub protected_prefix_count: usize,
    /// Digest of the complete protected prefix.
    pub protected_prefix_digest: MessageDigest,
    /// Number of original eligible history messages represented by summary.
    pub covered_history_count: usize,
    /// Digest of the complete covered original history.
    pub covered_history_digest: MessageDigest,
    /// SBproxy model-aware token estimate for the covered original history.
    pub covered_input_tokens: u64,
    /// Summarizer-reported or conservatively estimated output tokens.
    pub summary_tokens: u64,
    /// Configured summarizer provider name.
    pub summarizer_provider: String,
    /// Configured summarizer model name.
    pub summarizer_model: String,
    /// Stable mesh/process writer identity, never a credential.
    pub writer_node: String,
    /// Logical version this update extended.
    pub parent_logical_version: Option<u64>,
    /// Whether LWW merge observed competing children of one parent.
    pub conflict_detected: bool,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Last update timestamp in Unix milliseconds.
    pub updated_at_unix_ms: u64,
    /// Backend expiration timestamp in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Live content or deletion tombstone.
    pub kind: RecordKind,
}

impl fmt::Debug for CompressionSessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressionSessionRecord")
            .field("schema_version", &self.schema_version)
            .field("logical_version", &self.logical_version)
            .field("tenant_id", &self.tenant_id)
            .field("origin", &self.origin)
            .field("summary", &"<redacted>")
            .field("protected_prefix_count", &self.protected_prefix_count)
            .field("protected_prefix_digest", &self.protected_prefix_digest)
            .field("covered_history_count", &self.covered_history_count)
            .field("covered_history_digest", &self.covered_history_digest)
            .field("covered_input_tokens", &self.covered_input_tokens)
            .field("summary_tokens", &self.summary_tokens)
            .field("summarizer_provider", &self.summarizer_provider)
            .field("summarizer_model", &self.summarizer_model)
            .field("writer_node", &self.writer_node)
            .field("parent_logical_version", &self.parent_logical_version)
            .field("conflict_detected", &self.conflict_detected)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("updated_at_unix_ms", &self.updated_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("kind", &self.kind)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{CompressionSessionRecord, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION};
    use serde_json::json;

    #[test]
    fn canonical_message_digest_ignores_object_key_order_not_array_order() {
        let left = vec![json!({"role": "user", "content": "hello", "name": "a"})];
        let same = vec![json!({"name": "a", "content": "hello", "role": "user"})];
        let reversed = vec![
            json!({"role": "assistant", "content": "second"}),
            json!({"role": "user", "content": "first"}),
        ];
        let chronological = vec![
            json!({"role": "user", "content": "first"}),
            json!({"role": "assistant", "content": "second"}),
        ];

        assert_eq!(
            MessageDigest::for_messages(&left),
            MessageDigest::for_messages(&same)
        );
        assert_ne!(
            MessageDigest::for_messages(&reversed),
            MessageDigest::for_messages(&chronological)
        );
    }

    #[test]
    fn message_digest_serializes_as_canonical_lowercase_hex() {
        let digest = MessageDigest::for_messages(&[json!({"role": "user", "content": "x"})]);
        let encoded = serde_json::to_string(&digest).unwrap();
        assert_eq!(encoded.len(), 66, "64 hex characters plus JSON quotes");
        assert_eq!(
            serde_json::from_str::<MessageDigest>(&encoded).unwrap(),
            digest
        );
    }

    #[test]
    fn record_contains_summary_state_but_no_raw_session_or_turn_fields() {
        let record = CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: 2,
            tenant_id: "tenant-a".to_string(),
            origin: "api.example.com".to_string(),
            summary: "bounded generated summary".to_string(),
            protected_prefix_count: 1,
            protected_prefix_digest: MessageDigest::for_messages(&[json!({
                "role": "system",
                "content": "protected"
            })]),
            covered_history_count: 4,
            covered_history_digest: MessageDigest::for_messages(&[json!({
                "role": "user",
                "content": "covered"
            })]),
            covered_input_tokens: 123,
            summary_tokens: 20,
            summarizer_provider: "anthropic".to_string(),
            summarizer_model: "claude-summary".to_string(),
            writer_node: "node-a".to_string(),
            parent_logical_version: Some(1),
            conflict_detected: false,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
            expires_at_unix_ms: 3_000,
            kind: RecordKind::Live,
        };

        let encoded = serde_json::to_string(&record).unwrap();
        assert!(encoded.contains("bounded generated summary"));
        assert!(!encoded.contains("raw_session"));
        assert!(!encoded.contains("session_id"));
        assert!(!encoded.contains("messages"));
        assert!(!encoded.contains("raw_turn"));
        assert_eq!(
            serde_json::from_str::<CompressionSessionRecord>(&encoded).unwrap(),
            record
        );
        let diagnostic = format!("{record:?}");
        assert!(!diagnostic.contains("bounded generated summary"));
        assert!(diagnostic.contains("<redacted>"));
    }
}
