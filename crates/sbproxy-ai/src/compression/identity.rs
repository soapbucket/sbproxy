//! Opaque domain-separated session record identity.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

use super::SummaryPolicyFingerprint;

const RECORD_ID_NAMESPACE: &[u8] = b"sbproxy:compression-session:v1";
const POLICY_RECORD_ID_NAMESPACE: &[u8] = b"sbproxy:compression-session-policy:v2";

/// Opaque identifier for one tenant, AI origin, and captured session tuple.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressionRecordId([u8; 32]);

impl CompressionRecordId {
    /// Derive a policy-agnostic domain-separated ID without retaining the raw session value.
    ///
    /// Stateful request-path levers must use [`Self::derive_for_summary_policy`]
    /// so rolling behavior changes cannot share a stored lineage.
    pub fn derive(tenant_id: &str, origin: &str, session_id: [u8; 16]) -> Self {
        let normalized_origin = normalize_origin(origin);
        let mut digest = Sha256::new();
        update_length_delimited(&mut digest, RECORD_ID_NAMESPACE);
        update_length_delimited(&mut digest, tenant_id.as_bytes());
        update_length_delimited(&mut digest, normalized_origin.as_bytes());
        update_length_delimited(&mut digest, &session_id);
        Self(digest.finalize().into())
    }

    /// Derive a summary-state ID isolated by its complete behavior fingerprint.
    pub fn derive_for_summary_policy(
        tenant_id: &str,
        origin: &str,
        session_id: [u8; 16],
        policy: SummaryPolicyFingerprint,
    ) -> Self {
        let normalized_origin = normalize_origin(origin);
        let mut digest = Sha256::new();
        update_length_delimited(&mut digest, POLICY_RECORD_ID_NAMESPACE);
        update_length_delimited(&mut digest, tenant_id.as_bytes());
        update_length_delimited(&mut digest, normalized_origin.as_bytes());
        update_length_delimited(&mut digest, &session_id);
        update_length_delimited(&mut digest, policy.as_bytes());
        Self(digest.finalize().into())
    }

    /// Borrow the digest bytes for backend key construction.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render canonical lowercase hexadecimal.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CompressionRecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompressionRecordId(<opaque>)")
    }
}

impl fmt::Display for CompressionRecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for CompressionRecordId {
    type Err = RecordIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RecordIdParseError);
        }
        let decoded = hex::decode(value).map_err(|_| RecordIdParseError)?;
        let bytes = decoded
            .try_into()
            .map_err(|_: Vec<u8>| RecordIdParseError)?;
        Ok(Self(bytes))
    }
}

impl Serialize for CompressionRecordId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CompressionRecordId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Invalid or non-canonical compression record identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid compression record id")]
pub struct RecordIdParseError;

/// Normalize the stable AI handler hostname used in record identity.
pub fn normalize_origin(origin: &str) -> String {
    origin.trim_end_matches('.').to_ascii_lowercase()
}

fn update_length_delimited(digest: &mut Sha256, value: &[u8]) {
    match u32::try_from(value.len()) {
        Ok(length) => digest.update(length.to_be_bytes()),
        Err(_) => {
            digest.update(u32::MAX.to_be_bytes());
            digest.update((value.len() as u64).to_be_bytes());
        }
    }
    digest.update(value);
}

#[cfg(test)]
mod tests {
    use super::CompressionRecordId;
    use crate::compression::{SummarizerConfig, SummaryBufferConfig, SummaryPolicyFingerprint};
    use std::str::FromStr;
    use std::time::Duration;

    fn summary_config() -> SummaryBufferConfig {
        SummaryBufferConfig {
            min_tokens: 12_000,
            retain_recent_messages: 8,
            target_summary_tokens: 2_048,
            summarizer: SummarizerConfig {
                provider: "anthropic-internal".to_string(),
                model: "claude-summary-v1".to_string(),
                timeout_secs: 5,
            },
        }
    }

    #[test]
    fn record_id_matches_stable_length_delimited_vector() {
        let session = std::array::from_fn(|index| index as u8);
        let id = CompressionRecordId::derive("tenant-a", "API.Example.COM.", session);

        assert_eq!(
            id.to_string(),
            "670bb7bb610f3600675ee2fcb45db09ca3c6557dc7865b87311355ee1c9d1bb8"
        );
    }

    #[test]
    fn policy_record_id_matches_stable_length_delimited_vector() {
        let session = std::array::from_fn(|index| index as u8);
        let policy =
            SummaryPolicyFingerprint::current(&summary_config(), Duration::from_secs(86_400));
        let id = CompressionRecordId::derive_for_summary_policy(
            "tenant-a",
            "API.Example.COM.",
            session,
            policy,
        );

        assert_eq!(
            id.to_string(),
            "cee8c51340c1413d8b85a56c6f51928a92b12fa00e1e8cfd761c3cd0fb28ce47"
        );
        assert_ne!(
            id,
            CompressionRecordId::derive("tenant-a", "API.Example.COM.", session),
            "a mixed rollout must not reuse policy-agnostic v1 state"
        );
    }

    #[test]
    fn origin_normalization_is_stable() {
        let session = [7; 16];
        assert_eq!(
            CompressionRecordId::derive("tenant-a", "API.Example.COM.", session),
            CompressionRecordId::derive("tenant-a", "api.example.com", session)
        );
    }

    #[test]
    fn tuple_fields_are_domain_separated() {
        let session = [7; 16];
        let baseline = CompressionRecordId::derive("tenant-a", "api.example.com", session);

        assert_ne!(
            baseline,
            CompressionRecordId::derive("tenant-b", "api.example.com", session)
        );
        assert_ne!(
            baseline,
            CompressionRecordId::derive("tenant-a", "other.example.com", session)
        );
        assert_ne!(
            baseline,
            CompressionRecordId::derive("tenant-a", "api.example.com", [8; 16])
        );
    }

    #[test]
    fn parsing_accepts_only_canonical_lowercase_hex() {
        let text = "670bb7bb610f3600675ee2fcb45db09ca3c6557dc7865b87311355ee1c9d1bb8";
        assert_eq!(
            CompressionRecordId::from_str(text).unwrap().to_string(),
            text
        );
        assert!(CompressionRecordId::from_str(&text.to_uppercase()).is_err());
        assert!(CompressionRecordId::from_str("abcd").is_err());
        assert!(CompressionRecordId::from_str(&"z".repeat(64)).is_err());
    }
}
