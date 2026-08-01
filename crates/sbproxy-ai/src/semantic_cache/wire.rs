//! Versioned bounded wire format for distributed semantic-cache records.
//!
//! This module is the only distributed serialization path for the semantic
//! cache. Redis and mesh both encode through [`encode_entry`] and decode
//! through [`decode_entry`], so every structural bound is applied in exactly
//! one place.
//!
//! An encoded record is a fixed six-byte header followed by postcard data:
//!
//! ```text
//! "SBSC" | schema version (u16, big endian) | postcard payload
//! ```
//!
//! The magic and version let random Redis or mesh bytes fail before any
//! deserialization work happens. Decoding then rechecks the total size, the
//! namespace, the expiry, the vector, the response, and the header bounds, so
//! a tampered or stale distributed value becomes a safe miss rather than a
//! replayable response.
//!
//! Attacker-controlled length prefixes never reach a bare `Vec::with_capacity`.
//! The embedding, header, string, and body fields all deserialize through
//! bounded visitors that reject an oversized declared length before reserving
//! anything.

use std::fmt;

use bytes::Bytes;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::config::{
    MAX_EMBEDDING_DIMENSIONS, MAX_SEMANTIC_ENTRY_BYTES, MAX_SEMANTIC_RESPONSE_BYTES,
};
use super::identity::SemanticNamespace;
use super::store::StoredSemanticEntry;
use super::CachedHttpResponse;

/// Current semantic-cache wire and keyspace version.
///
/// Version 2 starts an independent OSS format that cannot read or overwrite
/// an older experimental version 1 namespace.
pub const SEMANTIC_CACHE_SCHEMA_VERSION: u16 = 2;

/// Maximum response headers a stored record may carry.
pub const MAX_SEMANTIC_RESPONSE_HEADERS: usize = 128;

/// Maximum bytes in one stored response header name.
pub const MAX_SEMANTIC_HEADER_NAME_BYTES: usize = 256;

/// Maximum bytes in one stored response header value.
pub const MAX_SEMANTIC_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Maximum aggregate bytes across every stored response header.
pub const MAX_SEMANTIC_TOTAL_HEADER_BYTES: usize = 64 * 1024;

/// The one HTTP status the semantic cache admits.
const CACHEABLE_STATUS: u16 = 200;

/// Fixed four-byte magic that precedes every encoded record.
const WIRE_MAGIC: [u8; 4] = *b"SBSC";

/// Bytes of fixed header before the postcard payload.
const WIRE_HEADER_BYTES: usize = WIRE_MAGIC.len() + 2;

/// Closed wire failure classes.
///
/// Every `Display` string is a fixed label. Raw bytes, header names, header
/// values, namespace inputs, and decoder internals never appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The encoded record crosses the fixed entry ceiling.
    #[error("semantic cache wire entry is too large")]
    TooLarge,
    /// The record does not start with the semantic magic.
    #[error("semantic cache wire magic is invalid")]
    BadMagic,
    /// The record declares a schema version this build cannot read.
    #[error("semantic cache wire version is unsupported")]
    UnknownVersion,
    /// The postcard payload could not be read as a semantic record.
    #[error("semantic cache wire record is malformed")]
    Malformed,
    /// The record belongs to a different namespace.
    #[error("semantic cache wire record is out of namespace")]
    WrongNamespace,
    /// The record is past its expiry.
    #[error("semantic cache wire record is expired")]
    Expired,
    /// The record expires at or before it was stored.
    #[error("semantic cache wire record has an invalid expiry")]
    InvalidExpiry,
    /// The embedding is empty, oversized, non-finite, or zero-norm.
    #[error("semantic cache wire embedding is invalid")]
    InvalidEmbedding,
    /// The record carries a status other than the cacheable status.
    #[error("semantic cache wire status is not cacheable")]
    InvalidStatus,
    /// The response body crosses the response ceiling.
    #[error("semantic cache wire response is too large")]
    ResponseTooLarge,
    /// The record carries more headers than the header count bound.
    #[error("semantic cache wire record has too many headers")]
    TooManyHeaders,
    /// One header name crosses the name bound.
    #[error("semantic cache wire header name is too long")]
    HeaderNameTooLong,
    /// One header value crosses the value bound.
    #[error("semantic cache wire header value is too long")]
    HeaderValueTooLong,
    /// The aggregate header bytes cross the total header bound.
    #[error("semantic cache wire headers are too large")]
    HeaderBytesTooLarge,
    /// The record could not be encoded.
    #[error("semantic cache wire encoding failed")]
    Encode,
}

/// Borrowed encoding view of one record.
///
/// The response body is borrowed as a byte slice so encoding does not copy it
/// a second time. Field order is part of the format: postcard writes struct
/// fields positionally, so this must stay aligned with [`OwnedWireEntry`].
#[derive(Serialize)]
struct BorrowedWireEntry<'a> {
    namespace: &'a SemanticNamespace,
    prompt_digest: &'a [u8; 32],
    embedding: &'a [f32],
    status: u16,
    headers: &'a [(String, String)],
    body: WireBytes<'a>,
    stored_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

/// Owned decoding view of one record, bounded field by field.
#[derive(Deserialize)]
struct OwnedWireEntry {
    namespace: SemanticNamespace,
    prompt_digest: [u8; 32],
    embedding: BoundedEmbedding,
    status: u16,
    headers: BoundedHeaders,
    body: BoundedBody,
    stored_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

/// Encodes a byte slice through postcard's length-prefixed byte form.
struct WireBytes<'a>(&'a [u8]);

impl Serialize for WireBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// Embedding vector that rejects an oversized declared length before it
/// reserves any capacity.
struct BoundedEmbedding(Vec<f32>);

impl<'de> Deserialize<'de> for BoundedEmbedding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedEmbeddingVisitor;

        impl<'de> Visitor<'de> for BoundedEmbeddingVisitor {
            type Value = BoundedEmbedding;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded semantic embedding")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let declared = seq.size_hint().unwrap_or(0);
                if declared > MAX_EMBEDDING_DIMENSIONS {
                    return Err(de::Error::custom("bound"));
                }
                let mut values = Vec::with_capacity(declared.min(MAX_EMBEDDING_DIMENSIONS));
                while let Some(value) = seq.next_element::<f32>()? {
                    if values.len() >= MAX_EMBEDDING_DIMENSIONS {
                        return Err(de::Error::custom("bound"));
                    }
                    values.push(value);
                }
                Ok(BoundedEmbedding(values))
            }
        }

        deserializer.deserialize_seq(BoundedEmbeddingVisitor)
    }
}

/// String that rejects a declared length above `N` bytes.
struct BoundedString<const N: usize>(String);

impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedStringVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for BoundedStringVisitor<N> {
            type Value = BoundedString<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded semantic header string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > N {
                    return Err(de::Error::custom("bound"));
                }
                Ok(BoundedString(value.to_string()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                if value.len() > N {
                    return Err(de::Error::custom("bound"));
                }
                Ok(BoundedString(value))
            }
        }

        deserializer.deserialize_str(BoundedStringVisitor::<N>)
    }
}

/// Header list bounded by count, per-field size, and aggregate size.
struct BoundedHeaders(Vec<(String, String)>);

impl<'de> Deserialize<'de> for BoundedHeaders {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedHeadersVisitor;

        impl<'de> Visitor<'de> for BoundedHeadersVisitor {
            type Value = BoundedHeaders;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded semantic header list")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let declared = seq.size_hint().unwrap_or(0);
                if declared > MAX_SEMANTIC_RESPONSE_HEADERS {
                    return Err(de::Error::custom("bound"));
                }
                let mut headers = Vec::with_capacity(declared.min(MAX_SEMANTIC_RESPONSE_HEADERS));
                let mut total = 0usize;
                type Pair = (
                    BoundedString<MAX_SEMANTIC_HEADER_NAME_BYTES>,
                    BoundedString<MAX_SEMANTIC_HEADER_VALUE_BYTES>,
                );
                while let Some((name, value)) = seq.next_element::<Pair>()? {
                    if headers.len() >= MAX_SEMANTIC_RESPONSE_HEADERS {
                        return Err(de::Error::custom("bound"));
                    }
                    total = total
                        .checked_add(name.0.len())
                        .and_then(|sum| sum.checked_add(value.0.len()))
                        .ok_or_else(|| de::Error::custom("bound"))?;
                    if total > MAX_SEMANTIC_TOTAL_HEADER_BYTES {
                        return Err(de::Error::custom("bound"));
                    }
                    headers.push((name.0, value.0));
                }
                Ok(BoundedHeaders(headers))
            }
        }

        deserializer.deserialize_seq(BoundedHeadersVisitor)
    }
}

/// Response body bounded by the response ceiling.
struct BoundedBody(Vec<u8>);

impl<'de> Deserialize<'de> for BoundedBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedBodyVisitor;

        impl<'de> Visitor<'de> for BoundedBodyVisitor {
            type Value = BoundedBody;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded semantic response body")
            }

            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                if value.len() > MAX_SEMANTIC_RESPONSE_BYTES {
                    return Err(de::Error::custom("bound"));
                }
                Ok(BoundedBody(value.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                if value.len() > MAX_SEMANTIC_RESPONSE_BYTES {
                    return Err(de::Error::custom("bound"));
                }
                Ok(BoundedBody(value))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let declared = seq.size_hint().unwrap_or(0);
                if declared > MAX_SEMANTIC_RESPONSE_BYTES {
                    return Err(de::Error::custom("bound"));
                }
                let mut body = Vec::with_capacity(declared.min(MAX_SEMANTIC_RESPONSE_BYTES));
                while let Some(byte) = seq.next_element::<u8>()? {
                    if body.len() >= MAX_SEMANTIC_RESPONSE_BYTES {
                        return Err(de::Error::custom("bound"));
                    }
                    body.push(byte);
                }
                Ok(BoundedBody(body))
            }
        }

        deserializer.deserialize_bytes(BoundedBodyVisitor)
    }
}

/// Apply every structural bound to one record.
fn validate_entry(
    schema_version: u16,
    embedding: &[f32],
    response: &CachedHttpResponse,
    stored_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(), WireError> {
    if schema_version != SEMANTIC_CACHE_SCHEMA_VERSION {
        return Err(WireError::UnknownVersion);
    }
    if expires_at_unix_ms <= stored_at_unix_ms {
        return Err(WireError::InvalidExpiry);
    }
    if embedding.is_empty() || embedding.len() > MAX_EMBEDDING_DIMENSIONS {
        return Err(WireError::InvalidEmbedding);
    }
    let mut sum_of_squares = 0f64;
    for value in embedding {
        if !value.is_finite() {
            return Err(WireError::InvalidEmbedding);
        }
        sum_of_squares += f64::from(*value) * f64::from(*value);
    }
    if !(sum_of_squares.is_finite() && sum_of_squares > 0.0) {
        return Err(WireError::InvalidEmbedding);
    }
    if response.status != CACHEABLE_STATUS {
        return Err(WireError::InvalidStatus);
    }
    if response.body.len() > MAX_SEMANTIC_RESPONSE_BYTES {
        return Err(WireError::ResponseTooLarge);
    }
    if response.headers.len() > MAX_SEMANTIC_RESPONSE_HEADERS {
        return Err(WireError::TooManyHeaders);
    }
    let mut total = 0usize;
    for (name, value) in &response.headers {
        if name.len() > MAX_SEMANTIC_HEADER_NAME_BYTES {
            return Err(WireError::HeaderNameTooLong);
        }
        if value.len() > MAX_SEMANTIC_HEADER_VALUE_BYTES {
            return Err(WireError::HeaderValueTooLong);
        }
        total = total
            .checked_add(name.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .ok_or(WireError::HeaderBytesTooLarge)?;
        if total > MAX_SEMANTIC_TOTAL_HEADER_BYTES {
            return Err(WireError::HeaderBytesTooLarge);
        }
    }
    Ok(())
}

/// Encode one record for a distributed backend.
///
/// Every structural limit is applied before any encoding buffer is allocated,
/// and the finished record is rejected if it crosses the fixed 8 MiB wire
/// entry ceiling.
pub fn encode_entry(entry: &StoredSemanticEntry) -> Result<Bytes, WireError> {
    validate_entry(
        entry.schema_version,
        &entry.embedding,
        &entry.response,
        entry.stored_at_unix_ms,
        entry.expires_at_unix_ms,
    )?;
    let dto = BorrowedWireEntry {
        namespace: &entry.namespace,
        prompt_digest: &entry.prompt_digest,
        embedding: &entry.embedding,
        status: entry.response.status,
        headers: &entry.response.headers,
        body: WireBytes(entry.response.body.as_ref()),
        stored_at_unix_ms: entry.stored_at_unix_ms,
        expires_at_unix_ms: entry.expires_at_unix_ms,
    };
    let payload = postcard::to_stdvec(&dto).map_err(|_| WireError::Encode)?;
    let total = payload
        .len()
        .checked_add(WIRE_HEADER_BYTES)
        .ok_or(WireError::TooLarge)?;
    if total > MAX_SEMANTIC_ENTRY_BYTES {
        return Err(WireError::TooLarge);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&WIRE_MAGIC);
    encoded.extend_from_slice(&SEMANTIC_CACHE_SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(Bytes::from(encoded))
}

/// Decode one distributed record defensively.
///
/// Total size, magic, and version are checked before deserialization. The
/// namespace, expiry, vector, response, and header bounds are rechecked
/// afterwards, so a corrupt, stale, or cross-namespace value returns a
/// [`WireError`] instead of a replayable response.
pub fn decode_entry(
    bytes: &[u8],
    expected_namespace: &SemanticNamespace,
    now_unix_ms: u64,
) -> Result<StoredSemanticEntry, WireError> {
    if bytes.len() > MAX_SEMANTIC_ENTRY_BYTES {
        return Err(WireError::TooLarge);
    }
    if bytes.len() < WIRE_HEADER_BYTES {
        return Err(WireError::Malformed);
    }
    if bytes[..WIRE_MAGIC.len()] != WIRE_MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != SEMANTIC_CACHE_SCHEMA_VERSION {
        return Err(WireError::UnknownVersion);
    }
    let dto: OwnedWireEntry =
        postcard::from_bytes(&bytes[WIRE_HEADER_BYTES..]).map_err(|_| WireError::Malformed)?;
    if dto.namespace != *expected_namespace {
        return Err(WireError::WrongNamespace);
    }
    let response = CachedHttpResponse {
        status: dto.status,
        headers: dto.headers.0,
        body: Bytes::from(dto.body.0),
    };
    validate_entry(
        version,
        &dto.embedding.0,
        &response,
        dto.stored_at_unix_ms,
        dto.expires_at_unix_ms,
    )?;
    if dto.expires_at_unix_ms <= now_unix_ms {
        return Err(WireError::Expired);
    }
    Ok(StoredSemanticEntry {
        schema_version: version,
        namespace: dto.namespace,
        prompt_digest: dto.prompt_digest,
        embedding: dto.embedding.0,
        response: std::sync::Arc::new(response),
        stored_at_unix_ms: dto.stored_at_unix_ms,
        expires_at_unix_ms: dto.expires_at_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_cache::store::contract::contract_namespace;
    use std::sync::Arc;

    fn entry_with(
        namespace: &SemanticNamespace,
        embedding: Vec<f32>,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        stored_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> StoredSemanticEntry {
        StoredSemanticEntry {
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
            namespace: namespace.clone(),
            prompt_digest: [5u8; 32],
            embedding,
            response: Arc::new(CachedHttpResponse {
                status,
                headers,
                body: Bytes::from(body),
            }),
            stored_at_unix_ms,
            expires_at_unix_ms,
        }
    }

    fn simple_entry(namespace: &SemanticNamespace) -> StoredSemanticEntry {
        entry_with(
            namespace,
            vec![0.6, 0.8, 0.0],
            200,
            vec![("content-type".to_string(), "application/json".to_string())],
            b"{\"ok\":true}".to_vec(),
            1_000,
            9_000_000,
        )
    }

    #[test]
    fn version_2_round_trip_preserves_status_headers_body_vector_and_times() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = simple_entry(&namespace);
        let encoded = encode_entry(&entry).expect("encode");
        assert_eq!(&encoded[..4], b"SBSC");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 2);
        let decoded = decode_entry(&encoded, &namespace, 2_000).expect("decode");
        assert_eq!(decoded.schema_version, SEMANTIC_CACHE_SCHEMA_VERSION);
        assert_eq!(decoded.response.status, 200);
        assert_eq!(decoded.response.headers, entry.response.headers);
        assert_eq!(decoded.response.body, entry.response.body);
        assert_eq!(decoded.embedding, entry.embedding);
        assert_eq!(decoded.prompt_digest, entry.prompt_digest);
        assert_eq!(decoded.stored_at_unix_ms, entry.stored_at_unix_ms);
        assert_eq!(decoded.expires_at_unix_ms, entry.expires_at_unix_ms);
    }

    #[test]
    fn maximum_legal_body_vector_and_headers_fit_beneath_the_entry_cap() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let mut headers = Vec::new();
        let value_bytes = MAX_SEMANTIC_TOTAL_HEADER_BYTES / MAX_SEMANTIC_RESPONSE_HEADERS - 8;
        for index in 0..MAX_SEMANTIC_RESPONSE_HEADERS {
            headers.push((format!("x-h-{index:03}"), "v".repeat(value_bytes)));
        }
        let entry = entry_with(
            &namespace,
            vec![0.5; MAX_EMBEDDING_DIMENSIONS],
            200,
            headers,
            vec![7u8; MAX_SEMANTIC_RESPONSE_BYTES],
            1_000,
            9_000_000,
        );
        let encoded = encode_entry(&entry).expect("maximum legal record encodes");
        assert!(encoded.len() <= MAX_SEMANTIC_ENTRY_BYTES);
        let decoded = decode_entry(&encoded, &namespace, 2_000).expect("decode");
        assert_eq!(decoded.response.body.len(), MAX_SEMANTIC_RESPONSE_BYTES);
        assert_eq!(decoded.embedding.len(), MAX_EMBEDDING_DIMENSIONS);
    }

    #[test]
    fn wire_input_above_the_entry_cap_is_rejected_before_deserialization() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let oversized = vec![0u8; MAX_SEMANTIC_ENTRY_BYTES + 1];
        assert_eq!(
            decode_entry(&oversized, &namespace, 2_000).unwrap_err(),
            WireError::TooLarge
        );
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let mut encoded = encode_entry(&simple_entry(&namespace))
            .expect("encode")
            .to_vec();
        encoded[5] = 3;
        assert_eq!(
            decode_entry(&encoded, &namespace, 2_000).unwrap_err(),
            WireError::UnknownVersion
        );
        encoded[0] = b'X';
        assert_eq!(
            decode_entry(&encoded, &namespace, 2_000).unwrap_err(),
            WireError::BadMagic
        );
    }

    #[test]
    fn wrong_namespace_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let other = contract_namespace("tenant-secret-b", "origin-a.example");
        let encoded = encode_entry(&simple_entry(&namespace)).expect("encode");
        assert_eq!(
            decode_entry(&encoded, &other, 2_000).unwrap_err(),
            WireError::WrongNamespace
        );
    }

    #[test]
    fn expired_entry_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let encoded = encode_entry(&simple_entry(&namespace)).expect("encode");
        assert_eq!(
            decode_entry(&encoded, &namespace, 9_000_001).unwrap_err(),
            WireError::Expired
        );
    }

    #[test]
    fn expiry_at_or_before_storage_time_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            Vec::new(),
            b"x".to_vec(),
            5_000,
            5_000,
        );
        assert_eq!(encode_entry(&entry).unwrap_err(), WireError::InvalidExpiry);
    }

    #[test]
    fn write_time_seconds_to_milliseconds_overflow_is_rejected() {
        // The orchestrator computes expiry with checked arithmetic. When that
        // saturates, the entry it would produce cannot be encoded.
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let stored_at = u64::MAX;
        let expires_at = stored_at.saturating_add(3_600_000);
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            Vec::new(),
            b"x".to_vec(),
            stored_at,
            expires_at,
        );
        assert_eq!(encode_entry(&entry).unwrap_err(), WireError::InvalidExpiry);
    }

    #[test]
    fn zero_nan_or_infinite_embedding_elements_are_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        for embedding in [
            Vec::new(),
            vec![0.0, 0.0, 0.0],
            vec![f32::NAN, 1.0, 0.0],
            vec![f32::INFINITY, 1.0, 0.0],
            vec![f32::NEG_INFINITY, 1.0, 0.0],
        ] {
            let entry = entry_with(
                &namespace,
                embedding,
                200,
                Vec::new(),
                b"x".to_vec(),
                1_000,
                9_000,
            );
            assert_eq!(
                encode_entry(&entry).unwrap_err(),
                WireError::InvalidEmbedding
            );
        }
    }

    #[test]
    fn embedding_dimensions_above_the_common_limit_are_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = entry_with(
            &namespace,
            vec![0.5; MAX_EMBEDDING_DIMENSIONS + 1],
            200,
            Vec::new(),
            b"x".to_vec(),
            1_000,
            9_000,
        );
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::InvalidEmbedding
        );
    }

    #[test]
    fn status_other_than_the_canonical_cacheable_status_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        for status in [201u16, 204, 301, 400, 500] {
            let entry = entry_with(
                &namespace,
                vec![0.6, 0.8, 0.0],
                status,
                Vec::new(),
                b"x".to_vec(),
                1_000,
                9_000,
            );
            assert_eq!(encode_entry(&entry).unwrap_err(), WireError::InvalidStatus);
        }
    }

    #[test]
    fn response_body_above_the_body_cap_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            Vec::new(),
            vec![1u8; MAX_SEMANTIC_RESPONSE_BYTES + 1],
            1_000,
            9_000,
        );
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::ResponseTooLarge
        );
    }

    #[test]
    fn more_than_the_header_count_bound_is_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let headers = (0..=MAX_SEMANTIC_RESPONSE_HEADERS)
            .map(|index| (format!("x-h-{index}"), "v".to_string()))
            .collect();
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            headers,
            b"x".to_vec(),
            1_000,
            9_000,
        );
        assert_eq!(encode_entry(&entry).unwrap_err(), WireError::TooManyHeaders);
    }

    #[test]
    fn header_names_above_the_name_bound_are_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            vec![(
                "n".repeat(MAX_SEMANTIC_HEADER_NAME_BYTES + 1),
                "v".to_string(),
            )],
            b"x".to_vec(),
            1_000,
            9_000,
        );
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::HeaderNameTooLong
        );
    }

    #[test]
    fn individual_header_values_above_the_value_bound_are_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            vec![(
                "x-h".to_string(),
                "v".repeat(MAX_SEMANTIC_HEADER_VALUE_BYTES + 1),
            )],
            b"x".to_vec(),
            1_000,
            9_000,
        );
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::HeaderValueTooLong
        );
    }

    #[test]
    fn aggregate_header_bytes_above_the_total_bound_are_rejected() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let headers = (0..MAX_SEMANTIC_RESPONSE_HEADERS)
            .map(|index| {
                (
                    format!("x-h-{index:03}"),
                    "v".repeat(MAX_SEMANTIC_HEADER_VALUE_BYTES),
                )
            })
            .collect();
        let entry = entry_with(
            &namespace,
            vec![0.6, 0.8, 0.0],
            200,
            headers,
            b"x".to_vec(),
            1_000,
            9_000,
        );
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::HeaderBytesTooLarge
        );
    }

    /// Varint encoding of `u64::MAX`, the widest length a postcard length
    /// prefix can declare.
    const HUGE_DECLARED_LENGTH: [u8; 10] =
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    /// Fixed-width record prefix: the namespace followed by a prompt digest.
    /// Serializing them as a tuple reproduces the exact leading bytes of a
    /// record without hardcoding the namespace representation.
    fn record_prefix(namespace: &SemanticNamespace) -> Vec<u8> {
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&WIRE_MAGIC);
        prefix.extend_from_slice(&SEMANTIC_CACHE_SCHEMA_VERSION.to_be_bytes());
        prefix.extend_from_slice(
            &postcard::to_stdvec(&(namespace.clone(), [5u8; 32])).expect("prefix encodes"),
        );
        prefix
    }

    #[test]
    fn a_declared_huge_vector_in_a_tiny_input_decodes_without_allocating() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let mut malformed = record_prefix(&namespace);
        malformed.extend_from_slice(&HUGE_DECLARED_LENGTH);
        assert!(malformed.len() < 256);
        assert_eq!(
            decode_entry(&malformed, &namespace, 2_000).unwrap_err(),
            WireError::Malformed
        );
    }

    #[test]
    fn a_declared_huge_header_list_in_a_tiny_input_decodes_without_allocating() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let mut malformed = record_prefix(&namespace);
        // A one-element embedding, then status 200, then a huge declared
        // header count in an input that carries no header bytes at all.
        malformed.push(0x01);
        malformed.extend_from_slice(&1.0f32.to_le_bytes());
        malformed.extend_from_slice(&[0xC8, 0x01]);
        malformed.extend_from_slice(&HUGE_DECLARED_LENGTH);
        assert!(malformed.len() < 256);
        assert_eq!(
            decode_entry(&malformed, &namespace, 2_000).unwrap_err(),
            WireError::Malformed
        );
    }

    #[test]
    fn wire_error_display_never_contains_bytes_headers_or_decode_internals() {
        for error in [
            WireError::TooLarge,
            WireError::BadMagic,
            WireError::UnknownVersion,
            WireError::Malformed,
            WireError::WrongNamespace,
            WireError::Expired,
            WireError::InvalidExpiry,
            WireError::InvalidEmbedding,
            WireError::InvalidStatus,
            WireError::ResponseTooLarge,
            WireError::TooManyHeaders,
            WireError::HeaderNameTooLong,
            WireError::HeaderValueTooLong,
            WireError::HeaderBytesTooLarge,
            WireError::Encode,
        ] {
            let text = error.to_string();
            assert!(text.starts_with("semantic cache wire"));
            assert!(std::error::Error::source(&error).is_none());
            for sentinel in ["SBSC", "content-type", "postcard", "0x", "tenant-secret-a"] {
                assert!(
                    !text.contains(sentinel),
                    "wire error must not carry {sentinel}"
                );
            }
        }
    }
}
