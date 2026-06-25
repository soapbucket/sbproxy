// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Error type and size limits shared by every storage backend.
//!
//! Backends must map their native error types onto [`StorageError`] so
//! callers can write retry / fallback logic without depending on
//! `redis::RedisError`, `tokio_postgres::Error`, etc. The variant set
//! is intentionally small: it covers the failure modes that are
//! actionable at the call site (retryable vs. fatal vs. configuration
//! bug). Anything more specific belongs in the backend's own logs or
//! metrics.

use std::time::Duration;

/// Hard cap on key length accepted by any backend.
///
/// Keys are typically `workspace_id:tenant:logical_key`; 1 KiB is
/// generous and matches the upper bound enforced by the Redis backend
/// and the mesh transport so the abstraction never silently accepts a
/// key one backend would reject.
pub const MAX_KEY_BYTES: usize = 1024;

/// Hard cap on value length accepted by any backend.
///
/// 16 MiB is the largest blob the cache and mesh transports are
/// configured to handle. Larger payloads should round-trip through
/// object storage (`object_store` / S3) instead.
pub const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

/// Errors returned by every [`crate::EphemeralKv`], [`crate::PersistentKv`],
/// and [`crate::PubSub`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Backend-side error wrapped as a string. Use this for the long
    /// tail of opaque driver errors (Redis returned a `MOVED` slot,
    /// Postgres rejected the SQL, etc.). Callers should treat these
    /// as retryable unless paired with [`StorageError::Disconnected`].
    #[error("backend error: {0}")]
    Backend(String),

    /// The backend exceeded its configured deadline. Callers should
    /// retry on a fresh connection or fall back to a degraded mode.
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    /// Caller-supplied key exceeded [`MAX_KEY_BYTES`]. This is a
    /// programming error and should not be retried.
    #[error("key too large ({len} bytes, max {max})")]
    KeyTooLarge {
        /// Actual length supplied by the caller.
        len: usize,
        /// Configured maximum (always [`MAX_KEY_BYTES`] today).
        max: usize,
    },

    /// Caller-supplied value exceeded [`MAX_VALUE_BYTES`]. Caller
    /// should chunk or write to object storage instead.
    #[error("value too large ({len} bytes, max {max})")]
    ValueTooLarge {
        /// Actual length supplied by the caller.
        len: usize,
        /// Configured maximum (always [`MAX_VALUE_BYTES`] today).
        max: usize,
    },

    /// The underlying connection / channel is gone. The caller should
    /// drop any cached subscription and re-resolve the backend.
    #[error("backend disconnected")]
    Disconnected,

    /// The backend was constructed with an invalid configuration
    /// (missing URL, malformed DSN, mutually exclusive flags). Not
    /// retryable; surface as a startup failure.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl StorageError {
    /// Short, label-safe identifier for this variant. Used by the
    /// metrics layer so error counters stay bounded-cardinality.
    pub fn kind(&self) -> &'static str {
        match self {
            StorageError::Backend(_) => "backend",
            StorageError::Timeout(_) => "timeout",
            StorageError::KeyTooLarge { .. } => "key_too_large",
            StorageError::ValueTooLarge { .. } => "value_too_large",
            StorageError::Disconnected => "disconnected",
            StorageError::InvalidConfig(_) => "invalid_config",
        }
    }
}

/// Validate that `key` fits in [`MAX_KEY_BYTES`].
///
/// Pulled out so backends don't have to re-implement the check.
pub fn check_key(key: &str) -> Result<(), StorageError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(StorageError::KeyTooLarge {
            len: key.len(),
            max: MAX_KEY_BYTES,
        });
    }
    Ok(())
}

/// Validate that `value` fits in [`MAX_VALUE_BYTES`].
pub fn check_value(value: &[u8]) -> Result<(), StorageError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(StorageError::ValueTooLarge {
            len: value.len(),
            max: MAX_VALUE_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_labels_are_stable() {
        assert_eq!(StorageError::Backend("x".into()).kind(), "backend");
        assert_eq!(
            StorageError::Timeout(Duration::from_secs(1)).kind(),
            "timeout"
        );
        assert_eq!(
            StorageError::KeyTooLarge { len: 2, max: 1 }.kind(),
            "key_too_large"
        );
        assert_eq!(
            StorageError::ValueTooLarge { len: 2, max: 1 }.kind(),
            "value_too_large"
        );
        assert_eq!(StorageError::Disconnected.kind(), "disconnected");
        assert_eq!(
            StorageError::InvalidConfig("bad".into()).kind(),
            "invalid_config"
        );
    }

    #[test]
    fn check_key_rejects_oversize() {
        let big = "k".repeat(MAX_KEY_BYTES + 1);
        let err = check_key(&big).unwrap_err();
        assert!(matches!(err, StorageError::KeyTooLarge { .. }));
        check_key("ok").expect("small key passes");
    }

    #[test]
    fn check_value_rejects_oversize() {
        let big = vec![0u8; MAX_VALUE_BYTES + 1];
        let err = check_value(&big).unwrap_err();
        assert!(matches!(err, StorageError::ValueTooLarge { .. }));
        check_value(b"ok").expect("small value passes");
    }
}
