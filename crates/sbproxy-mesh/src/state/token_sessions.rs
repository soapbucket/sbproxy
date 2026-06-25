//! Encode session state in tokens (no server-side store needed).
//!
//! Session data is serialized to JSON, base64url-encoded (no padding), and
//! handed to the client. On subsequent requests the token is decoded and
//! validated. This eliminates any server-side session storage requirement.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// A session token carrying arbitrary JSON data with an expiry timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// Unique identifier for this session.
    pub session_id: String,
    /// Arbitrary session data as a JSON value.
    pub data: serde_json::Value,
    /// Unix timestamp (seconds) when this token was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) after which this token is expired.
    pub expires_at: u64,
}

/// Encode session state as a URL-safe base64 token (no padding).
pub fn encode_token(session: &SessionToken) -> anyhow::Result<String> {
    let json = serde_json::to_vec(session)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
}

/// Decode a session token from a URL-safe base64 string.
pub fn decode_token(token: &str) -> anyhow::Result<SessionToken> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Returns true if the token's `expires_at` is in the past.
pub fn is_expired(token: &SessionToken) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > token.expires_at
}

/// Return the number of seconds until this token expires, or 0 if already expired.
pub fn ttl_secs(token: &SessionToken) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    token.expires_at.saturating_sub(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn future_token() -> SessionToken {
        SessionToken {
            session_id: "sess-abc".to_string(),
            data: json!({"user": "alice", "role": "admin"}),
            created_at: 1_700_000_000,
            expires_at: u64::MAX,
        }
    }

    fn past_token() -> SessionToken {
        SessionToken {
            session_id: "sess-expired".to_string(),
            data: json!({"user": "bob"}),
            created_at: 1_000_000,
            expires_at: 1_000_001,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let session = future_token();
        let token = encode_token(&session).expect("encode");
        let decoded = decode_token(&token).expect("decode");
        assert_eq!(decoded.session_id, "sess-abc");
        assert_eq!(decoded.created_at, 1_700_000_000);
        assert_eq!(decoded.expires_at, u64::MAX);
    }

    #[test]
    fn data_preserved_through_roundtrip() {
        let session = future_token();
        let token = encode_token(&session).expect("encode");
        let decoded = decode_token(&token).expect("decode");
        assert_eq!(decoded.data["user"], json!("alice"));
        assert_eq!(decoded.data["role"], json!("admin"));
    }

    #[test]
    fn expired_token_is_detected() {
        let session = past_token();
        assert!(is_expired(&session), "old token should be expired");
    }

    #[test]
    fn future_token_is_not_expired() {
        let session = future_token();
        assert!(
            !is_expired(&session),
            "far-future token should not be expired"
        );
    }

    #[test]
    fn ttl_is_zero_for_expired_token() {
        let session = past_token();
        assert_eq!(ttl_secs(&session), 0);
    }

    #[test]
    fn ttl_is_nonzero_for_valid_token() {
        let session = future_token();
        assert!(ttl_secs(&session) > 0);
    }

    #[test]
    fn decode_invalid_base64_returns_error() {
        let result = decode_token("not-valid-base64!!!!");
        assert!(result.is_err());
    }

    #[test]
    fn decode_valid_base64_but_invalid_json_returns_error() {
        let garbage = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json at all");
        let result = decode_token(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn encoded_token_is_url_safe() {
        let session = future_token();
        let token = encode_token(&session).expect("encode");
        // URL-safe characters only (no +, /, or = padding)
        for ch in token.chars() {
            assert!(
                ch.is_alphanumeric() || ch == '-' || ch == '_',
                "token contains non-URL-safe char: {ch}"
            );
        }
    }

    #[test]
    fn different_sessions_produce_different_tokens() {
        let s1 = future_token();
        let mut s2 = future_token();
        s2.session_id = "sess-xyz".to_string();
        let t1 = encode_token(&s1).expect("encode");
        let t2 = encode_token(&s2).expect("encode");
        assert_ne!(t1, t2);
    }
}
