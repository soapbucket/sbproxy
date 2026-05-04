//! Realtime session types for the OpenAI Realtime API.
//!
//! Provides configuration, session tracking, and event types for real-time
//! streaming sessions.  WebSocket management is handled by the transport layer;
//! this module defines the shared data structures.

use serde::{Deserialize, Serialize};

/// Configuration for the Realtime API feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeConfig {
    /// Whether the Realtime API is enabled.
    pub enabled: bool,
    /// Default model to use for new sessions (e.g. `gpt-4o-realtime-preview`).
    pub model: String,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: "gpt-4o-realtime-preview".to_string(),
        }
    }
}

/// Lifecycle status of a Realtime session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeStatus {
    /// The session is connected and accepting events.
    Active,
    /// The session has been closed gracefully.
    Closed,
    /// The session encountered an unrecoverable error.
    Error,
}

/// An active or historical Realtime session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeSession {
    /// Unique session identifier assigned by the provider.
    pub session_id: String,
    /// Model in use for this session.
    pub model: String,
    /// ISO-8601 timestamp when the session was created.
    pub created_at: String,
    /// Current lifecycle status.
    pub status: RealtimeStatus,
}

/// A single event exchanged over a Realtime session WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    /// The event type string (e.g. `"response.text.delta"`).
    pub event_type: String,
    /// Arbitrary event payload as returned by the provider.
    pub data: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_config_default() {
        let cfg = RealtimeConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.model.is_empty());
    }

    #[test]
    fn realtime_session_roundtrip() {
        let session = RealtimeSession {
            session_id: "sess_abc123".to_string(),
            model: "gpt-4o-realtime-preview".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            status: RealtimeStatus::Active,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: RealtimeSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "sess_abc123");
        assert_eq!(parsed.status, RealtimeStatus::Active);
    }

    #[test]
    fn realtime_status_serialisation() {
        assert_eq!(
            serde_json::to_string(&RealtimeStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&RealtimeStatus::Closed).unwrap(),
            "\"closed\""
        );
        assert_eq!(
            serde_json::to_string(&RealtimeStatus::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn realtime_event_roundtrip() {
        let event = RealtimeEvent {
            event_type: "response.text.delta".to_string(),
            data: serde_json::json!({ "delta": "Hello" }),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: RealtimeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, "response.text.delta");
        assert_eq!(parsed.data["delta"], "Hello");
    }
}
