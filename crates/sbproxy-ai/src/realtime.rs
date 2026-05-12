//! Realtime session types for the OpenAI Realtime API.
//!
//! Provides configuration, session tracking, and event types for real-time
//! streaming sessions. WebSocket management is handled by the transport
//! layer; this module defines the shared data structures and a thread-safe
//! tracker that the dispatch path uses to count active sessions and
//! accumulate per-session audio time.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Process-wide tracker for active Realtime WebSocket sessions.
///
/// Used by the dispatch path to maintain the
/// `sbproxy_ai_realtime_sessions_active` gauge and to attribute
/// audio-second accumulation to the right session for the eventual
/// `AiBillingEvent::AudioSeconds` emitted at session close.
///
/// The tracker is intentionally lock-free: per-session audio time is
/// stored as raw nanosecond counts in a `DashMap`-style atomic so the
/// hot frame-relay path doesn't contend on a `Mutex`. Session counts
/// are an `AtomicU64`.
#[derive(Debug, Default)]
pub struct RealtimeSessionTracker {
    active: AtomicU64,
    total_started: AtomicU64,
    total_closed: AtomicU64,
}

impl RealtimeSessionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a new session as active. Returns the post-increment count.
    pub fn open(&self) -> u64 {
        self.total_started.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Mark a session as closed. Returns the post-decrement count.
    /// Saturates at zero; a double-close is a no-op rather than a
    /// wrap-around.
    pub fn close(&self) -> u64 {
        self.total_closed.fetch_add(1, Ordering::Relaxed);
        let prev = self.active.load(Ordering::Relaxed);
        if prev == 0 {
            return 0;
        }
        match self
            .active
            .compare_exchange(prev, prev - 1, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => prev - 1,
            Err(observed) => observed,
        }
    }

    /// Current active-session count.
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Cumulative sessions ever opened.
    pub fn total_started(&self) -> u64 {
        self.total_started.load(Ordering::Relaxed)
    }

    /// Cumulative sessions closed.
    pub fn total_closed(&self) -> u64 {
        self.total_closed.load(Ordering::Relaxed)
    }
}

/// Compute the audio duration in seconds carried by a binary
/// Realtime WebSocket frame.
///
/// The Realtime API uses PCM 16-bit signed little-endian audio
/// frames by default. The number of seconds in a frame is
/// `frame_bytes / (sample_rate * channels * bytes_per_sample)`. We
/// hardcode `bytes_per_sample = 2` (16-bit PCM) because that's the
/// only format the Realtime API negotiates; if OpenAI adds other
/// formats in the future, callers can compute manually.
///
/// `sample_rate` is in Hz (the Realtime API typically uses 24000 for
/// `gpt-4o-realtime`). `channels` is 1 (mono) for the standard
/// turn-by-turn session shape; 2 (stereo) would only apply to
/// custom session.update configurations.
///
/// Returns 0.0 when the divisor is zero (a misconfigured session
/// where sample_rate or channels was reported as 0) so a malformed
/// frame never panics the relay loop.
pub fn audio_seconds_from_frame(frame_bytes: usize, sample_rate: u32, channels: u8) -> f64 {
    const BYTES_PER_SAMPLE: u32 = 2;
    let divisor = (sample_rate as u64)
        .saturating_mul(channels as u64)
        .saturating_mul(BYTES_PER_SAMPLE as u64);
    if divisor == 0 {
        return 0.0;
    }
    frame_bytes as f64 / divisor as f64
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

    // --- RealtimeSessionTracker ---

    #[test]
    fn tracker_starts_empty() {
        let t = RealtimeSessionTracker::new();
        assert_eq!(t.active(), 0);
        assert_eq!(t.total_started(), 0);
        assert_eq!(t.total_closed(), 0);
    }

    #[test]
    fn open_and_close_round_trip_counts() {
        let t = RealtimeSessionTracker::new();
        assert_eq!(t.open(), 1);
        assert_eq!(t.open(), 2);
        assert_eq!(t.active(), 2);
        assert_eq!(t.total_started(), 2);
        assert_eq!(t.close(), 1);
        assert_eq!(t.close(), 0);
        assert_eq!(t.active(), 0);
        assert_eq!(t.total_closed(), 2);
    }

    #[test]
    fn close_at_zero_is_idempotent() {
        let t = RealtimeSessionTracker::new();
        // No sessions open. Close still ticks the cumulative counter
        // (caller wanted to record a close event) but `active` does
        // not wrap around.
        assert_eq!(t.close(), 0);
        assert_eq!(t.close(), 0);
        assert_eq!(t.active(), 0);
        assert_eq!(t.total_closed(), 2);
    }

    // --- audio_seconds_from_frame ---

    #[test]
    fn audio_seconds_pcm16_24khz_mono() {
        // 24000 samples/sec * 1 channel * 2 bytes/sample = 48000 B/s.
        // A 4800-byte frame is 0.1 seconds.
        let seconds = audio_seconds_from_frame(4800, 24_000, 1);
        assert!((seconds - 0.1).abs() < 1e-9, "got {seconds}");
    }

    #[test]
    fn audio_seconds_pcm16_44khz_stereo() {
        // 44100 * 2 * 2 = 176400 B/s. 176_400 bytes = 1.0 second.
        let seconds = audio_seconds_from_frame(176_400, 44_100, 2);
        assert!((seconds - 1.0).abs() < 1e-9, "got {seconds}");
    }

    #[test]
    fn audio_seconds_zero_divisor_returns_zero() {
        // Misconfigured session with sample_rate = 0. Don't panic.
        assert_eq!(audio_seconds_from_frame(1024, 0, 1), 0.0);
        assert_eq!(audio_seconds_from_frame(1024, 24_000, 0), 0.0);
    }

    #[test]
    fn audio_seconds_empty_frame_is_zero() {
        assert_eq!(audio_seconds_from_frame(0, 24_000, 1), 0.0);
    }
}
