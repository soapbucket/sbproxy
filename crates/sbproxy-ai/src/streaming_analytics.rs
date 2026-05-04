//! Streaming performance analytics: Time to First Token and Tokens Per Second.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

// --- StreamTracker ---

/// Track streaming performance for an active stream.
pub struct StreamTracker {
    /// Identifier of the request being tracked.
    pub request_id: String,
    /// Provider name handling the stream.
    pub provider: String,
    /// Model name producing the stream.
    pub model: String,
    /// Wall-clock instant when tracking began.
    pub start: Instant,
    /// Instant the first token arrived, if any.
    pub first_token: Option<Instant>,
    /// Total tokens observed in the stream so far.
    pub token_count: u64,
    /// Instant the most recent token arrived.
    pub last_token: Option<Instant>,
}

impl StreamTracker {
    /// Create a new tracker for a streaming request.
    pub fn new(request_id: &str, provider: &str, model: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            start: Instant::now(),
            first_token: None,
            token_count: 0,
            last_token: None,
        }
    }

    /// Called when the first token arrives.
    pub fn record_first_token(&mut self) {
        let now = Instant::now();
        if self.first_token.is_none() {
            self.first_token = Some(now);
        }
        self.token_count += 1;
        self.last_token = Some(now);
    }

    /// Called for each subsequent token after the first.
    pub fn record_token(&mut self) {
        let now = Instant::now();
        self.token_count += 1;
        self.last_token = Some(now);
    }

    /// Time to first token in milliseconds.
    ///
    /// Returns `None` if no token has been received yet.
    pub fn ttft_ms(&self) -> Option<f64> {
        self.first_token
            .map(|t| t.duration_since(self.start).as_secs_f64() * 1000.0)
    }

    /// Tokens per second, averaged over the stream lifetime (start to last token).
    ///
    /// Returns `None` if fewer than one token has been received or elapsed time
    /// is zero.
    pub fn tps(&self) -> Option<f64> {
        let last = self.last_token?;
        if self.token_count == 0 {
            return None;
        }
        let elapsed = last.duration_since(self.start).as_secs_f64();
        if elapsed == 0.0 {
            return None;
        }
        Some(self.token_count as f64 / elapsed)
    }

    /// Average inter-token latency (ms between consecutive tokens).
    ///
    /// Computed as (last_token - first_token) / (token_count - 1).
    /// Returns `None` if fewer than two tokens have been received.
    pub fn avg_itl_ms(&self) -> Option<f64> {
        if self.token_count < 2 {
            return None;
        }
        let first = self.first_token?;
        let last = self.last_token?;
        let total_ms = last.duration_since(first).as_secs_f64() * 1000.0;
        Some(total_ms / (self.token_count - 1) as f64)
    }
}

// --- StreamRegistry ---

/// Global registry of active streams for monitoring.
pub struct StreamRegistry {
    active: Mutex<HashMap<String, StreamTracker>>,
}

impl StreamRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new stream and start tracking it.
    pub fn start_stream(&self, request_id: &str, provider: &str, model: &str) {
        let tracker = StreamTracker::new(request_id, provider, model);
        self.active
            .lock()
            .unwrap()
            .insert(request_id.to_string(), tracker);
    }

    /// Record a token arrival for the given stream.
    ///
    /// If this is the first token, `record_first_token` is called on the
    /// tracker; otherwise `record_token` is called.
    pub fn record_token(&self, request_id: &str) {
        if let Some(tracker) = self.active.lock().unwrap().get_mut(request_id) {
            if tracker.first_token.is_none() {
                tracker.record_first_token();
            } else {
                tracker.record_token();
            }
        }
    }

    /// Remove and return the completed tracker for post-stream analysis.
    ///
    /// Returns `None` if no active stream with that ID exists.
    pub fn end_stream(&self, request_id: &str) -> Option<StreamTracker> {
        self.active.lock().unwrap().remove(request_id)
    }

    /// Current number of active (in-flight) streams.
    pub fn active_count(&self) -> usize {
        self.active.lock().unwrap().len()
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // --- StreamTracker tests ---

    #[test]
    fn ttft_none_before_first_token() {
        let tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        assert!(tracker.ttft_ms().is_none());
    }

    #[test]
    fn ttft_some_after_first_token() {
        let mut tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        thread::sleep(Duration::from_millis(10));
        tracker.record_first_token();
        let ttft = tracker
            .ttft_ms()
            .expect("should have TTFT after first token");
        assert!(ttft >= 0.0, "TTFT must be non-negative");
    }

    #[test]
    fn tps_none_before_any_token() {
        let tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        assert!(tracker.tps().is_none());
    }

    #[test]
    fn tps_some_after_tokens() {
        let mut tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        // Sleep to ensure non-zero elapsed time.
        thread::sleep(Duration::from_millis(5));
        tracker.record_first_token();
        thread::sleep(Duration::from_millis(5));
        tracker.record_token();
        thread::sleep(Duration::from_millis(5));
        tracker.record_token();

        let tps = tracker.tps().expect("should have TPS after tokens");
        assert!(tps > 0.0, "TPS must be positive");
        assert_eq!(tracker.token_count, 3);
    }

    #[test]
    fn avg_itl_none_with_single_token() {
        let mut tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        tracker.record_first_token();
        assert!(
            tracker.avg_itl_ms().is_none(),
            "ITL needs at least 2 tokens"
        );
    }

    #[test]
    fn avg_itl_some_with_multiple_tokens() {
        let mut tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        tracker.record_first_token();
        thread::sleep(Duration::from_millis(10));
        tracker.record_token();
        thread::sleep(Duration::from_millis(10));
        tracker.record_token();

        let itl = tracker.avg_itl_ms().expect("should have ITL with 3 tokens");
        assert!(itl >= 0.0, "ITL must be non-negative");
        assert_eq!(tracker.token_count, 3);
    }

    #[test]
    fn record_first_token_sets_first_token_once() {
        let mut tracker = StreamTracker::new("req-1", "openai", "gpt-4");
        tracker.record_first_token();
        let first = tracker.first_token.unwrap();
        // Calling again should NOT overwrite first_token.
        thread::sleep(Duration::from_millis(2));
        tracker.record_first_token();
        assert_eq!(tracker.first_token.unwrap(), first);
        assert_eq!(tracker.token_count, 2);
    }

    // --- StreamRegistry tests ---

    #[test]
    fn registry_active_count_lifecycle() {
        let registry = StreamRegistry::new();
        assert_eq!(registry.active_count(), 0);

        registry.start_stream("r1", "anthropic", "claude-3-5-sonnet");
        registry.start_stream("r2", "openai", "gpt-4o");
        assert_eq!(registry.active_count(), 2);

        registry.end_stream("r1");
        assert_eq!(registry.active_count(), 1);

        registry.end_stream("r2");
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn registry_record_token_first_and_subsequent() {
        let registry = StreamRegistry::new();
        registry.start_stream("req-a", "openai", "gpt-4");

        // First call sets first_token.
        registry.record_token("req-a");
        // Additional calls increment token_count via record_token.
        registry.record_token("req-a");
        registry.record_token("req-a");

        let tracker = registry.end_stream("req-a").expect("tracker must exist");
        assert!(tracker.first_token.is_some());
        assert_eq!(tracker.token_count, 3);
    }

    #[test]
    fn registry_end_stream_unknown_id_returns_none() {
        let registry = StreamRegistry::new();
        assert!(registry.end_stream("does-not-exist").is_none());
    }

    #[test]
    fn registry_end_stream_returns_tracker() {
        let registry = StreamRegistry::new();
        registry.start_stream("req-b", "anthropic", "claude-3-haiku");
        registry.record_token("req-b");

        let tracker = registry
            .end_stream("req-b")
            .expect("tracker should be returned on end");
        assert_eq!(tracker.request_id, "req-b");
        assert_eq!(tracker.provider, "anthropic");
        assert_eq!(tracker.model, "claude-3-haiku");
        assert_eq!(tracker.token_count, 1);
    }

    #[test]
    fn registry_default_is_empty() {
        let registry = StreamRegistry::default();
        assert_eq!(registry.active_count(), 0);
    }
}
