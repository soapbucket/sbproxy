//! Provider rate limit tracking.
//!
//! Parses rate limit headers from provider responses into advisory
//! [`ProviderQuotaSnapshot`] values. Pre-emptively throttles when
//! remaining capacity falls below the configured fraction of a *known*
//! limit. Unknown or stale signals do not invent hard guarantees.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How trustworthy a quota observation is for advisory routing.
///
/// Callers must not treat [`QuotaSignalQuality::Unknown`] or
/// [`QuotaSignalQuality::Stale`] as hard capacity guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaSignalQuality {
    /// Fresh header-derived observation within the freshness window.
    KnownFresh,
    /// Previously observed but aged past freshness or cleared after reset.
    Stale,
    /// Never observed; must not invent capacity.
    Unknown,
}

/// Where a quota observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaSignalSource {
    /// Parsed from upstream provider response headers.
    ProviderHeaders,
    /// Inferred from local token_rate counters (advisory fallback).
    InferredTokenRate,
    /// No signal available.
    None,
}

/// Advisory snapshot of a provider's remaining quota.
///
/// Unknown or stale signals must not invent hard guarantees. Admission
/// and routing that need certainty must treat non-KnownFresh as "no advice".
#[derive(Debug, Clone)]
pub struct ProviderQuotaSnapshot {
    /// Remaining requests in the current window, when reported.
    pub remaining_requests: Option<u64>,
    /// Remaining tokens in the current window, when reported.
    pub remaining_tokens: Option<u64>,
    /// Request limit for the current window, when reported.
    pub limit_requests: Option<u64>,
    /// Token limit for the current window, when reported.
    pub limit_tokens: Option<u64>,
    /// Absolute Instant when the window is expected to reset.
    pub reset_at: Option<Instant>,
    /// Freshness / certainty of this observation.
    pub quality: QuotaSignalQuality,
    /// Origin of the observation.
    pub source: QuotaSignalSource,
    /// When this snapshot was last updated from a signal.
    pub last_updated: Instant,
}

impl ProviderQuotaSnapshot {
    /// Empty advisory snapshot: no invented capacity.
    pub fn unknown() -> Self {
        Self {
            remaining_requests: None,
            remaining_tokens: None,
            limit_requests: None,
            limit_tokens: None,
            reset_at: None,
            quality: QuotaSignalQuality::Unknown,
            source: QuotaSignalSource::None,
            last_updated: Instant::now(),
        }
    }

    /// Request pressure in `[0.0, 1.0]` when both remaining and limit are
    /// known on a fresh signal. `None` otherwise (do not invent).
    pub fn request_pressure(&self) -> Option<f64> {
        if self.quality != QuotaSignalQuality::KnownFresh {
            return None;
        }
        let limit = self.limit_requests?;
        if limit == 0 {
            return None;
        }
        let remaining = self.remaining_requests?;
        Some(1.0 - (remaining as f64 / limit as f64))
    }

    /// True when a fresh signal reports remaining requests or tokens > 0.
    pub fn has_positive_capacity(&self) -> bool {
        if self.quality != QuotaSignalQuality::KnownFresh {
            return false;
        }
        matches!(self.remaining_requests, Some(r) if r > 0)
            || matches!(self.remaining_tokens, Some(t) if t > 0)
    }
}

/// Current rate limit state observed from a provider's response headers.
#[derive(Debug, Clone)]
pub struct ProviderRateState {
    /// Remaining requests allowed in the current window (if reported).
    pub remaining_requests: Option<u64>,
    /// Remaining tokens allowed in the current window (if reported).
    pub remaining_tokens: Option<u64>,
    /// Request limit for the current window (if reported).
    pub limit_requests: Option<u64>,
    /// Token limit for the current window (if reported).
    pub limit_tokens: Option<u64>,
    /// When the rate limit window resets.
    pub reset_at: Option<Instant>,
    /// When this state was last updated.
    pub last_updated: Instant,
}

impl ProviderRateState {
    fn to_snapshot(&self, now: Instant, freshness: Duration) -> ProviderQuotaSnapshot {
        let quality = if self.reset_at.is_some_and(|r| now >= r)
            || now.saturating_duration_since(self.last_updated) > freshness
        {
            QuotaSignalQuality::Stale
        } else {
            QuotaSignalQuality::KnownFresh
        };
        ProviderQuotaSnapshot {
            remaining_requests: self.remaining_requests,
            remaining_tokens: self.remaining_tokens,
            limit_requests: self.limit_requests,
            limit_tokens: self.limit_tokens,
            reset_at: self.reset_at,
            quality,
            source: QuotaSignalSource::ProviderHeaders,
            last_updated: self.last_updated,
        }
    }
}

/// How long a header-derived observation stays [`QuotaSignalQuality::KnownFresh`].
const DEFAULT_FRESHNESS: Duration = Duration::from_secs(60);

/// Tracks rate limit state across providers and pre-emptively throttles
/// when remaining capacity falls below the configured threshold of a
/// *known* limit.
pub struct ProviderRateLimitTracker {
    /// provider_name -> rate state
    state: Mutex<HashMap<String, ProviderRateState>>,
    /// Pre-emptive throttle threshold (0.0 - 1.0).
    /// Throttling is triggered when remaining / limit <= threshold.
    /// Default: 0.1 (throttle at 10% remaining or below).
    throttle_threshold: f64,
    /// Freshness window for advisory snapshots.
    freshness: Duration,
}

impl ProviderRateLimitTracker {
    /// Create a new tracker with the given throttle threshold (0.0 - 1.0).
    pub fn new(throttle_threshold: f64) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            throttle_threshold: throttle_threshold.clamp(0.0, 1.0),
            freshness: DEFAULT_FRESHNESS,
        }
    }

    /// Update the rate state for a provider from response headers.
    ///
    /// Recognized headers (case-insensitive):
    /// - `x-ratelimit-remaining-requests` / `x-ratelimit-remaining-tokens`
    /// - `x-ratelimit-limit-requests` / `x-ratelimit-limit-tokens`
    /// - `x-ratelimit-reset-requests` (seconds until reset, e.g. `"1s"` or `"500ms"`)
    /// - `retry-after` (delta-seconds or HTTP-date)
    /// - Anthropic variants: `anthropic-ratelimit-requests-remaining`,
    ///   `anthropic-ratelimit-tokens-remaining`,
    ///   `anthropic-ratelimit-requests-reset`,
    ///   `anthropic-ratelimit-requests-limit`,
    ///   `anthropic-ratelimit-tokens-limit`
    pub fn update_from_headers(&self, provider: &str, headers: &[(String, String)]) {
        self.update_from_headers_with_status(provider, headers, 200);
    }

    /// Like [`Self::update_from_headers`], but a `429` status marks
    /// remaining requests as exhausted when the headers omit an explicit
    /// remaining count.
    pub fn update_from_headers_with_status(
        &self,
        provider: &str,
        headers: &[(String, String)],
        status: u16,
    ) {
        let mut remaining_requests: Option<u64> = None;
        let mut remaining_tokens: Option<u64> = None;
        let mut limit_requests: Option<u64> = None;
        let mut limit_tokens: Option<u64> = None;
        let mut reset_secs: Option<f64> = None;

        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            match name_lower.as_str() {
                "x-ratelimit-remaining-requests" | "anthropic-ratelimit-requests-remaining" => {
                    remaining_requests = value.parse().ok();
                }
                "x-ratelimit-remaining-tokens" | "anthropic-ratelimit-tokens-remaining" => {
                    remaining_tokens = value.parse().ok();
                }
                "x-ratelimit-limit-requests" | "anthropic-ratelimit-requests-limit" => {
                    limit_requests = value.parse().ok();
                }
                "x-ratelimit-limit-tokens" | "anthropic-ratelimit-tokens-limit" => {
                    limit_tokens = value.parse().ok();
                }
                "x-ratelimit-reset-requests"
                | "x-ratelimit-reset-tokens"
                | "anthropic-ratelimit-requests-reset" => {
                    if let Some(secs) = parse_duration_header(value) {
                        reset_secs = Some(reset_secs.map_or(secs, |prev: f64| prev.max(secs)));
                    }
                }
                "retry-after" => {
                    if let Some(secs) = parse_retry_after(value) {
                        reset_secs = Some(reset_secs.map_or(secs, |prev: f64| prev.max(secs)));
                    }
                }
                _ => {}
            }
        }

        if status == 429 && remaining_requests.is_none() {
            remaining_requests = Some(0);
        }

        // Only update if we got at least something useful
        if remaining_requests.is_none()
            && remaining_tokens.is_none()
            && limit_requests.is_none()
            && limit_tokens.is_none()
            && reset_secs.is_none()
        {
            return;
        }

        let reset_at = reset_secs.map(|s| Instant::now() + Duration::from_secs_f64(s.max(0.0)));

        let mut state = self.state.lock();
        let entry = state
            .entry(provider.to_string())
            .or_insert_with(|| ProviderRateState {
                remaining_requests: None,
                remaining_tokens: None,
                limit_requests: None,
                limit_tokens: None,
                reset_at: None,
                last_updated: Instant::now(),
            });

        if remaining_requests.is_some() {
            entry.remaining_requests = remaining_requests;
        }
        if remaining_tokens.is_some() {
            entry.remaining_tokens = remaining_tokens;
        }
        if limit_requests.is_some() {
            entry.limit_requests = limit_requests;
        }
        if limit_tokens.is_some() {
            entry.limit_tokens = limit_tokens;
        }
        if reset_at.is_some() {
            entry.reset_at = reset_at;
        }
        entry.last_updated = Instant::now();
    }

    /// Advisory snapshot for a provider. Never invents capacity for
    /// unknown providers.
    pub fn snapshot(&self, provider: &str) -> ProviderQuotaSnapshot {
        let now = Instant::now();
        let mut state = self.state.lock();
        let Some(entry) = state.get_mut(provider) else {
            return ProviderQuotaSnapshot::unknown();
        };

        // Clear expired windows so subsequent reads stay honest.
        if let Some(reset_at) = entry.reset_at {
            if now >= reset_at {
                entry.remaining_requests = None;
                entry.remaining_tokens = None;
                entry.reset_at = None;
                return ProviderQuotaSnapshot {
                    remaining_requests: None,
                    remaining_tokens: None,
                    limit_requests: entry.limit_requests,
                    limit_tokens: entry.limit_tokens,
                    reset_at: None,
                    quality: QuotaSignalQuality::Stale,
                    source: QuotaSignalSource::ProviderHeaders,
                    last_updated: entry.last_updated,
                };
            }
        }

        entry.to_snapshot(now, self.freshness)
    }

    /// Return true if the provider should be pre-emptively throttled.
    ///
    /// Throttles when:
    /// - remaining_requests == 0, OR
    /// - remaining_tokens == 0, OR
    /// - both remaining and limit are known and
    ///   remaining <= floor(limit * threshold)
    ///
    /// Does NOT throttle if no state is recorded, or if remaining is
    /// known without a limit (no synthetic denominator).
    /// Clears stale throttle state after the reset window has passed.
    pub fn should_throttle(&self, provider: &str) -> bool {
        let mut state = self.state.lock();
        let Some(entry) = state.get_mut(provider) else {
            return false;
        };

        // If reset window has passed, clear throttle state
        if let Some(reset_at) = entry.reset_at {
            if Instant::now() >= reset_at {
                entry.remaining_requests = None;
                entry.remaining_tokens = None;
                entry.reset_at = None;
                return false;
            }
        }

        // Hard block: no requests left
        if entry.remaining_requests == Some(0) {
            return true;
        }
        if entry.remaining_tokens == Some(0) {
            return true;
        }

        // Pre-emptive throttle against a *real* limit only.
        if let (Some(remaining), Some(limit)) = (entry.remaining_requests, entry.limit_requests) {
            if limit > 0 {
                let threshold_abs = ((limit as f64) * self.throttle_threshold) as u64;
                if remaining <= threshold_abs {
                    return true;
                }
            }
        }

        false
    }

    /// Get the current rate state for a provider, if any has been recorded.
    pub fn get_state(&self, provider: &str) -> Option<ProviderRateState> {
        self.state.lock().get(provider).cloned()
    }
}

/// Parse a duration header value like `"1s"`, `"500ms"`, `"2.5s"`, or plain `"60"` (seconds).
fn parse_duration_header(value: &str) -> Option<f64> {
    let v = value.trim();
    if let Some(ms_str) = v.strip_suffix("ms") {
        return ms_str.trim().parse::<f64>().ok().map(|ms| ms / 1000.0);
    }
    if let Some(s_str) = v.strip_suffix('s') {
        return s_str.trim().parse::<f64>().ok();
    }
    // Plain numeric value - treat as seconds
    v.parse::<f64>().ok()
}

/// Parse `Retry-After` as delta-seconds or HTTP-date (IMF-fix / RFC 2822).
fn parse_retry_after(value: &str) -> Option<f64> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<f64>() {
        return Some(secs.max(0.0));
    }
    // HTTP-date: "Wed, 21 Oct 2015 07:28:00 GMT"
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(v) {
        let now = chrono::Utc::now();
        let delta = dt.with_timezone(&chrono::Utc).signed_duration_since(now);
        return Some(delta.num_milliseconds().max(0) as f64 / 1000.0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- update_from_headers tests ---

    #[test]
    fn update_from_openai_style_headers() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "500"),
                ("x-ratelimit-remaining-tokens", "50000"),
                ("x-ratelimit-reset-requests", "30s"),
            ]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(500));
        assert_eq!(state.remaining_tokens, Some(50000));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn update_from_anthropic_style_headers() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "anthropic",
            &headers(&[
                ("anthropic-ratelimit-requests-remaining", "200"),
                ("anthropic-ratelimit-tokens-remaining", "100000"),
                ("anthropic-ratelimit-requests-reset", "60s"),
            ]),
        );

        let state = tracker.get_state("anthropic").unwrap();
        assert_eq!(state.remaining_requests, Some(200));
        assert_eq!(state.remaining_tokens, Some(100000));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn update_from_retry_after_header() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("retry-after", "5"),
            ]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(0));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn empty_headers_do_not_create_state() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers("openai", &headers(&[]));
        assert!(tracker.get_state("openai").is_none());
    }

    #[test]
    fn parse_millisecond_duration_header() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "10"),
                ("x-ratelimit-reset-requests", "500ms"),
            ]),
        );
        let state = tracker.get_state("openai").unwrap();
        assert!(state.reset_at.is_some());
    }

    // --- should_throttle tests ---

    #[test]
    fn throttle_when_remaining_requests_is_zero() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "0")]),
        );
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn throttle_when_remaining_tokens_is_zero() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers("openai", &headers(&[("x-ratelimit-remaining-tokens", "0")]));
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn throttle_when_remaining_below_threshold() {
        // Threshold 0.1 with real limit 1000 -> throttle at <= 100 remaining.
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-limit-requests", "1000"),
                ("x-ratelimit-remaining-requests", "50"),
            ]),
        );
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn no_throttle_when_plenty_remaining() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-limit-requests", "1000"),
                ("x-ratelimit-remaining-requests", "800"),
            ]),
        );
        assert!(!tracker.should_throttle("openai"));
    }

    #[test]
    fn no_throttle_for_unknown_provider() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        assert!(!tracker.should_throttle("unknown-provider"));
    }

    #[test]
    fn no_throttle_after_reset_window_expires() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        // Set remaining=0 with an already-expired reset (0 seconds in the future)
        {
            let mut state = tracker.state.lock();
            state.insert(
                "openai".to_string(),
                ProviderRateState {
                    remaining_requests: Some(0),
                    remaining_tokens: None,
                    limit_requests: None,
                    limit_tokens: None,
                    // Already expired: reset_at is in the past
                    reset_at: Some(Instant::now() - Duration::from_secs(1)),
                    last_updated: Instant::now(),
                },
            );
        }

        // After the reset window, should no longer throttle
        assert!(!tracker.should_throttle("openai"));
    }

    #[test]
    fn different_providers_tracked_independently() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "0")]),
        );
        tracker.update_from_headers(
            "anthropic",
            &headers(&[("anthropic-ratelimit-requests-remaining", "500")]),
        );

        assert!(tracker.should_throttle("openai"));
        assert!(!tracker.should_throttle("anthropic"));
    }

    #[test]
    fn state_is_updated_incrementally() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        // First update: requests only
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "100")]),
        );

        // Second update: tokens only (requests should be preserved)
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-tokens", "5000")]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(100));
        assert_eq!(state.remaining_tokens, Some(5000));
    }

    // --- WOR-1881: ProviderQuotaSnapshot + real limits + Retry-After ---

    #[test]
    fn parses_limit_and_remaining_headers_into_snapshot() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-limit-requests", "1000"),
                ("x-ratelimit-remaining-requests", "250"),
                ("x-ratelimit-limit-tokens", "90000"),
                ("x-ratelimit-remaining-tokens", "12000"),
                ("x-ratelimit-reset-requests", "30s"),
            ]),
        );

        let snap = tracker.snapshot("openai");
        assert_eq!(snap.limit_requests, Some(1000));
        assert_eq!(snap.remaining_requests, Some(250));
        assert_eq!(snap.limit_tokens, Some(90000));
        assert_eq!(snap.remaining_tokens, Some(12000));
        assert!(snap.reset_at.is_some());
        assert_eq!(snap.quality, QuotaSignalQuality::KnownFresh);
        assert_eq!(snap.source, QuotaSignalSource::ProviderHeaders);
        // Real limit: pressure = 1 - 250/1000 = 0.75
        assert!((snap.request_pressure().unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn snapshot_unknown_when_never_observed() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        let snap = tracker.snapshot("ghost");
        assert_eq!(snap.quality, QuotaSignalQuality::Unknown);
        assert_eq!(snap.source, QuotaSignalSource::None);
        assert!(snap.request_pressure().is_none());
    }

    #[test]
    fn throttle_uses_real_limit_not_synthetic_thousand() {
        // Threshold 0.1 with real limit 50: throttle at remaining <= 5.
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-limit-requests", "50"),
                ("x-ratelimit-remaining-requests", "6"),
            ]),
        );
        assert!(
            !tracker.should_throttle("openai"),
            "6/50 is above 10% threshold; must not use synthetic 1000-req baseline"
        );
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "5")]),
        );
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn remaining_without_limit_does_not_invent_throttle_threshold() {
        // Without a known limit, remaining alone must not invent a hard
        // guarantee via a synthetic denominator.
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "50")]),
        );
        assert!(!tracker.should_throttle("openai"));
        let snap = tracker.snapshot("openai");
        assert!(snap.request_pressure().is_none());
    }

    #[test]
    fn retry_after_delta_seconds_sets_reset_at() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        let before = Instant::now();
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("retry-after", "5"),
            ]),
        );
        let snap = tracker.snapshot("openai");
        let reset = snap.reset_at.expect("reset_at from Retry-After delta");
        let elapsed = reset.saturating_duration_since(before);
        assert!(
            elapsed >= Duration::from_secs(4) && elapsed <= Duration::from_secs(6),
            "delta-seconds Retry-After should land ~5s ahead, got {elapsed:?}"
        );
    }

    #[test]
    fn retry_after_http_date_sets_reset_at() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        let target = chrono::Utc::now() + chrono::Duration::seconds(8);
        let http_date = target.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let before = Instant::now();
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("retry-after", &http_date),
            ]),
        );
        let snap = tracker.snapshot("openai");
        let reset = snap.reset_at.expect("reset_at from Retry-After HTTP-date");
        let elapsed = reset.saturating_duration_since(before);
        assert!(
            elapsed >= Duration::from_secs(6) && elapsed <= Duration::from_secs(10),
            "HTTP-date Retry-After should land ~8s ahead, got {elapsed:?}"
        );
    }

    #[test]
    fn status_429_marks_remaining_requests_exhausted() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers_with_status("openai", &headers(&[("retry-after", "2")]), 429);
        let snap = tracker.snapshot("openai");
        assert_eq!(snap.remaining_requests, Some(0));
        assert!(snap.reset_at.is_some());
        assert_eq!(snap.quality, QuotaSignalQuality::KnownFresh);
        assert!(tracker.should_throttle("openai"));
    }
}
