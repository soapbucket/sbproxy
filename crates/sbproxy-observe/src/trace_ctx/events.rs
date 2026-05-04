//! Span event helpers for significant occurrences.
//!
//! Each function records a structured tracing event that gets attached to the
//! currently active span (if any) or emitted as a standalone log record.

/// Emit an event recording a cache hit.
///
/// `cache_type` identifies the cache layer, e.g. `"semantic"`, `"response"`,
/// or `"prompt"`.
pub fn cache_hit_event(cache_type: &str) {
    tracing::info!(event = "cache_hit", cache_type = cache_type);
}

/// Emit an event recording a cache miss.
///
/// `cache_type` identifies the cache layer, e.g. `"semantic"`, `"response"`,
/// or `"prompt"`.
pub fn cache_miss_event(cache_type: &str) {
    tracing::info!(event = "cache_miss", cache_type = cache_type);
}

/// Emit an event recording a failover between two upstreams or providers.
///
/// `from` is the origin that failed, `to` is the target being switched to,
/// and `reason` is a short human-readable explanation (e.g. `"timeout"`,
/// `"circuit_open"`).
pub fn failover_event(from: &str, to: &str, reason: &str) {
    tracing::warn!(event = "failover", from = from, to = to, reason = reason);
}

/// Emit an event recording that a guardrail blocked a request.
///
/// `category` is the guardrail rule category (e.g. `"content_policy"`) and
/// `reason` is the specific sub-reason or rule that triggered.
pub fn guardrail_block_event(category: &str, reason: &str) {
    tracing::warn!(
        event = "guardrail_block",
        category = category,
        reason = reason
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_event_does_not_panic() {
        cache_hit_event("semantic");
    }

    #[test]
    fn cache_miss_event_does_not_panic() {
        cache_miss_event("response");
    }

    #[test]
    fn failover_event_does_not_panic() {
        failover_event("primary.example.com", "fallback.example.com", "timeout");
    }

    #[test]
    fn guardrail_block_event_does_not_panic() {
        guardrail_block_event("content_policy", "profanity_detected");
    }

    #[test]
    fn all_event_helpers_run_in_sequence() {
        // Run all helpers in a single test to confirm there is no shared
        // mutable state that would cause ordering issues.
        cache_hit_event("prompt");
        cache_miss_event("semantic");
        failover_event("svc-a", "svc-b", "circuit_open");
        guardrail_block_event("pii_detection", "email_address");
    }
}
