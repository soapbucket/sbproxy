//! LLM-aware failure classification and per-error retry policy.
//!
//! Status-code retries treat every 5xx the same and ignore the LLM-specific
//! failure modes a provider signals in the body (a context-window overflow,
//! a content-policy refusal, a rate limit). This module classifies an
//! upstream failure into a [`FailureCause`] and lets an operator set retry
//! counts per error class, so a `429` can be retried while a
//! `context_length_exceeded` is not (it would only fail again) and instead
//! routes to its own fallback list.
//!
//! The classifier is the seam the richer LLM-aware actions build on:
//! a context-window failure can drive compress-and-retry over
//! [`crate::compression`], and a content-policy failure can drive a
//! redact-and-retry, each selected by [`FailureCause::fallback_trigger`].

use serde::Deserialize;

/// The classified cause of an upstream LLM failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureCause {
    /// The request timed out (`408`, `504`).
    Timeout,
    /// The provider rate-limited the request (`429`).
    RateLimit,
    /// The prompt exceeded the model's context window.
    ContextWindowExceeded,
    /// The provider refused on content-policy / safety grounds.
    ContentPolicy,
    /// Authentication or authorization failed (`401`, `403`).
    Auth,
    /// A provider-side server error (`5xx`).
    ServerError,
    /// A malformed request the provider rejected (`400` / `422`).
    BadRequest,
    /// An unclassifiable outcome.
    Unknown,
}

/// Which fallback list a failure should route to, separating the
/// any-error list from the context-window and content-policy lists (the
/// LiteLLM `context_window_fallbacks` / `content_policy_fallbacks` split).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackTrigger {
    /// Route to the general fallback list.
    Any,
    /// Route to a larger-context model.
    ContextWindow,
    /// Route to a more permissive model.
    ContentPolicy,
}

impl FailureCause {
    /// Classify a failure from the HTTP status and (optionally) the
    /// response body. The body refines a `400`/`422` (or even a `200` that
    /// carries a refusal) into a context-window or content-policy cause.
    pub fn classify(status: u16, body: &str) -> FailureCause {
        let lower = body.to_ascii_lowercase();
        let says_context = lower.contains("context_length_exceeded")
            || lower.contains("maximum context length")
            || lower.contains("too many tokens")
            || lower.contains("reduce the length")
            || lower.contains("context window");
        let says_content = lower.contains("content_policy")
            || lower.contains("content_filter")
            || lower.contains("contentpolicy")
            || lower.contains("content-policy")
            || lower.contains("safety system")
            || lower.contains("flagged");

        match status {
            408 | 504 => FailureCause::Timeout,
            429 => FailureCause::RateLimit,
            401 | 403 => FailureCause::Auth,
            400 | 422 => {
                if says_context {
                    FailureCause::ContextWindowExceeded
                } else if says_content {
                    FailureCause::ContentPolicy
                } else {
                    FailureCause::BadRequest
                }
            }
            s if (500..600).contains(&s) => FailureCause::ServerError,
            s if (200..300).contains(&s) => {
                // A 200 can still carry a content-policy refusal in the body.
                if says_content {
                    FailureCause::ContentPolicy
                } else {
                    FailureCause::Unknown
                }
            }
            _ => FailureCause::Unknown,
        }
    }

    /// Whether this cause is worth retrying with no other change. A
    /// transient class (timeout, rate limit, server error) is; a request
    /// that is malformed, unauthorized, refused, or too long would only
    /// fail again, so it is not.
    pub fn is_retryable_default(self) -> bool {
        matches!(
            self,
            FailureCause::Timeout | FailureCause::RateLimit | FailureCause::ServerError
        )
    }

    /// The fallback list this cause should route to.
    pub fn fallback_trigger(self) -> FallbackTrigger {
        match self {
            FailureCause::ContextWindowExceeded => FallbackTrigger::ContextWindow,
            FailureCause::ContentPolicy => FallbackTrigger::ContentPolicy,
            _ => FallbackTrigger::Any,
        }
    }

    /// A stable label for metrics and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureCause::Timeout => "timeout",
            FailureCause::RateLimit => "rate_limit",
            FailureCause::ContextWindowExceeded => "context_window_exceeded",
            FailureCause::ContentPolicy => "content_policy",
            FailureCause::Auth => "auth",
            FailureCause::ServerError => "server_error",
            FailureCause::BadRequest => "bad_request",
            FailureCause::Unknown => "unknown",
        }
    }
}

/// Per-error-class retry counts, mapping the LiteLLM `retry_policy` surface.
/// A `None` for a class means "use the default retryability"; a `Some(n)`
/// caps retries for that class at `n` attempts.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct RetryPolicy {
    /// Retries for a timeout.
    #[serde(default)]
    pub timeout: Option<u32>,
    /// Retries for a rate limit.
    #[serde(default)]
    pub rate_limit: Option<u32>,
    /// Retries for a server error.
    #[serde(default)]
    pub server_error: Option<u32>,
    /// Retries for a content-policy refusal (usually 0; a fallback to a
    /// more permissive model is preferable).
    #[serde(default)]
    pub content_policy: Option<u32>,
    /// Retries for an auth failure (usually 0).
    #[serde(default)]
    pub auth: Option<u32>,
    /// Retries for a malformed request (usually 0).
    #[serde(default)]
    pub bad_request: Option<u32>,
    /// Retries for a context-window overflow (usually 0; compress-and-retry
    /// or a larger-context fallback is preferable).
    #[serde(default)]
    pub context_window: Option<u32>,
}

impl RetryPolicy {
    /// The configured retry count for a cause, if any.
    pub fn retries_for(&self, cause: FailureCause) -> Option<u32> {
        match cause {
            FailureCause::Timeout => self.timeout,
            FailureCause::RateLimit => self.rate_limit,
            FailureCause::ServerError => self.server_error,
            FailureCause::ContentPolicy => self.content_policy,
            FailureCause::Auth => self.auth,
            FailureCause::BadRequest => self.bad_request,
            FailureCause::ContextWindowExceeded => self.context_window,
            FailureCause::Unknown => None,
        }
    }

    /// Whether to retry a request that failed with `cause` on its
    /// `attempt`-th try (zero-based). An explicit per-class count caps the
    /// retries for that class; absent a count, the cause's default
    /// retryability decides. The caller still bounds the total by the
    /// overall `max_attempts`.
    pub fn should_retry(&self, cause: FailureCause, attempt: usize) -> bool {
        match self.retries_for(cause) {
            Some(n) => (attempt as u32) < n,
            None => cause.is_retryable_default(),
        }
    }
}

/// Per-error-class cooldown durations (WOR-2556), the cooldown half of
/// the LiteLLM `RetryPolicy` / `AllowedFailsPolicy` split. Where
/// [`RetryPolicy`] decides whether the *same request* gets another
/// attempt, this decides whether the *provider* keeps taking new
/// requests: a class with a configured duration removes the failing
/// provider from candidate rotation for that many seconds after a
/// failure of that class.
///
/// A `None` for a class means failures of that class never trigger a
/// cooldown (the default, which preserves current behavior exactly). An
/// explicit `0` is the same as `None` and is accepted so an operator can
/// switch a class off without deleting the line.
///
/// The cooldown is advisory in the same sense as the circuit breaker and
/// outlier ejection: when every candidate is cooling down, the router
/// hands back the unfiltered set rather than manufacturing an outage
/// (see `Router::routable_candidate_indices`).
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CooldownPolicy {
    /// Cooldown seconds after a timeout.
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Cooldown seconds after a rate limit. The most common entry: a
    /// `429` is a statement about the provider's capacity, not about
    /// the request, so backing the whole pool off it helps.
    #[serde(default)]
    pub rate_limit: Option<u64>,
    /// Cooldown seconds after a server error.
    #[serde(default)]
    pub server_error: Option<u64>,
    /// Cooldown seconds after a content-policy refusal. Usually unset:
    /// a refusal is about the prompt, not the provider's health.
    #[serde(default)]
    pub content_policy: Option<u64>,
    /// Cooldown seconds after an auth failure. A misconfigured key
    /// fails every request, so a long value here stops a dead
    /// credential from eating an attempt on every request.
    #[serde(default)]
    pub auth: Option<u64>,
    /// Cooldown seconds after a malformed request. Usually unset.
    #[serde(default)]
    pub bad_request: Option<u64>,
    /// Cooldown seconds after a context-window overflow. Usually unset:
    /// the prompt is the problem, and the typed
    /// `context_window_fallbacks` reroute is the aimed tool.
    #[serde(default)]
    pub context_window: Option<u64>,
}

impl CooldownPolicy {
    /// The configured cooldown for a cause, if any. Explicit zeros
    /// normalize to `None` so callers only see actionable durations.
    pub fn cooldown_secs_for(&self, cause: FailureCause) -> Option<u64> {
        let secs = match cause {
            FailureCause::Timeout => self.timeout,
            FailureCause::RateLimit => self.rate_limit,
            FailureCause::ServerError => self.server_error,
            FailureCause::ContentPolicy => self.content_policy,
            FailureCause::Auth => self.auth,
            FailureCause::BadRequest => self.bad_request,
            FailureCause::ContextWindowExceeded => self.context_window,
            FailureCause::Unknown => None,
        };
        secs.filter(|&s| s > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_status_codes() {
        assert_eq!(FailureCause::classify(504, ""), FailureCause::Timeout);
        assert_eq!(FailureCause::classify(429, ""), FailureCause::RateLimit);
        assert_eq!(FailureCause::classify(401, ""), FailureCause::Auth);
        assert_eq!(FailureCause::classify(503, ""), FailureCause::ServerError);
        assert_eq!(FailureCause::classify(400, ""), FailureCause::BadRequest);
        assert_eq!(FailureCause::classify(418, ""), FailureCause::Unknown);
    }

    #[test]
    fn classifies_context_window_from_body() {
        let body = r#"{"error":{"message":"This model's maximum context length is 8192 tokens","code":"context_length_exceeded"}}"#;
        assert_eq!(
            FailureCause::classify(400, body),
            FailureCause::ContextWindowExceeded
        );
        assert_eq!(
            FailureCause::classify(400, body).fallback_trigger(),
            FallbackTrigger::ContextWindow
        );
    }

    #[test]
    fn classifies_content_policy_from_body_even_on_200() {
        let body = r#"{"error":{"message":"Your request was rejected by our safety system","type":"content_policy_violation"}}"#;
        assert_eq!(
            FailureCause::classify(400, body),
            FailureCause::ContentPolicy
        );
        // A 200 carrying a refusal is still a content-policy outcome.
        assert_eq!(
            FailureCause::classify(200, body),
            FailureCause::ContentPolicy
        );
        assert_eq!(
            FailureCause::ContentPolicy.fallback_trigger(),
            FallbackTrigger::ContentPolicy
        );
    }

    #[test]
    fn retryability_defaults() {
        assert!(FailureCause::Timeout.is_retryable_default());
        assert!(FailureCause::RateLimit.is_retryable_default());
        assert!(FailureCause::ServerError.is_retryable_default());
        assert!(!FailureCause::Auth.is_retryable_default());
        assert!(!FailureCause::BadRequest.is_retryable_default());
        assert!(!FailureCause::ContextWindowExceeded.is_retryable_default());
        assert!(!FailureCause::ContentPolicy.is_retryable_default());
    }

    #[test]
    fn cooldown_policy_maps_causes_and_normalizes_zero() {
        let policy: CooldownPolicy =
            serde_json::from_str(r#"{"rate_limit": 30, "auth": 300, "content_policy": 0}"#)
                .unwrap();
        assert_eq!(policy.cooldown_secs_for(FailureCause::RateLimit), Some(30));
        assert_eq!(policy.cooldown_secs_for(FailureCause::Auth), Some(300));
        // Explicit 0 means "no cooldown for this class", same as unset.
        assert_eq!(policy.cooldown_secs_for(FailureCause::ContentPolicy), None);
        assert_eq!(policy.cooldown_secs_for(FailureCause::ServerError), None);
        assert_eq!(policy.cooldown_secs_for(FailureCause::Unknown), None);
    }

    #[test]
    fn cooldown_policy_refuses_unknown_fields() {
        // deny_unknown_fields: a typo must fail the config load, not
        // silently disable the class it was meant to configure.
        let error = serde_json::from_str::<CooldownPolicy>(r#"{"rate_limits": 30}"#)
            .expect_err("a misspelled class must be refused");
        assert!(
            error.to_string().contains("rate_limits"),
            "the error names the unknown key: {error}"
        );
    }

    #[test]
    fn retry_policy_per_error_counts() {
        let policy: RetryPolicy =
            serde_json::from_str(r#"{"rate_limit": 3, "server_error": 1, "content_policy": 0}"#)
                .unwrap();
        // Rate limit retries up to 3 attempts.
        assert!(policy.should_retry(FailureCause::RateLimit, 0));
        assert!(policy.should_retry(FailureCause::RateLimit, 2));
        assert!(!policy.should_retry(FailureCause::RateLimit, 3));
        // Server error capped at 1.
        assert!(policy.should_retry(FailureCause::ServerError, 0));
        assert!(!policy.should_retry(FailureCause::ServerError, 1));
        // Content policy explicitly 0: never retry.
        assert!(!policy.should_retry(FailureCause::ContentPolicy, 0));
        // Timeout has no explicit count: falls back to default retryability.
        assert!(policy.should_retry(FailureCause::Timeout, 0));
        // Auth has no count and is not retryable by default.
        assert!(!policy.should_retry(FailureCause::Auth, 0));
    }
}
