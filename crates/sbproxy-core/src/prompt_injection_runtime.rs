//! Runtime observability for an unavailable `prompt_injection_v2` detector.
//!
//! The request consumers all funnel through [`record_unavailable`] so metric,
//! structured event, bounded admin state, and rate-limited warning labels
//! cannot drift. Only configured origin identifiers and closed vocabularies
//! enter the state. Prompt text, classifier endpoints, model paths, bearer
//! material, and dependency error strings are never accepted by this API.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use sbproxy_modules::{DetectionFailure, DetectionFailureStage, PromptInjectionAction};
use serde::Serialize;

const MAX_FAILURE_KEYS: usize = 256;
const WARNING_INTERVAL: Duration = Duration::from_secs(60);
const UNMATCHED_ORIGIN: &str = "__unmatched__";

/// Generic fail-closed response for a mandatory unavailable classifier.
pub(crate) const UNAVAILABLE_STATUS: u16 = 503;
/// The response deliberately reveals neither which control failed nor why.
pub(crate) const UNAVAILABLE_BODY: &str = "service unavailable";
/// Stable media type for the generic unavailable response.
pub(crate) const UNAVAILABLE_CONTENT_TYPE: &str = "text/plain";

/// Request outcome after the classifier became unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnavailableDecision {
    /// The block action refused before provider dispatch.
    Blocked,
    /// Tag/log policy continued while explicitly waiving classification.
    Degraded,
}

impl UnavailableDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Degraded => "degraded",
        }
    }
}

/// Record an unavailable classification against a request's pinned,
/// configured origin and attach the typed policy decision to its admin-ring
/// context. Caller-supplied Host bytes are never used as the aggregation key.
pub(crate) fn record_for_request(
    ctx: &mut crate::context::RequestContext,
    scan_path: &'static str,
    action: PromptInjectionAction,
    outcome: UnavailableDecision,
    failure: DetectionFailure,
) {
    let origin_id = ctx
        .origin_idx
        .and_then(|index| ctx.pipeline.config.origins.get(index))
        .map(|origin| origin.origin_id.to_string());
    let tenant_id = ctx.tenant_id.to_string();
    let request_id = ctx.request_id.to_string();
    ctx.record_policy_decision(
        "prompt_injection_v2",
        match outcome {
            UnavailableDecision::Blocked => "blocked_unavailable",
            UnavailableDecision::Degraded => "degraded",
        },
    );
    record_unavailable(
        origin_id.as_deref(),
        tenant_id.as_str(),
        (!request_id.is_empty()).then_some(request_id.as_str()),
        scan_path,
        action,
        outcome,
        failure,
    );
}

/// Bounded admin row for one configured origin and closed failure stage.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PromptInjectionFailureHealth {
    /// Configured origin identifier, or the fixed unmatched sentinel.
    pub origin_id: String,
    /// Closed detector stage.
    pub stage: &'static str,
    /// Closed failure reason.
    pub reason: &'static str,
    /// All failures observed for this origin, stage, and reason.
    pub failures_total: u64,
    /// Failures whose effective policy action refused the request.
    pub blocked_total: u64,
    /// Failures whose effective tag/log action continued as degraded.
    pub degraded_total: u64,
    /// Aggregated warning records emitted for this key.
    pub warnings_emitted: u64,
    /// Repeated warnings suppressed inside the aggregation interval.
    pub warnings_suppressed: u64,
    /// Latest observation time as Unix epoch milliseconds.
    pub last_seen_unix_ms: u64,
    /// Closed scan path of the latest observation.
    pub last_scan_path: &'static str,
    /// Effective action of the latest observation.
    pub last_action: &'static str,
    /// Blocked or degraded outcome of the latest observation.
    pub last_outcome: &'static str,
}

/// Bounded process snapshot returned by the authenticated admin route.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PromptInjectionFailureSnapshot {
    /// Maximum distinct origin/stage/reason keys retained.
    pub max_entries: usize,
    /// Keys evicted after the bounded map filled.
    pub evicted_keys: u64,
    /// Stable-sorted current health rows.
    pub entries: Vec<PromptInjectionFailureHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FailureKey {
    origin_id: String,
    stage: &'static str,
    reason: &'static str,
}

struct FailureEntry {
    health: PromptInjectionFailureHealth,
    last_warning: Option<Instant>,
    sequence: u64,
}

#[derive(Default)]
struct FailureHealth {
    entries: HashMap<FailureKey, FailureEntry>,
    evicted_keys: u64,
    sequence: u64,
}

/// One observed detector failure, named rather than positional.
///
/// `origin_id` and `scan_path` are both string slices and sat next to each
/// other in the argument list, which is the transposition the compiler cannot
/// catch.
struct FailureObservation<'a> {
    origin_id: &'a str,
    stage: DetectionFailureStage,
    scan_path: &'static str,
    action: PromptInjectionAction,
    outcome: UnavailableDecision,
    now: Instant,
    now_unix_ms: u64,
}

impl FailureHealth {
    fn note(&mut self, observed: FailureObservation<'_>) -> Option<u64> {
        let FailureObservation {
            origin_id,
            stage,
            scan_path,
            action,
            outcome,
            now,
            now_unix_ms,
        } = observed;
        let key = FailureKey {
            origin_id: origin_id.to_string(),
            stage: stage.origin.as_str(),
            reason: stage.kind.as_str(),
        };
        if !self.entries.contains_key(&key) && self.entries.len() == MAX_FAILURE_KEYS {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
                self.evicted_keys = self.evicted_keys.saturating_add(1);
            }
        }
        self.sequence = self.sequence.saturating_add(1);
        let sequence = self.sequence;
        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| FailureEntry {
                health: PromptInjectionFailureHealth {
                    origin_id: key.origin_id.clone(),
                    stage: key.stage,
                    reason: key.reason,
                    failures_total: 0,
                    blocked_total: 0,
                    degraded_total: 0,
                    warnings_emitted: 0,
                    warnings_suppressed: 0,
                    last_seen_unix_ms: now_unix_ms,
                    last_scan_path: scan_path,
                    last_action: action.as_str(),
                    last_outcome: outcome.as_str(),
                },
                last_warning: None,
                sequence,
            });
        entry.sequence = sequence;
        entry.health.failures_total = entry.health.failures_total.saturating_add(1);
        match outcome {
            UnavailableDecision::Blocked => {
                entry.health.blocked_total = entry.health.blocked_total.saturating_add(1);
            }
            UnavailableDecision::Degraded => {
                entry.health.degraded_total = entry.health.degraded_total.saturating_add(1);
            }
        }
        entry.health.last_seen_unix_ms = now_unix_ms;
        entry.health.last_scan_path = scan_path;
        entry.health.last_action = action.as_str();
        entry.health.last_outcome = outcome.as_str();

        let should_warn = entry
            .last_warning
            .is_none_or(|last| now.saturating_duration_since(last) >= WARNING_INTERVAL);
        if should_warn {
            entry.last_warning = Some(now);
            entry.health.warnings_emitted = entry.health.warnings_emitted.saturating_add(1);
            Some(entry.health.warnings_suppressed)
        } else {
            entry.health.warnings_suppressed = entry.health.warnings_suppressed.saturating_add(1);
            None
        }
    }

    fn snapshot(&self) -> PromptInjectionFailureSnapshot {
        let mut entries: Vec<_> = self
            .entries
            .values()
            .map(|entry| entry.health.clone())
            .collect();
        entries.sort_by(|left, right| {
            left.origin_id
                .cmp(&right.origin_id)
                .then(left.stage.cmp(right.stage))
                .then(left.reason.cmp(right.reason))
        });
        PromptInjectionFailureSnapshot {
            max_entries: MAX_FAILURE_KEYS,
            evicted_keys: self.evicted_keys,
            entries,
        }
    }
}

static FAILURE_HEALTH: OnceLock<Mutex<FailureHealth>> = OnceLock::new();

fn health() -> &'static Mutex<FailureHealth> {
    FAILURE_HEALTH.get_or_init(|| Mutex::new(FailureHealth::default()))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Serialize)]
struct FailureEventStage {
    origin: &'static str,
    reason: &'static str,
}

impl From<DetectionFailureStage> for FailureEventStage {
    fn from(stage: DetectionFailureStage) -> Self {
        Self {
            origin: stage.origin.as_str(),
            reason: stage.kind.as_str(),
        }
    }
}

#[derive(Serialize)]
struct PromptInjectionUnavailableEvent<'a> {
    guardrail: &'static str,
    classification_state: &'static str,
    policy_decision: &'static str,
    action: &'static str,
    scan_path: &'static str,
    request_id: Option<&'a str>,
    primary_failure: Option<FailureEventStage>,
    terminal_failure: FailureEventStage,
}

fn event_data(
    request_id: Option<&str>,
    scan_path: &'static str,
    action: PromptInjectionAction,
    outcome: UnavailableDecision,
    failure: DetectionFailure,
) -> serde_json::Value {
    let event = PromptInjectionUnavailableEvent {
        guardrail: "prompt_injection_v2",
        classification_state: "unavailable",
        policy_decision: outcome.as_str(),
        action: action.as_str(),
        scan_path,
        request_id,
        primary_failure: failure.primary().map(Into::into),
        terminal_failure: failure.terminal().into(),
    };
    match serde_json::to_value(event) {
        Ok(value) => value,
        Err(_) => serde_json::json!({
            "guardrail": "prompt_injection_v2",
            "classification_state": "unavailable",
            "policy_decision": outcome.as_str(),
        }),
    }
}

/// Record one unavailable classification through every operational surface.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_unavailable(
    origin_id: Option<&str>,
    tenant_id: &str,
    request_id: Option<&str>,
    scan_path: &'static str,
    action: PromptInjectionAction,
    outcome: UnavailableDecision,
    failure: DetectionFailure,
) {
    let origin_id = origin_id
        .filter(|value| !value.is_empty())
        .unwrap_or(UNMATCHED_ORIGIN);
    let now = Instant::now();
    let now_unix_ms = unix_ms();
    let stages = [failure.primary(), Some(failure.terminal())];
    for stage in stages.into_iter().flatten() {
        sbproxy_observe::metrics::record_prompt_injection_classifier_failure(
            scan_path,
            action.as_str(),
            stage.origin.as_str(),
            stage.kind.as_str(),
            outcome.as_str(),
            tenant_id,
        );
        let suppressed = health().lock().note(FailureObservation {
            origin_id,
            stage,
            scan_path,
            action,
            outcome,
            now,
            now_unix_ms,
        });
        if let Some(suppressed) = suppressed {
            tracing::warn!(
                target: "sbproxy::prompt_injection_v2",
                origin_id = %origin_id,
                scan_path = %scan_path,
                action = action.as_str(),
                failure_stage = stage.origin.as_str(),
                failure_reason = stage.kind.as_str(),
                outcome = outcome.as_str(),
                warnings_suppressed = suppressed,
                "prompt-injection classifier unavailable"
            );
        }
    }

    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::GuardrailTriggered, || {
        sbproxy_observe::ProxyEvent::new(
            sbproxy_observe::EventType::GuardrailTriggered,
            origin_id.to_string(),
            tenant_id.to_string(),
            event_data(request_id, scan_path, action, outcome, failure),
        )
    });
}

/// Read the bounded failure state for the authenticated admin endpoint.
pub(crate) fn snapshot() -> PromptInjectionFailureSnapshot {
    health().lock().snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_modules::{DetectionFailureKind, DetectionFailureOrigin};

    #[test]
    fn repeated_failures_are_rate_limited_by_closed_origin_and_reason() {
        let mut state = FailureHealth::default();
        let now = Instant::now();
        let stage = DetectionFailureStage {
            origin: DetectionFailureOrigin::Detector,
            kind: DetectionFailureKind::Inference,
        };

        assert_eq!(
            state.note(FailureObservation {
                origin_id: "origin-a",
                stage,
                scan_path: "header_scan",
                action: PromptInjectionAction::Log,
                outcome: UnavailableDecision::Degraded,
                now,
                now_unix_ms: 1,
            }),
            Some(0)
        );
        assert_eq!(
            state.note(FailureObservation {
                origin_id: "origin-a",
                stage,
                scan_path: "header_scan",
                action: PromptInjectionAction::Log,
                outcome: UnavailableDecision::Degraded,
                now: now + Duration::from_secs(1),
                now_unix_ms: 2,
            }),
            None
        );

        let snapshot = state.snapshot();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].failures_total, 2);
        assert_eq!(snapshot.entries[0].blocked_total, 0);
        assert_eq!(snapshot.entries[0].degraded_total, 2);
        assert_eq!(snapshot.entries[0].warnings_emitted, 1);
        assert_eq!(snapshot.entries[0].warnings_suppressed, 1);
    }

    #[test]
    fn event_carries_both_closed_failure_stages_without_sensitive_inputs() {
        let failure = DetectionFailure::direct(DetectionFailureKind::Inference).after_sidecar();
        let data = event_data(
            Some("request-1"),
            "ai_body",
            PromptInjectionAction::Block,
            UnavailableDecision::Blocked,
            failure,
        );
        let rendered = data.to_string();

        assert!(rendered.contains("primary_sidecar"));
        assert!(rendered.contains("local_fallback"));
        assert!(rendered.contains("inference"));
        assert!(rendered.contains("unavailable"));
        assert!(rendered.contains("blocked"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("oops"));
        assert!(!rendered.contains("bearer"));
    }
}
