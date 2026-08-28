//! Bounded in-memory store of redacted request content samples (WOR-2096).
//!
//! When an AI origin sets `capture_content: true` AND the governed
//! key's policy sets `allow_content_capture`, the dispatch path stores
//! a redacted sample of the prompt and response here so an operator can
//! inspect one request's content from the admin console
//! (`GET /api/requests/{id}/content`, admin role, audited on read).
//!
//! Redaction happens before storage: the secret redactor, the origin's
//! PII redactor when configured, and the capture payload cap all apply
//! at the capture site, so this store never holds raw content.
//!
//! Deliberately not durable. The store clears on restart; the
//! production-grade content path remains OTLP `trace_content:` span
//! events consumed by the operator's collector.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

/// Upper bound on retained samples across all tenants.
const CONTENT_STORE_CAPACITY: usize = 200;

/// Upper bound on samples one tenant may hold, so a single busy tenant
/// cannot evict every other tenant's samples.
const PER_TENANT_CAPACITY: usize = 50;

/// Upper bound on retained shadow answers per sample (WOR-2654).
///
/// `shadow.targets` has no length limit of its own, so this is what
/// stops a long target list from multiplying the store's real memory
/// ceiling by the length of a config array.
const MAX_SHADOW_RESPONSES_PER_SAMPLE: usize = 8;

/// One redacted input message.
#[derive(Debug, Clone, Serialize)]
pub struct CapturedMessage {
    /// Message role (`system`, `user`, `assistant`, `tool`).
    pub role: String,
    /// Redacted, capped message content.
    pub content: String,
}

/// One shadow target's redacted answer to the same prompt (WOR-2654).
///
/// Retained only alongside a primary sample, never on its own: half a
/// pair is not a comparison, and keeping it would mean holding content
/// whose counterpart the consent gate refused.
#[derive(Debug, Clone, Serialize)]
pub struct ShadowResponseSample {
    /// Target name, which is the shadow provider's name.
    pub target: String,
    /// Model the target answered under, after any `model:` override.
    pub model: String,
    /// Status the target answered with.
    pub status: u16,
    /// Redacted, capped answer text.
    pub output_text: String,
}

/// One redacted content sample for one request.
#[derive(Debug, Clone, Serialize)]
pub struct ContentSample {
    /// Request correlation id; the store key.
    pub request_id: String,
    /// Canonical public key id of the consenting key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// Origin-scoped tenant label.
    pub tenant_id: String,
    /// Origin hostname the request was dispatched for.
    pub origin: String,
    /// Model, when routing resolved one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// RFC 3339 capture timestamp.
    pub captured_at: String,
    /// Redacted input messages, in request order.
    pub input_messages: Vec<CapturedMessage>,
    /// Redacted response text, attached when the upstream answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    /// WOR-2654: the same prompt's shadow answers, one per target that
    /// ran. Empty on every request that configured no `shadow:` block,
    /// and on every request whose targets were sampled out or refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shadow_responses: Vec<ShadowResponseSample>,
}

fn store() -> &'static Mutex<VecDeque<ContentSample>> {
    static STORE: std::sync::OnceLock<Mutex<VecDeque<ContentSample>>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Store the input half of a sample, evicting the oldest sample (or the
/// oldest sample of the same tenant once its budget is reached). An
/// existing sample for the same request id is replaced.
pub fn store_input(sample: ContentSample) {
    let Ok(mut store) = store().lock() else {
        return;
    };
    store.retain(|existing| existing.request_id != sample.request_id);
    let tenant_count = store
        .iter()
        .filter(|existing| existing.tenant_id == sample.tenant_id)
        .count();
    if tenant_count >= PER_TENANT_CAPACITY {
        if let Some(position) = store
            .iter()
            .position(|existing| existing.tenant_id == sample.tenant_id)
        {
            store.remove(position);
        }
    } else if store.len() >= CONTENT_STORE_CAPACITY {
        store.pop_front();
    }
    store.push_back(sample);
}

/// Attach the redacted response text to a stored sample, when one
/// exists. A response for a request whose input was never captured
/// (gate off at input time) is dropped: the sample must be whole.
pub fn attach_output(request_id: &str, output_text: String) {
    let Ok(mut store) = store().lock() else {
        return;
    };
    if let Some(sample) = store
        .iter_mut()
        .find(|sample| sample.request_id == request_id)
    {
        sample.output_text = Some(output_text);
    }
}

/// Attach one target's redacted answer to a stored sample.
///
/// Returns whether it landed. `false` when no sample exists for that
/// request id, which is the shape of the consent gate: the input half
/// is stored only when the origin's `capture_content` and the governed
/// key's `allow_content_capture` both said yes, so a request whose
/// consent was off has no sample and therefore retains no shadow
/// answer either. There is no partial capture: a shadow answer never
/// creates a sample of its own.
///
/// `tenant_id` must match the stored sample's own. The store key is
/// the request correlation id, which `server.correlation_id` adopts
/// from an inbound header by default, so two tenants can present the
/// same one; and unlike the primary's own answer, a shadow answer is
/// written from a detached task that outlives its request. Without
/// this check a late shadow leg could write one tenant's candidate
/// output into another tenant's stored sample, and
/// `GET /api/requests/{id}/content` would then serve it inside a
/// record stamped with the wrong tenant.
///
/// A second answer from the same target replaces the first rather than
/// appending, so a retry cannot make one request look like two
/// comparisons.
pub fn attach_shadow_response(
    request_id: &str,
    tenant_id: &str,
    response: ShadowResponseSample,
) -> bool {
    let Ok(mut store) = store().lock() else {
        return false;
    };
    let Some(sample) = store
        .iter_mut()
        .find(|sample| sample.request_id == request_id && sample.tenant_id == tenant_id)
    else {
        return false;
    };
    if let Some(existing) = sample
        .shadow_responses
        .iter_mut()
        .find(|existing| existing.target == response.target)
    {
        *existing = response;
        return true;
    }
    if sample.shadow_responses.len() >= MAX_SHADOW_RESPONSES_PER_SAMPLE {
        return false;
    }
    sample.shadow_responses.push(response);
    true
}

/// Fetch one sample by request id.
pub fn sample_for(request_id: &str) -> Option<ContentSample> {
    store()
        .lock()
        .ok()?
        .iter()
        .find(|sample| sample.request_id == request_id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(request_id: &str, tenant: &str) -> ContentSample {
        ContentSample {
            request_id: request_id.to_string(),
            api_key_id: Some("sbp_capture_test".to_string()),
            tenant_id: tenant.to_string(),
            origin: "ai.test".to_string(),
            model: Some("gpt-test".to_string()),
            captured_at: "2026-07-31T00:00:00Z".to_string(),
            input_messages: vec![CapturedMessage {
                role: "user".to_string(),
                content: "hello".to_string(),
            }],
            output_text: None,
            shadow_responses: Vec::new(),
        }
    }

    fn shadow(target: &str, text: &str) -> ShadowResponseSample {
        ShadowResponseSample {
            target: target.to_string(),
            model: "candidate-model".to_string(),
            status: 200,
            output_text: text.to_string(),
        }
    }

    #[test]
    fn input_then_output_round_trip() {
        store_input(sample("req-cc-roundtrip", "tenant-cc-a"));
        attach_output("req-cc-roundtrip", "hi there".to_string());
        let got = sample_for("req-cc-roundtrip").expect("sample stored");
        assert_eq!(got.output_text.as_deref(), Some("hi there"));
        assert_eq!(got.input_messages.len(), 1);
    }

    #[test]
    fn output_without_input_is_dropped() {
        attach_output("req-cc-orphan", "orphan".to_string());
        assert!(sample_for("req-cc-orphan").is_none());
    }

    #[test]
    fn a_tenant_cannot_exceed_its_budget() {
        for i in 0..(PER_TENANT_CAPACITY + 10) {
            store_input(sample(&format!("req-cc-budget-{i}"), "tenant-cc-budget"));
        }
        let Ok(store) = store().lock() else {
            panic!("store lock");
        };
        let held = store
            .iter()
            .filter(|s| s.tenant_id == "tenant-cc-budget")
            .count();
        assert!(held <= PER_TENANT_CAPACITY, "held {held}");
        drop(store);
        // The newest sample survived; the oldest was evicted first.
        assert!(sample_for(&format!("req-cc-budget-{}", PER_TENANT_CAPACITY + 9)).is_some());
        assert!(sample_for("req-cc-budget-0").is_none());
    }

    /// The pair the comparison surface exists to hold.
    #[test]
    fn a_captured_request_retains_the_primary_and_every_target() {
        store_input(sample("req-cc-pair", "tenant-cc-pair"));
        attach_output("req-cc-pair", "primary says four".to_string());
        assert!(attach_shadow_response(
            "req-cc-pair",
            "tenant-cc-pair",
            shadow("candidate-a", "candidate a says four")
        ));
        assert!(attach_shadow_response(
            "req-cc-pair",
            "tenant-cc-pair",
            shadow("candidate-b", "candidate b says five")
        ));
        let got = sample_for("req-cc-pair").expect("sample stored");
        assert_eq!(got.output_text.as_deref(), Some("primary says four"));
        assert_eq!(got.shadow_responses.len(), 2);
        assert_eq!(got.shadow_responses[0].target, "candidate-a");
        assert_eq!(got.shadow_responses[1].output_text, "candidate b says five");
    }

    /// The gate. Consent off means no input sample, and no input
    /// sample means the shadow answer has nothing to pair with and is
    /// refused rather than kept on its own.
    #[test]
    fn a_shadow_answer_without_consent_retains_nothing_at_all() {
        assert!(
            !attach_shadow_response(
                "req-cc-no-consent",
                "tenant-cc-none",
                shadow("candidate", "secret answer")
            ),
            "a shadow answer must not create a sample the consent gate refused"
        );
        assert!(
            sample_for("req-cc-no-consent").is_none(),
            "and it must not leave a partial one behind either"
        );
    }

    /// The store key is a correlation id a caller can choose, and a
    /// shadow answer is written from a task that outlives its request,
    /// so a late leg landing on a colliding id must not write one
    /// tenant's candidate output into another tenant's record.
    #[test]
    fn a_shadow_answer_never_lands_in_another_tenants_sample() {
        store_input(sample("req-cc-collide", "tenant-cc-owner"));
        assert!(
            !attach_shadow_response(
                "req-cc-collide",
                "tenant-cc-stranger",
                shadow("candidate", "the other tenant's answer")
            ),
            "a shadow answer from a different tenant must be refused"
        );
        let got = sample_for("req-cc-collide").expect("sample stored");
        assert!(
            got.shadow_responses.is_empty(),
            "and it must leave the owner's sample untouched: {:?}",
            got.shadow_responses
        );
        assert!(
            attach_shadow_response(
                "req-cc-collide",
                "tenant-cc-owner",
                shadow("candidate", "the owner's answer")
            ),
            "the owning tenant's own answer still lands"
        );
    }

    /// A retried target replaces its own answer rather than making one
    /// request look like two comparisons.
    #[test]
    fn a_second_answer_from_one_target_replaces_the_first() {
        store_input(sample("req-cc-retry", "tenant-cc-retry"));
        assert!(attach_shadow_response(
            "req-cc-retry",
            "tenant-cc-retry",
            shadow("candidate", "first")
        ));
        assert!(attach_shadow_response(
            "req-cc-retry",
            "tenant-cc-retry",
            shadow("candidate", "second")
        ));
        let got = sample_for("req-cc-retry").expect("sample stored");
        assert_eq!(got.shadow_responses.len(), 1);
        assert_eq!(got.shadow_responses[0].output_text, "second");
    }

    /// A long `targets:` list cannot multiply the store's ceiling.
    #[test]
    fn retained_shadow_answers_are_capped_per_sample() {
        store_input(sample("req-cc-cap", "tenant-cc-cap"));
        for index in 0..(MAX_SHADOW_RESPONSES_PER_SAMPLE + 4) {
            let landed = attach_shadow_response(
                "req-cc-cap",
                "tenant-cc-cap",
                shadow(&format!("candidate-{index}"), "text"),
            );
            assert_eq!(
                landed,
                index < MAX_SHADOW_RESPONSES_PER_SAMPLE,
                "target {index} landed unexpectedly"
            );
        }
        let got = sample_for("req-cc-cap").expect("sample stored");
        assert_eq!(got.shadow_responses.len(), MAX_SHADOW_RESPONSES_PER_SAMPLE);
    }

    #[test]
    fn same_request_id_replaces_rather_than_duplicates() {
        store_input(sample("req-cc-replace", "tenant-cc-r"));
        store_input(sample("req-cc-replace", "tenant-cc-r"));
        let Ok(store) = store().lock() else {
            panic!("store lock");
        };
        assert_eq!(
            store
                .iter()
                .filter(|s| s.request_id == "req-cc-replace")
                .count(),
            1
        );
    }
}
