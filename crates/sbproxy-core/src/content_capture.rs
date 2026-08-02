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

/// One redacted input message.
#[derive(Debug, Clone, Serialize)]
pub struct CapturedMessage {
    /// Message role (`system`, `user`, `assistant`, `tool`).
    pub role: String,
    /// Redacted, capped message content.
    pub content: String,
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
