//! Bounded in-memory sample of recent audit events (WOR-2094).
//!
//! Production audit consumption is the OTel collector reading the
//! `security_audit` / `key_audit` / `config_audit` /
//! `sbproxy::admin::audit` tracing targets. This ring exists so the
//! admin console can show a runtime sample without any collector
//! wiring: every typed audit emitter pushes a normalized copy here at
//! emit time, and `GET /api/audit/events` reads it back.
//!
//! Deliberately not durable. A restart clears it, exactly like the
//! request-log ring; the durable trail lives in whatever store the
//! collector ships to.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

/// Upper bound on retained events. Old events are dropped first.
const AUDIT_RING_CAPACITY: usize = 1_000;

/// Upper bound on the `detail` field so one pathological reason string
/// cannot dominate the ring's memory.
const MAX_DETAIL_BYTES: usize = 512;

/// One normalized audit event, spanning every channel.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRingEvent {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Source channel: `security`, `key`, `config`, `admin`, or
    /// `policy`.
    pub channel: String,
    /// Channel-specific kind: the security `event_type`, the key
    /// lifecycle `op`, the config `source`, the admin `action`, or the
    /// denying policy type.
    pub kind: String,
    /// Operator who performed the change, for change channels. Absent
    /// on request-scoped events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Tenant scope, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Canonical public key id the event is attributed to, when one
    /// resolved. Never the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// Request correlation id for request-scoped events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Bounded, machine-readable detail: the deny reason, the revision
    /// pair, the mutated resource id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditRingEvent {
    /// Build an event with the detail field capped at the module's
    /// 512-byte bound on a UTF-8 boundary.
    #[allow(clippy::too_many_arguments)] // one call site per channel; a builder would be noise
    pub fn new(
        channel: &str,
        kind: impl Into<String>,
        actor: Option<String>,
        tenant_id: Option<String>,
        api_key_id: Option<String>,
        request_id: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            channel: channel.to_string(),
            kind: kind.into(),
            actor,
            tenant_id,
            api_key_id,
            request_id,
            detail: detail.map(|d| bound_detail(&d)),
        }
    }
}

fn bound_detail(detail: &str) -> String {
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail.to_string();
    }
    let mut end = MAX_DETAIL_BYTES;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &detail[..end])
}

fn ring() -> &'static Mutex<VecDeque<AuditRingEvent>> {
    static RING: std::sync::OnceLock<Mutex<VecDeque<AuditRingEvent>>> = std::sync::OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(AUDIT_RING_CAPACITY)))
}

/// Push one event, evicting the oldest past capacity. Never blocks
/// meaningfully and never fails: a poisoned lock drops the event
/// rather than propagating a panic into an emitter.
pub fn push_audit_event(event: AuditRingEvent) {
    let Ok(mut ring) = ring().lock() else {
        return;
    };
    if ring.len() == AUDIT_RING_CAPACITY {
        ring.pop_front();
    }
    ring.push_back(event);
}

/// Read recent events, newest first, with optional exact-match filters.
pub fn recent_audit_events(
    limit: usize,
    channel: Option<&str>,
    kind: Option<&str>,
    api_key_id: Option<&str>,
) -> Vec<AuditRingEvent> {
    let Ok(ring) = ring().lock() else {
        return Vec::new();
    };
    ring.iter()
        .rev()
        .filter(|e| channel.is_none_or(|c| e.channel == c))
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .filter(|e| api_key_id.is_none_or(|id| e.api_key_id.as_deref() == Some(id)))
        .take(limit)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ring is process-global, so every assertion here tolerates
    // events pushed by other tests: filters use unique markers.

    #[test]
    fn push_and_filtered_read_round_trip() {
        push_audit_event(AuditRingEvent::new(
            "key",
            "rotate-ring-test",
            Some("op-a".into()),
            Some("tenant-a".into()),
            Some("sbp_ring_test_key".into()),
            None,
            Some("status: active -> rotated".into()),
        ));
        let events = recent_audit_events(10, Some("key"), Some("rotate-ring-test"), None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor.as_deref(), Some("op-a"));
        assert_eq!(events[0].api_key_id.as_deref(), Some("sbp_ring_test_key"));

        let by_key = recent_audit_events(10, None, None, Some("sbp_ring_test_key"));
        assert_eq!(by_key.len(), 1);
        assert!(recent_audit_events(10, Some("config"), Some("rotate-ring-test"), None).is_empty());
    }

    #[test]
    fn detail_is_bounded_on_a_char_boundary() {
        let long = "รับ".repeat(400); // multi-byte, > MAX_DETAIL_BYTES
        let bounded = bound_detail(&long);
        assert!(bounded.len() <= MAX_DETAIL_BYTES + 3);
        assert!(bounded.ends_with("..."));
        // Must not panic on a boundary split and must stay valid UTF-8.
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn capacity_evicts_oldest_first() {
        for i in 0..(AUDIT_RING_CAPACITY + 5) {
            push_audit_event(AuditRingEvent::new(
                "policy",
                format!("evict-test-{i}"),
                None,
                None,
                None,
                None,
                None,
            ));
        }
        assert!(recent_audit_events(1, Some("policy"), Some("evict-test-0"), None).is_empty());
        assert_eq!(
            recent_audit_events(
                1,
                Some("policy"),
                Some(&format!("evict-test-{}", AUDIT_RING_CAPACITY + 4)),
                None,
            )
            .len(),
            1
        );
    }
}
