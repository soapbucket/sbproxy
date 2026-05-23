//! Policy-decision audit event bus.
//!
//! Per `docs/adr-policy-audit-binding.md`, every policy decision
//! emits a `PolicyVerdictEvent` (see
//! [`sbproxy_observe::events::PolicyVerdictEvent`]) on the audit
//! bus and the hot path finishes as soon as the event is
//! enqueued. The bus is a bounded `tokio::sync::mpsc` channel; a
//! downstream consumer drains it asynchronously.
//!
//! In OSS the consumer is a stub that drops events to stderr as
//! JSON-lines; this is sufficient for local dev and gives operators
//! a way to inspect decisions without provisioning a NATS cluster.
//! Enterprise replaces the stub with a NATS-backed audit-chain
//! consumer that hash-chains and KMS-signs Merkle roots downstream.
//!
//! Backpressure: the producer side bounds the in-memory queue at
//! `DEFAULT_BUS_CAPACITY` (10 000 events). On overflow the dispatcher
//! drops the event, increments
//! `sbproxy_policy_audit_events_dropped_total{tenant}`, and continues.
//! The hot path never blocks on the bus.

use std::sync::OnceLock;

use sbproxy_observe::events::PolicyVerdictEvent;
use tokio::sync::mpsc;

/// Sender half of the policy verdict audit bus.
pub type PolicyBus = mpsc::Sender<PolicyVerdictEvent>;

/// Receiver half of the policy verdict audit bus. The OSS stub
/// consumes this; enterprise wraps it with the NATS bridge.
pub type PolicyVerdictReceiver = mpsc::Receiver<PolicyVerdictEvent>;

/// Default channel capacity. Sized at 10 000 events per the
/// audit-binding ADR's overflow contract: large enough that a
/// healthy consumer never sees the queue saturated, small enough
/// that a sustained consumer outage produces a paging signal in
/// minutes rather than hours.
pub const DEFAULT_BUS_CAPACITY: usize = 10_000;

/// Construct a bounded mpsc channel pair for policy verdict events.
///
/// The default capacity is [`DEFAULT_BUS_CAPACITY`]; tests can pass
/// a smaller value to exercise the drop-on-overflow path without
/// generating thousands of events.
pub fn channel(capacity: usize) -> (PolicyBus, PolicyVerdictReceiver) {
    mpsc::channel(capacity)
}

/// Process-wide audit-bus sender singleton.
///
/// Initialised by the server boot path via [`init_global_bus`]; the
/// dispatcher reads it through [`global_bus`] when emitting verdict
/// events. `OnceLock` ensures the bus is set exactly once even if
/// the boot path races with a unit test that also tries to install
/// it; the second installer is a no-op.
static GLOBAL_BUS: OnceLock<PolicyBus> = OnceLock::new();

/// Install the global audit-bus sender. Returns `true` when this
/// call installed the sender, `false` when one was already in
/// place.
///
/// The server boot path calls this once with the producer side of
/// the channel constructed by [`channel`]. Tests that exercise the
/// dispatcher without booting the full server can install a
/// purpose-built sender here; subsequent installations are silently
/// ignored, matching the project's existing `OnceLock` singletons.
pub fn init_global_bus(bus: PolicyBus) -> bool {
    GLOBAL_BUS.set(bus).is_ok()
}

/// Read the process-wide audit-bus sender, if installed.
///
/// Returns `None` when the server has not yet booted (or a unit
/// test has not installed a stub). Callers treat `None` as
/// "audit emission unavailable" and fall through silently; the
/// dispatcher is not expected to fail when the bus is not yet
/// wired.
pub fn global_bus() -> Option<PolicyBus> {
    GLOBAL_BUS.get().cloned()
}

/// Upper bound on a single serialized audit line (WOR-609).
///
/// The OSS [`PolicyVerdictEvent`] is already bounded by construction (the
/// inbound request id is capped upstream at 256 bytes and the OSS payload
/// carries no request-header or response-body context, which are
/// enterprise-only fields), so an oversized line is not reachable today. This
/// cap is defense-in-depth for the `#[non_exhaustive]` struct as the enterprise
/// audit envelope grows it, and it keeps a single event from flooding the audit
/// sink and the disk behind it.
const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;

/// Spawn the OSS drain stub that prints every event to stderr as
/// a JSON line.
///
/// The output format matches the on-wire shape of
/// `PolicyVerdictEvent`, so an operator who pipes stderr through
/// `jq` or a structured-log shipper sees the same payload the
/// enterprise consumer would receive on NATS. Production: enterprise
/// extends this with the NATS subscriber that does hash-chained
/// Merkle commits.
pub async fn drain_to_stderr(mut rx: PolicyVerdictReceiver) {
    while let Some(event) = rx.recv().await {
        match serde_json::to_string(&event) {
            Ok(line) => {
                // Stderr is the audit-event channel for the OSS
                // stub. Operators who want a different sink wrap
                // the stub binary or replace this consumer at the
                // enterprise extension point. We deliberately use
                // `eprintln!` rather than the tracing subscriber
                // so the audit emission survives even when log
                // sampling is on for the broader proxy. This is
                // intentional; WOR-637 deliberately left this site
                // unconverted for that audit-durability reason.
                eprintln!("policy_verdict_event: {}", bound_audit_line(&event, line));
            }
            Err(err) => {
                tracing::warn!(error = %err, "policy_verdict_event: serialise failed");
            }
        }
    }
}

/// Bound a serialized audit line to [`MAX_AUDIT_LINE_BYTES`].
///
/// An oversized line collapses to a valid-JSON marker that preserves the
/// correlation keys, stamps `truncated: true`, and records the original size,
/// so downstream `jq`/log-shipper consumers stay parseable and the truncation
/// is observable.
fn bound_audit_line(event: &PolicyVerdictEvent, line: String) -> String {
    if line.len() <= MAX_AUDIT_LINE_BYTES {
        return line;
    }
    tracing::warn!(
        original_bytes = line.len(),
        request_id = %event.request_id,
        "policy_verdict_event: truncated oversized audit line"
    );
    serde_json::json!({
        "event_id": event.event_id,
        "request_id": truncate_on_char_boundary(&event.request_id, 256),
        "policy_id": truncate_on_char_boundary(&event.policy_id, 256),
        "verdict": &event.verdict,
        "truncated": true,
        "original_bytes": line.len(),
    })
    .to_string()
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 character.
fn truncate_on_char_boundary(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Try to publish an audit event without blocking.
///
/// Returns `Ok(())` when the event was enqueued, `Err(boxed_event)`
/// when the queue was full or the bus was not installed. The
/// caller is responsible for incrementing the dropped-events
/// metric on `Err(...)`; this function deliberately stays
/// decoupled from the metrics module so the bus can be exercised
/// in unit tests without a metrics registry.
///
/// The `Err` payload is boxed so the `Result` stays small on the
/// hot path even though `PolicyVerdictEvent` is non-trivial in
/// size. `Box::new(event)` only allocates on the rare overflow
/// path; the common case (bus installed and queue not full)
/// hands ownership to tokio's channel and never touches the
/// allocator beyond what `mpsc::Sender::try_send` already does.
///
/// Per `docs/adr-policy-audit-binding.md` the hot path never
/// blocks on the audit bus, so this is the only emission entry
/// point exposed to the dispatcher.
pub fn try_publish(event: PolicyVerdictEvent) -> Result<(), Box<PolicyVerdictEvent>> {
    let Some(bus) = global_bus() else {
        return Err(Box::new(event));
    };
    bus.try_send(event).map_err(|err| {
        Box::new(match err {
            mpsc::error::TrySendError::Full(ev) | mpsc::error::TrySendError::Closed(ev) => ev,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sbproxy_observe::events::{PolicySurface, VerdictTag};

    fn sample_event() -> PolicyVerdictEvent {
        PolicyVerdictEvent::new(
            uuid::Uuid::new_v4(),
            "req-1".to_string(),
            String::new(),
            String::new(),
            Utc::now(),
            "rate_limit".to_string(),
            PolicySurface::BuiltIn,
            VerdictTag::Allow,
            1,
        )
    }

    #[test]
    fn audit_line_passes_through_when_small() {
        let event = sample_event();
        let line = serde_json::to_string(&event).unwrap();
        // A normal event is well under the cap and is emitted verbatim.
        assert!(line.len() <= MAX_AUDIT_LINE_BYTES);
        assert_eq!(bound_audit_line(&event, line.clone()), line);
    }

    #[test]
    fn audit_line_is_bounded_and_marked_when_oversized() {
        // WOR-609: an event whose serialization exceeds the cap collapses to a
        // bounded, still-valid-JSON marker stamped truncated:true. (The OSS
        // event is bounded in practice; we force the condition with a
        // pathological request id to exercise the guard.)
        let event = PolicyVerdictEvent::new(
            uuid::Uuid::new_v4(),
            "x".repeat(200_000),
            String::new(),
            String::new(),
            Utc::now(),
            "rate_limit".to_string(),
            PolicySurface::BuiltIn,
            VerdictTag::Allow,
            1,
        );
        let line = serde_json::to_string(&event).unwrap();
        assert!(line.len() > MAX_AUDIT_LINE_BYTES);

        let bounded = bound_audit_line(&event, line);
        assert!(
            bounded.len() <= MAX_AUDIT_LINE_BYTES,
            "bounded line is {} bytes",
            bounded.len()
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&bounded).expect("marker is valid JSON");
        assert_eq!(parsed["truncated"], serde_json::json!(true));
        assert_eq!(parsed["policy_id"], serde_json::json!("rate_limit"));
    }

    #[tokio::test]
    async fn channel_roundtrips_one_event() {
        let (tx, mut rx) = channel(4);
        tx.send(sample_event()).await.expect("send");
        let got = rx.recv().await.expect("recv");
        assert_eq!(got.policy_id, "rate_limit");
    }

    #[tokio::test]
    async fn try_send_returns_err_when_full() {
        // Capacity 1: the first send fits, the second overflows.
        let (tx, _rx) = channel(1);
        tx.send(sample_event()).await.expect("first send fits");
        let err = tx.try_send(sample_event()).expect_err("second overflows");
        match err {
            mpsc::error::TrySendError::Full(_) => {}
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[test]
    fn try_publish_when_no_bus_returns_event() {
        // The global bus is not installed in this test (or, more
        // precisely, may already be installed by another test in
        // the same binary; the call still returns Err on a closed
        // / full bus). Either way the API is "you get the event
        // back so you can drop it and count it."
        let event = sample_event();
        match try_publish(event.clone()) {
            Ok(()) => {
                // Bus was installed; nothing to assert.
            }
            Err(returned) => {
                assert_eq!(returned.policy_id, event.policy_id);
            }
        }
    }
}

// `PolicyVerdictEvent` derives `Clone` upstream; we use it in
// tests above to compare the round-tripped payload to the
// pristine event. No additional impls needed here.
