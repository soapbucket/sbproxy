//! Policy-decision audit event bus.
//!
//! Per `docs/adr-policy-audit-binding.md`, every policy decision
//! emits a `PolicyVerdictEvent` (see
//! [`sbproxy_observe::events::PolicyVerdictEvent`]) on the audit
//! bus and the hot path finishes as soon as the event is
//! enqueued. The bus is a bounded `tokio::sync::mpsc` channel; a
//! downstream consumer drains it asynchronously.
//!
//! The queue carries a [`crate::policy_bus::AuditRecord`], which is
//! either that policy verdict or a
//! [`sbproxy_observe::decision::DecisionAudit`] from the shared
//! decision family. One queue for both, for the reasons
//! [`crate::policy_bus::AuditRecord`] sets out.
//!
//! In OSS the consumer is a stub that drops events to stderr as
//! JSON-lines; this is sufficient for local dev and gives operators
//! a way to inspect decisions without provisioning a NATS cluster.
//! An extension can replace the stub with a NATS-backed audit-chain
//! consumer that hash-chains and KMS-signs Merkle roots downstream.
//!
//! Backpressure: the producer side bounds the in-memory queue at
//! `DEFAULT_BUS_CAPACITY` (10 000 events). On overflow the publish
//! call hands the record back, the caller increments its family's
//! dropped-events counter, and the request continues. The hot path
//! never blocks on the bus.
//!
//! Because both families share the queue, that one capacity now covers
//! both, and a flood on either arm evicts the other. The bus itself
//! cannot say which arm was responsible, so the per-family drop
//! counters at the two call sites are the only thing that names the
//! feed that lost coverage.

use std::sync::OnceLock;

use sbproxy_observe::decision::DecisionAudit;
use sbproxy_observe::events::PolicyVerdictEvent;
use tokio::sync::mpsc;

/// One record on the audit bus.
///
/// A sum type on one queue rather than a second sibling channel,
/// because the queue is where the backpressure contract lives. Two
/// queues would mean two `OnceLock` singletons to install, two drain
/// threads to keep alive for the process lifetime, two capacities to
/// size and document, and two drop counters to alert on, all to carry
/// records that describe the same requests.
///
/// The ordering argument is the one that settles it. An analyst
/// reconstructing a single request wants the policy verdict and the
/// route or cache decision for that request in the order they
/// happened. Two channels with independent drain rates interleave
/// them arbitrarily, so the reconstruction stops being evidence of
/// sequence. One queue makes publication order the delivery order,
/// which is the property the reconstruction rests on.
///
/// The two families are already coupled on purpose:
/// [`PolicyVerdictEvent::engine`] carries a
/// [`sbproxy_observe::decision::DecisionEngine`] precisely so the
/// metric and the audit record cannot disagree about who decided.
/// Splitting them across queues would reintroduce the disagreement
/// that coupling fixed.
///
/// The two arms do not share a wire shape. A verdict serializes
/// through its serde derive; a decision serializes through
/// `DecisionAudit::to_ocsf`. The drain picks per arm and stamps a
/// different stderr prefix for each, so a consumer's filter selects
/// exactly one parser's input.
///
/// Deliberately not `Serialize`: the envelope has no wire shape of
/// its own. Deriving one would ship a third encoding that nothing
/// reads and that drifts from the two that ship, which is the
/// failure mode `to_ocsf` versus the derive already invites on the
/// decision arm alone.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuditRecord {
    /// A policy verdict, one per policy evaluation.
    PolicyVerdict(PolicyVerdictEvent),
    /// A decision-family audit record, one per emitting decision
    /// point that the operator has enabled.
    Decision(DecisionAudit),
}

impl AuditRecord {
    /// Stderr line prefix the OSS drain stub stamps for this record.
    ///
    /// `policy_verdict_event` is load bearing rather than cosmetic:
    /// operators filter the stub's stderr on it with `grep` and `jq`,
    /// so the verdict arm keeps the prefix it has carried since the bus
    /// shipped. The decision arm gets its own instead of reusing it,
    /// because the two arms are different wire shapes and a filter
    /// matching both would feed a consumer records its parser cannot
    /// read.
    fn stderr_prefix(&self) -> &'static str {
        match self {
            Self::PolicyVerdict(_) => "policy_verdict_event",
            Self::Decision(_) => "decision_audit_event",
        }
    }
}

/// Sender half of the audit bus.
pub type PolicyBus = mpsc::Sender<AuditRecord>;

/// Receiver half of the audit bus. The OSS stub
/// consumes this; an extension can wrap it with a NATS bridge.
pub type PolicyVerdictReceiver = mpsc::Receiver<AuditRecord>;

/// Default channel capacity. Sized at 10 000 events per the
/// audit-binding ADR's overflow contract: large enough that a
/// healthy consumer never sees the queue saturated, small enough
/// that a sustained consumer outage produces a paging signal in
/// minutes rather than hours.
///
/// The figure is unchanged now that decision records share the queue.
/// The decision family emits nothing until an operator turns it on,
/// so nothing new competes for these slots by default; resize when
/// the per-family drop counters show contention, not before.
pub const DEFAULT_BUS_CAPACITY: usize = 10_000;

/// Construct a bounded mpsc channel pair for audit records.
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

/// Upper bound on a single serialized audit line.
///
/// The OSS [`PolicyVerdictEvent`] is already bounded by construction (the
/// inbound request id is capped upstream at 256 bytes and the OSS payload
/// carries no request-header or response-body context, which are
/// optional fields), so an oversized line is not reachable on that arm
/// today.
///
/// The decision arm bounds the field that carries untrusted text:
/// `DecisionAudit::reason` is a `RedactedReason`, capped at 512 bytes by
/// its own constructor. What it does not bound is `request_id`,
/// `origin`, `tenant`, and `rule_id`, so this cap is what stands behind
/// those. It is defense-in-depth on both arms either way, for the
/// `#[non_exhaustive]` payloads as their optional envelopes grow, and it
/// keeps a single record from flooding the audit sink and the disk
/// behind it.
const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;

/// Serialize one record in the shape its consumers parse.
///
/// Split out of the drain so the choice of wire shape is testable
/// rather than a comment. A verdict goes through its serde derive,
/// which is what an external NATS consumer would receive. A decision
/// goes through `to_ocsf`, because OCSF is the entire point of that
/// type and the SIEM parsers reading this feed are written against
/// it; rendering the derive instead would ship a second shape that
/// drifts from `to_ocsf` the first time a field moves.
fn encode_record(record: &AuditRecord) -> Result<String, serde_json::Error> {
    match record {
        AuditRecord::PolicyVerdict(event) => serde_json::to_string(event),
        AuditRecord::Decision(audit) => serde_json::to_string(&audit.to_ocsf()),
    }
}

/// Spawn the OSS drain stub that prints every record to stderr as
/// a JSON line.
///
/// The output format matches the on-wire shape of each record kind, so
/// an operator who pipes stderr through `jq` or a structured-log
/// shipper sees the same payload an external consumer would receive on
/// NATS. Each kind carries its own line prefix (see
/// `AuditRecord::stderr_prefix`) so the two shapes stay separable by a
/// grep. A production extension can add a NATS subscriber that does
/// hash-chained Merkle commits.
pub async fn drain_to_stderr(mut rx: PolicyVerdictReceiver) {
    while let Some(record) = rx.recv().await {
        match encode_record(&record) {
            Ok(line) => {
                // Stderr is the audit-event channel for the OSS
                // stub. Operators who want a different sink wrap
                // the stub binary or replace this consumer at the
                // policy-bus extension point. We deliberately use
                // `eprintln!` rather than the tracing subscriber
                // so the audit emission survives even when log
                // sampling is on for the broader proxy. This is
                // intentional; WOR-637 deliberately left this site
                // unconverted for that audit-durability reason.
                eprintln!(
                    "{}: {}",
                    record.stderr_prefix(),
                    bound_audit_line(&record, line)
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    record_kind = record.stderr_prefix(),
                    "audit record: serialize failed"
                );
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
///
/// The marker is shaped like the record it replaces, not like a shared
/// envelope: the verdict marker keeps `request_id` and `policy_id` at
/// the top level, the decision marker keeps `metadata.uid` and
/// `metadata.correlation_uid` under an OCSF `class_uid`. A consumer
/// that indexes on either shape can still find and count its own
/// truncations.
fn bound_audit_line(record: &AuditRecord, line: String) -> String {
    if line.len() <= MAX_AUDIT_LINE_BYTES {
        return line;
    }
    let original_bytes = line.len();
    match record {
        AuditRecord::PolicyVerdict(event) => {
            tracing::warn!(
                original_bytes,
                request_id = %event.request_id,
                "policy_verdict_event: truncated oversized audit line"
            );
            serde_json::json!({
                "event_id": event.event_id,
                "request_id": sbproxy_util::truncate_utf8(&event.request_id, 256).to_string(),
                "policy_id": sbproxy_util::truncate_utf8(&event.policy_id, 256).to_string(),
                "verdict": &event.verdict,
                "truncated": true,
                "original_bytes": original_bytes,
            })
            .to_string()
        }
        AuditRecord::Decision(audit) => {
            tracing::warn!(
                original_bytes,
                request_id = %audit.request_id,
                event = audit.event.as_label(),
                "decision_audit_event: truncated oversized audit line"
            );
            serde_json::json!({
                "class_uid": 6003,
                "metadata": {
                    "uid": audit.event_id.to_string(),
                    "correlation_uid":
                        sbproxy_util::truncate_utf8(&audit.request_id, 256).to_string(),
                },
                "policy": { "name": audit.event.as_label() },
                "truncated": true,
                "original_bytes": original_bytes,
            })
            .to_string()
        }
    }
}

/// Enqueue a record without blocking, handing it back when it could
/// not be enqueued.
///
/// The shared body behind [`try_publish`] and [`try_publish_decision`].
/// Both arms want identical behaviour on overflow, and identical is
/// easier to keep true when there is one implementation of it.
fn send_record(record: AuditRecord) -> Result<(), Box<AuditRecord>> {
    let Some(bus) = global_bus() else {
        return Err(Box::new(record));
    };
    bus.try_send(record).map_err(|err| {
        Box::new(match err {
            mpsc::error::TrySendError::Full(rec) | mpsc::error::TrySendError::Closed(rec) => rec,
        })
    })
}

/// Try to publish a policy verdict without blocking.
///
/// Returns `Ok(())` when the event was enqueued, `Err(boxed_record)`
/// when the queue was full or the bus was not installed. The
/// caller is responsible for incrementing the dropped-events
/// metric on `Err(...)`; this function deliberately stays
/// decoupled from the metrics module so the bus can be exercised
/// in unit tests without a metrics registry.
///
/// The `Err` payload is boxed so the `Result` stays small on the
/// hot path even though an [`AuditRecord`] is non-trivial in
/// size. `Box::new(record)` only allocates on the rare overflow
/// path; the common case (bus installed and queue not full)
/// hands ownership to tokio's channel and never touches the
/// allocator beyond what `mpsc::Sender::try_send` already does.
///
/// The payload comes back as the envelope rather than as the bare
/// event, because that is what the channel gives up and unwrapping it
/// again would need an arm for a variant this function cannot have
/// produced. Callers that only count the drop ignore it; callers that
/// want the event back match the [`AuditRecord::PolicyVerdict`] arm.
///
/// Per `docs/adr-policy-audit-binding.md` the hot path never
/// blocks on the audit bus, so this is the only emission entry
/// point exposed to the dispatcher.
pub fn try_publish(event: PolicyVerdictEvent) -> Result<(), Box<AuditRecord>> {
    send_record(AuditRecord::PolicyVerdict(event))
}

/// Try to publish a decision-family audit record without blocking.
///
/// The [`try_publish`] contract, one record kind over: `Ok(())` when
/// the record was enqueued, `Err(boxed_record)` when the queue was
/// full or the bus was not installed, and the caller increments the
/// drop counter under `Err(...)`. Deliberately not the place the drop
/// is counted, for the same reason the verdict path counts at its call
/// site: the bus stays usable in unit tests that have no metrics
/// registry, and the counter's labels come from what the call site
/// knows.
///
/// No `tenant` parameter, unlike the metric the caller records after
/// it. [`DecisionAudit`] already carries the tenant, and its
/// constructor is the thing that guarantees it is non-empty, so a
/// second copy passed alongside could only ever be the same string or
/// a wrong one. The `Err` arm hands the record back whole, so the
/// caller reads the tenant off it and cannot label a drop with a
/// tenant the record disagrees about.
pub fn try_publish_decision(audit: DecisionAudit) -> Result<(), Box<AuditRecord>> {
    send_record(AuditRecord::Decision(audit))
}

/// Build, scrub, publish, and account for one decision audit record.
///
/// The single chokepoint every emitting decision event routes through
/// (WOR-2405), so the four things that must happen together cannot drift
/// apart: the operator's PII rules are resolved for this request's
/// scope, the reason is scrubbed by [`DecisionAudit`]'s constructor, the
/// record is published, and the outcome is counted either as emitted or
/// as dropped.
///
/// `route` is the origin **hostname** the PII scopes are keyed by, which
/// is not necessarily `origin_id`, the configured identity the audit
/// record carries. They are equal in today's configs and the two
/// arguments exist so a future config can separate them without silently
/// skipping the origin-scoped redactor.
///
/// Returns whether the record reached the bus, so a caller that wants to
/// log the loss can, though the drop is already counted here.
#[allow(clippy::too_many_arguments)]
pub fn emit_decision_audit(
    event: sbproxy_observe::decision::DecisionEvent,
    engine: sbproxy_observe::decision::DecisionEngine,
    outcome: sbproxy_observe::decision::DecisionOutcome,
    request_id: &str,
    origin_id: &str,
    route: &str,
    tenant: &str,
    reason: &str,
) -> bool {
    // Resolved per request rather than cached: the state is swapped
    // whole on config reload, and holding it across requests would
    // scrub with a policy the operator has already replaced.
    let redact_state = sbproxy_observe::logging::operator_redact_state();

    let audit = DecisionAudit::new(
        uuid::Uuid::new_v4(),
        request_id,
        event,
        engine,
        outcome,
        origin_id,
        tenant,
        chrono::Utc::now(),
        reason,
        Some(redact_state.as_ref()),
        Some(route),
    );

    match try_publish_decision(audit) {
        Ok(()) => {
            sbproxy_observe::metrics::record_decision_audit_emitted(event, outcome);
            true
        }
        Err(_) => {
            // A silently lossy audit feed reads as evidence of absence,
            // which is worse than no feed at all, so every drop is
            // counted against the tenant whose feed lost it.
            sbproxy_observe::metrics::record_decision_audit_dropped(event, tenant);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sbproxy_observe::decision::{DecisionEngine, DecisionEvent, DecisionOutcome};
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
            DecisionEngine::BuiltIn,
            VerdictTag::Allow,
            1,
        )
    }

    fn sample_decision() -> DecisionAudit {
        decision_with_request_id("req-decision-1")
    }

    /// A decision record with a caller-chosen request id.
    ///
    /// Split out so the oversized-line test can hand in a pathological
    /// one. `reason` cannot serve that purpose any more: the constructor
    /// runs it through `RedactedReason`, which bounds it at 512 bytes,
    /// so the record's remaining unbounded fields are the only way to
    /// build a line the drain has to truncate.
    fn decision_with_request_id(request_id: &str) -> DecisionAudit {
        DecisionAudit::new(
            uuid::Uuid::new_v4(),
            request_id,
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Deny,
            "audit-origin",
            "acme-corp",
            Utc::now(),
            "response carries a set-cookie header",
            None,
            None,
        )
    }

    #[test]
    fn audit_line_passes_through_when_small() {
        let record = AuditRecord::PolicyVerdict(sample_event());
        let line = encode_record(&record).expect("encode");
        // A normal event is well under the cap and is emitted verbatim.
        assert!(line.len() <= MAX_AUDIT_LINE_BYTES);
        assert_eq!(bound_audit_line(&record, line.clone()), line);
    }

    #[test]
    fn audit_line_is_bounded_and_marked_when_oversized() {
        // WOR-609: an event whose serialization exceeds the cap collapses to a
        // bounded, still-valid-JSON marker stamped truncated:true. (The OSS
        // event is bounded in practice; we force the condition with a
        // pathological request id to exercise the guard.)
        let record = AuditRecord::PolicyVerdict(PolicyVerdictEvent::new(
            uuid::Uuid::new_v4(),
            "x".repeat(200_000),
            String::new(),
            String::new(),
            Utc::now(),
            "rate_limit".to_string(),
            PolicySurface::BuiltIn,
            DecisionEngine::BuiltIn,
            VerdictTag::Allow,
            1,
        ));
        let line = encode_record(&record).expect("encode");
        assert!(line.len() > MAX_AUDIT_LINE_BYTES);

        let bounded = bound_audit_line(&record, line);
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

    #[test]
    fn an_oversized_decision_keeps_its_ocsf_correlation_keys() {
        // Same guard as the verdict arm, forced the same way, with a
        // pathological request id. The marker has to stay findable in an
        // OCSF-shaped index, so it keeps `metadata.uid` and
        // `metadata.correlation_uid` rather than the verdict arm's
        // top-level `policy_id`: a consumer indexing this feed on the
        // OCSF keys can still count and correlate its own truncations.
        let audit = decision_with_request_id(&"x".repeat(200_000));
        let event_id = audit.event_id;
        let record = AuditRecord::Decision(audit);
        let line = encode_record(&record).expect("encode");
        assert!(line.len() > MAX_AUDIT_LINE_BYTES);

        let bounded = bound_audit_line(&record, line);
        assert!(
            bounded.len() <= MAX_AUDIT_LINE_BYTES,
            "bounded line is {} bytes",
            bounded.len()
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&bounded).expect("marker is valid JSON");
        assert_eq!(parsed["truncated"], serde_json::json!(true));
        assert_eq!(parsed["class_uid"], serde_json::json!(6003));
        assert_eq!(
            parsed["metadata"]["uid"],
            serde_json::json!(event_id.to_string())
        );
        assert_eq!(
            parsed["metadata"]["correlation_uid"],
            serde_json::json!("x".repeat(256))
        );
        assert_eq!(parsed["policy"]["name"], serde_json::json!("cache.admit"));
    }

    #[test]
    fn a_decision_drains_as_ocsf_rather_than_through_its_serde_derive() {
        // `DecisionAudit` has two renderings and only one of them is what
        // the SIEM parsers on this feed read. Nothing but this test stops
        // somebody "simplifying" the drain to `serde_json::to_string(audit)`,
        // which would keep every line valid JSON and break every consumer.
        let record = AuditRecord::Decision(sample_decision());
        let line = encode_record(&record).expect("encode");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");

        assert_eq!(parsed["class_uid"], serde_json::json!(6003));
        assert_eq!(
            parsed["metadata"]["correlation_uid"],
            serde_json::json!("req-decision-1")
        );
        assert!(
            parsed.get("occurred_at").is_none(),
            "`occurred_at` at the top level means the serde derive rendered this, \
             not `to_ocsf`: {line}"
        );
    }

    #[test]
    fn each_record_kind_carries_its_own_stderr_prefix() {
        // The verdict prefix is the one operators already filter on, so it
        // is pinned rather than assumed.
        assert_eq!(
            AuditRecord::PolicyVerdict(sample_event()).stderr_prefix(),
            "policy_verdict_event"
        );
        assert_eq!(
            AuditRecord::Decision(sample_decision()).stderr_prefix(),
            "decision_audit_event"
        );
    }

    #[tokio::test]
    async fn channel_roundtrips_one_event() {
        let (tx, mut rx) = channel(4);
        tx.send(AuditRecord::PolicyVerdict(sample_event()))
            .await
            .expect("send");
        match rx.recv().await.expect("recv") {
            AuditRecord::PolicyVerdict(event) => assert_eq!(event.policy_id, "rate_limit"),
            other => panic!("expected a verdict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn both_record_kinds_drain_in_publication_order() {
        // This is the property the shared queue buys, and the reason there
        // is not a sibling channel: an analyst reconstructing one request
        // reads the verdict and the decision in the order they happened.
        // Two queues draining independently would interleave them
        // arbitrarily and the reconstruction would stop being evidence of
        // sequence.
        let (tx, mut rx) = channel(4);
        tx.send(AuditRecord::PolicyVerdict(sample_event()))
            .await
            .expect("verdict send");
        tx.send(AuditRecord::Decision(sample_decision()))
            .await
            .expect("decision send");

        match rx.recv().await.expect("first recv") {
            AuditRecord::PolicyVerdict(event) => assert_eq!(event.request_id, "req-1"),
            other => panic!("the verdict was published first, got {other:?}"),
        }
        match rx.recv().await.expect("second recv") {
            AuditRecord::Decision(audit) => assert_eq!(audit.request_id, "req-decision-1"),
            other => panic!("the decision was published second, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn try_send_returns_err_when_full() {
        // Capacity 1: the first send fits, the second overflows.
        let (tx, _rx) = channel(1);
        tx.send(AuditRecord::PolicyVerdict(sample_event()))
            .await
            .expect("first send fits");
        let err = tx
            .try_send(AuditRecord::PolicyVerdict(sample_event()))
            .expect_err("second overflows");
        match err {
            mpsc::error::TrySendError::Full(_) => {}
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_full_bus_refuses_a_decision_the_same_way_it_refuses_a_verdict() {
        // A decision must not get a quieter failure than a verdict does.
        // If it did, a saturated queue would silently shed the newer feed
        // while the older one kept counting drops, and the drop counters
        // would say the bus was healthy.
        let (verdict_tx, _verdict_rx) = channel(1);
        verdict_tx
            .send(AuditRecord::PolicyVerdict(sample_event()))
            .await
            .expect("first verdict fits");
        let verdict_err = verdict_tx
            .try_send(AuditRecord::PolicyVerdict(sample_event()))
            .expect_err("second verdict overflows");

        let (decision_tx, _decision_rx) = channel(1);
        decision_tx
            .send(AuditRecord::Decision(sample_decision()))
            .await
            .expect("first decision fits");
        let decision_err = decision_tx
            .try_send(AuditRecord::Decision(sample_decision()))
            .expect_err("second decision overflows");

        match (verdict_err, decision_err) {
            (
                mpsc::error::TrySendError::Full(_),
                mpsc::error::TrySendError::Full(AuditRecord::Decision(audit)),
            ) => {
                // The record comes back whole, so the caller can label the
                // drop with the tenant the record itself names.
                assert_eq!(audit.tenant, "acme-corp");
            }
            (verdict, decision) => panic!(
                "both arms must overflow as Full and hand the record back; \
                 got {verdict:?} and {decision:?}"
            ),
        }
    }

    #[test]
    fn try_publish_when_no_bus_returns_event() {
        // The global bus is not installed in this test (or, more
        // precisely, may already be installed by another test in
        // the same binary; the call still returns Err on a closed
        // / full bus). Either way the API is "you get the record
        // back so you can drop it and count it."
        let event = sample_event();
        match try_publish(event.clone()) {
            Ok(()) => {
                // Bus was installed; nothing to assert.
            }
            Err(returned) => match *returned {
                AuditRecord::PolicyVerdict(got) => assert_eq!(got.policy_id, event.policy_id),
                other => panic!("a published verdict must come back as one, got {other:?}"),
            },
        }
    }

    #[test]
    fn try_publish_decision_hands_the_record_back_so_a_drop_can_be_counted() {
        // Same contract as the verdict path, and for the same reason: the
        // caller cannot label the drop counter without the record, and a
        // publish that swallowed it would make every drop unattributable.
        let audit = sample_decision();
        match try_publish_decision(audit.clone()) {
            Ok(()) => {
                // Bus was installed by a sibling test in this binary.
            }
            Err(returned) => match *returned {
                AuditRecord::Decision(got) => {
                    assert_eq!(got.request_id, audit.request_id);
                    assert_eq!(got.tenant, audit.tenant);
                }
                other => panic!("a published decision must come back as one, got {other:?}"),
            },
        }
    }

    // --- The chokepoint itself ---
    //
    // Everything above exercises one piece of the emit path in
    // isolation: the constructor, the encoder, the line bound, the
    // channel. Every one of those passes with `emit_decision_audit` and
    // its single call site deleted, which is the state this family
    // shipped in. The tests below go in the front door instead.

    /// Serialises every test below that touches process-wide state.
    ///
    /// Two singletons are in play. The audit bus is a `OnceLock`, so the
    /// process gets one bus however many tests want one and the receiver
    /// has to be shared rather than rebuilt per test. The operator
    /// redaction state is a hot-swapped `RwLock`, so a test that
    /// installs one has to be the only reader while it holds it.
    ///
    /// Under nextest, which is how the gate and CI run this lane, each
    /// test is its own process and neither singleton is shared at all.
    /// This lock is what keeps a threaded `cargo test --lib` from
    /// reading one test's record inside another.
    ///
    /// What it cannot do is serialise against `server::lifecycle`'s
    /// `OP_REDACT_TEST_LOCK`, which guards the same redaction state:
    /// `mod lifecycle` is private to `server`, so a sibling module
    /// cannot name it. Under nextest that gap is unreachable.
    static BUS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Receiver half of the bus these tests publish through.
    ///
    /// Capacity 1, so the overflow path is one call away rather than ten
    /// thousand.
    static TEST_BUS_RX: OnceLock<std::sync::Mutex<PolicyVerdictReceiver>> = OnceLock::new();

    /// Take the bus for one test: the serialisation lock plus a drained
    /// receiver.
    fn take_bus() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, PolicyVerdictReceiver>,
    ) {
        let lock = BUS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cell = TEST_BUS_RX.get_or_init(|| {
            let (tx, rx) = channel(1);
            // The result is deliberately ignored. `init_global_bus` is a
            // `OnceLock` and a sibling test elsewhere in this binary can
            // win it under a threaded `cargo test`; nothing here can
            // undo that. The tests that need to read a record say so in
            // their assertion message rather than letting a miss pass.
            let _installed = init_global_bus(tx);
            std::sync::Mutex::new(rx)
        });
        let mut rx = cell.lock().unwrap_or_else(|e| e.into_inner());
        // Drained on acquisition rather than on release: a test that
        // panics half way through cannot then leave a record behind for
        // the next one to read as its own.
        while rx.try_recv().is_ok() {}
        (lock, rx)
    }

    /// Read one counter sample by metric name and labels; 0 when the
    /// series has never been incremented in this process.
    fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
        sbproxy_observe::metrics::metrics()
            .render()
            .lines()
            .find(|line| {
                line.starts_with(name)
                    && labels
                        .iter()
                        .all(|(k, v)| line.contains(&format!("{k}=\"{v}\"")))
            })
            .and_then(|line| line.rsplit(' ').next()?.parse().ok())
            .unwrap_or(0.0)
    }

    /// The origin **hostname**, which is what the PII scopes are keyed
    /// by and what `emit_decision_audit`'s `route` argument takes.
    const SCOPE_ROUTE: &str = "audit.example.test";

    /// The configured origin **id**, which is what the audit record
    /// carries. Deliberately not a hostname, so a test that confuses the
    /// two cannot pass by coincidence.
    const SCOPE_ORIGIN_ID: &str = "billing-api";

    /// A string no built-in rule and no secret pattern matches, so a
    /// redaction of it can only have come from the rule below.
    const SCOPE_MARKER: &str = "admit-marker-alpha";

    /// A redactor whose only rule rewrites [`SCOPE_MARKER`].
    ///
    /// `defaults: false` is load bearing: with the built-in rule set on,
    /// a hit would prove only that some redactor ran, and every scope
    /// would have produced one.
    fn marker_redactor() -> sbproxy_security::pii::PiiRedactor {
        sbproxy_security::pii::PiiRedactor::from_config(&sbproxy_security::pii::PiiConfig {
            enabled: true,
            defaults: false,
            rules: vec![sbproxy_security::pii::PiiRule {
                name: "origin_scope_marker".to_string(),
                pattern: SCOPE_MARKER.to_string(),
                replacement: Some("[REDACTED:ORIGIN_SCOPE]".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect("the marker rule compiles")
    }

    /// Installs [`marker_redactor`] at **origin** scope for
    /// [`SCOPE_ROUTE`] and puts the empty state back on drop.
    ///
    /// A guard rather than a call at the end of the test: the state is
    /// process-wide, so an assertion that panicked with a redactor still
    /// installed would change what a sibling test scrubs.
    struct OriginScopedRedactor;

    impl OriginScopedRedactor {
        fn install() -> Self {
            let _ = sbproxy_observe::logging::install_op_redact_config(
                sbproxy_observe::logging::OpRedactState {
                    origin_pii: std::collections::HashMap::from([(
                        SCOPE_ROUTE.to_string(),
                        Some(marker_redactor()),
                    )]),
                    ..sbproxy_observe::logging::OpRedactState::empty()
                },
            );
            Self
        }
    }

    impl Drop for OriginScopedRedactor {
        fn drop(&mut self) {
            let _ = sbproxy_observe::logging::install_op_redact_config(
                sbproxy_observe::logging::OpRedactState::empty(),
            );
        }
    }

    /// Pull the next record off the bus, insisting it is a decision.
    fn next_decision(rx: &mut PolicyVerdictReceiver, context: &str) -> DecisionAudit {
        match rx
            .try_recv()
            .unwrap_or_else(|err| panic!("{context}: nothing reached the bus ({err})"))
        {
            AuditRecord::Decision(audit) => audit,
            other => panic!("{context}: the chokepoint publishes decisions, got {other:?}"),
        }
    }

    #[test]
    fn the_chokepoint_publishes_the_record_the_call_site_described() {
        // The wiring test. Nothing else in this workspace asserts that a
        // call to `emit_decision_audit` produces a record on the bus, so
        // deleting the call site left every other test green.
        //
        // Five fields are pinned because those are the five an analyst
        // filters a SIEM on, and the scrub is pinned because `reason` is
        // the only field carrying text the proxy did not author.
        let (_lock, mut rx) = take_bus();

        let emitted = [("event", "cache.admit"), ("outcome", "deny")];
        let dropped = [("event", "cache.admit"), ("tenant", "acme-corp")];
        let emitted_before = counter("sbproxy_decision_audit_events_total", &emitted);
        let dropped_before = counter("sbproxy_decision_audit_events_dropped_total", &dropped);

        let published = emit_decision_audit(
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Deny,
            "req-chokepoint-1",
            SCOPE_ORIGIN_ID,
            SCOPE_ROUTE,
            "acme-corp",
            "declined: upstream echoed Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        );
        assert!(
            published,
            "an installed bus with a free slot has to accept the record"
        );

        let audit = next_decision(&mut rx, "the record the chokepoint reported publishing");
        assert_eq!(audit.request_id, "req-chokepoint-1");
        assert_eq!(audit.event, DecisionEvent::CacheAdmit);
        assert_eq!(audit.engine, DecisionEngine::Lua);
        assert_eq!(audit.outcome, DecisionOutcome::Deny);
        assert_eq!(
            audit.origin, SCOPE_ORIGIN_ID,
            "`origin_id` is what the record carries; `route` only picks the redactor"
        );
        assert_eq!(audit.tenant, "acme-corp");
        assert!(
            !audit.reason.as_str().contains("abcdefghijklmnopqrstuvwxyz"),
            "the constructor's config-free scrub floor has to run on the way in: {}",
            audit.reason.as_str()
        );
        assert!(
            audit.reason.as_str().contains("Bearer [REDACTED]"),
            "a scrubbed reason still has to say what happened: {}",
            audit.reason.as_str()
        );

        assert_eq!(
            counter("sbproxy_decision_audit_events_total", &emitted),
            emitted_before + 1.0,
            "one accepted record is exactly one increment of the emitted counter"
        );
        assert_eq!(
            counter("sbproxy_decision_audit_events_dropped_total", &dropped),
            dropped_before,
            "a record that reached the bus must not also be counted as lost"
        );
    }

    #[test]
    fn a_full_bus_drops_the_record_and_counts_the_drop_exactly_once() {
        // The other half of the contract, and the half an operator
        // notices. A lossy audit feed reads as evidence that nothing was
        // decided, so a drop has to be visible twice over: `false` back
        // to the caller and one increment of the per-tenant drop
        // counter. Counted once, not zero times (the gap is invisible)
        // and not twice (the alert fires at half the real traffic).
        let (_lock, mut rx) = take_bus();

        // Fill whatever bus this process ended up with. Two iterations
        // on the capacity-1 bus this module installs. Bounded rather
        // than unbounded so a bus installed elsewhere with a live drain
        // fails the assertion below instead of spinning forever.
        let mut filled = false;
        for _ in 0..=DEFAULT_BUS_CAPACITY {
            if !emit_decision_audit(
                DecisionEvent::CacheAdmit,
                DecisionEngine::Lua,
                DecisionOutcome::Allow,
                "req-full-bus-filler",
                SCOPE_ORIGIN_ID,
                SCOPE_ROUTE,
                "full-bus-filler",
                "stored",
            ) {
                filled = true;
                break;
            }
        }
        assert!(
            filled,
            "the bus never saturated; something is draining it, so the overflow path below \
             would not be under test"
        );

        let dropped = [("event", "cache.admit"), ("tenant", "acme-corp")];
        let emitted = [("event", "cache.admit"), ("outcome", "deny")];
        let dropped_before = counter("sbproxy_decision_audit_events_dropped_total", &dropped);
        let emitted_before = counter("sbproxy_decision_audit_events_total", &emitted);

        let published = emit_decision_audit(
            DecisionEvent::CacheAdmit,
            DecisionEngine::Lua,
            DecisionOutcome::Deny,
            "req-full-bus-dropped",
            SCOPE_ORIGIN_ID,
            SCOPE_ROUTE,
            "acme-corp",
            "declined: set-cookie",
        );
        assert!(!published, "a full bus cannot have accepted the record");

        assert_eq!(
            counter("sbproxy_decision_audit_events_dropped_total", &dropped),
            dropped_before + 1.0,
            "the drop is counted once, against the tenant whose trail lost it"
        );
        assert_eq!(
            counter("sbproxy_decision_audit_events_total", &emitted),
            emitted_before,
            "a dropped record must not also be counted as emitted"
        );

        // And it must not arrive late. A record that turned up behind a
        // counted drop would be worse than either outcome on its own.
        while let Ok(record) = rx.try_recv() {
            if let AuditRecord::Decision(audit) = record {
                assert_ne!(
                    audit.request_id, "req-full-bus-dropped",
                    "the record the chokepoint reported dropping reached the bus anyway"
                );
            }
        }
    }

    #[test]
    fn the_route_argument_picks_the_redactor_and_the_origin_argument_names_the_record() {
        // The transposition `RedactedReason::redact`'s own rustdoc warns
        // about. `route` is the origin hostname the operator's PII
        // scopes are keyed by; `origin_id` is the configured identity
        // the record carries. Swap them and the record still publishes,
        // still validates, still reaches the SIEM, and the origin-scoped
        // redactor is silently skipped, so the operator's rules stop
        // applying to the one field carrying text the proxy did not
        // author.
        //
        // Both halves are asserted because either alone can be satisfied
        // by accident: the `origin` field pins argument five, the scrub
        // pins argument six.
        let (_lock, mut rx) = take_bus();
        let _redactor = OriginScopedRedactor::install();

        assert!(
            emit_decision_audit(
                DecisionEvent::CacheAdmit,
                DecisionEngine::Lua,
                DecisionOutcome::Deny,
                "req-scope-1",
                SCOPE_ORIGIN_ID,
                SCOPE_ROUTE,
                "acme-corp",
                &format!("declined: {SCOPE_MARKER} in the response body"),
            ),
            "the bus was drained on acquisition, so this record has a slot"
        );

        let audit = next_decision(&mut rx, "the origin-scoped record");
        assert_eq!(
            audit.origin, SCOPE_ORIGIN_ID,
            "the record carries the configured origin id, not the hostname the redactor \
             scopes are keyed by"
        );
        assert!(
            audit.reason.as_str().contains("[REDACTED:ORIGIN_SCOPE]"),
            "the origin-scoped redactor is keyed by `{SCOPE_ROUTE}`, so passing that as \
             `route` has to resolve it: {}",
            audit.reason.as_str()
        );
        assert!(
            !audit.reason.as_str().contains(SCOPE_MARKER),
            "the marker survived a redactor that was supposed to catch it: {}",
            audit.reason.as_str()
        );

        // The control, and the half that makes the assertion above mean
        // something. Same call with the origin id in the `route` slot,
        // which is exactly what the transposition produces. No scope is
        // keyed by `billing-api`, so `resolve_pii` falls through tenant
        // and proxy to `None` and the marker ships verbatim. Without
        // this, the test above would also pass against a redactor that
        // had been installed at every scope.
        assert!(
            emit_decision_audit(
                DecisionEvent::CacheAdmit,
                DecisionEngine::Lua,
                DecisionOutcome::Deny,
                "req-scope-2",
                SCOPE_ORIGIN_ID,
                SCOPE_ORIGIN_ID,
                "acme-corp",
                &format!("declined: {SCOPE_MARKER} in the response body"),
            ),
            "the previous record was read off, so this one has a slot too"
        );

        let transposed = next_decision(&mut rx, "the record with the origin id in `route`");
        assert!(
            transposed.reason.as_str().contains(SCOPE_MARKER),
            "nothing is keyed by `{SCOPE_ORIGIN_ID}`, so the marker had to survive; a \
             redaction here means this test cannot tell the two arguments apart: {}",
            transposed.reason.as_str()
        );
    }
}

// `PolicyVerdictEvent` and `DecisionAudit` both derive `Clone`
// upstream, so `AuditRecord` does too; the tests above clone a
// payload before publishing it and compare the round-tripped record
// to the pristine copy. No additional impls needed here.
