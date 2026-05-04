// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Wave 8 / T4.6 transport adapter: a generic sink for completed
//! [`crate::request_event::RequestEvent`] values.
//!
//! The OSS build ships a [`NoopSink`] default and a [`LoggingSink`]
//! that emits each event as a structured `tracing` log line. Enterprise
//! deployments register their own sink (e.g. one that adapts the OSS
//! `RequestEvent` to the protobuf wire format and ships it to the
//! NATS JetStream broker per `docs/adr-event-ingest-pipeline.md`).
//!
//! ## Registration
//!
//! Sinks are process-global. Call [`set_request_event_sink`] once at
//! startup; subsequent calls return `Err`. Callers that build their own
//! Pingora server can register a sink before [`crate::request_event`]
//! integration fires.
//!
//! ## Dispatch
//!
//! [`dispatch_request_event`] is the call site used by the request
//! pipeline (`sbproxy-core::server::logging`). When no sink has been
//! registered, dispatch is a no-op; OSS users who do not opt in pay
//! nothing.
//!
//! ## What this module does NOT do
//!
//! * No batching. Each call to [`dispatch_request_event`] hands one
//!   event to the sink synchronously. Backpressure / batching is the
//!   sink's responsibility (the enterprise NATS sink uses a bounded
//!   MPSC channel + drop-oldest policy per the ADR).
//! * No async. Sinks expose a sync `publish`; async backends spawn a
//!   background task and return immediately. The dispatch site is on
//!   the request hot path, so blocking is forbidden.

use std::sync::{Arc, OnceLock};

use crate::request_event::RequestEvent;

/// Trait every backend implements. `publish` MUST NOT block on I/O;
/// async backends should hand the event to a background task and
/// return immediately. The contract preserves the request hot path
/// regardless of backend latency.
pub trait RequestEventSink: Send + Sync {
    /// Hand a completed `RequestEvent` off to the backend. Sinks that
    /// fail internally should swallow the failure and update their
    /// own metrics (`sbproxy_ingest_dropped_total{reason="..."}` etc.);
    /// the dispatch site does not propagate sink errors.
    fn publish(&self, event: RequestEvent);
}

/// The default OSS sink. Drops every event silently. Acts as the
/// implicit no-op when no other sink has been registered.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl RequestEventSink for NoopSink {
    fn publish(&self, _event: RequestEvent) {
        // Intentional: no sink registered means nothing happens.
    }
}

/// A sink that emits each event as a single structured `tracing` log
/// line under the `request_event` target. Useful for OSS deployments
/// that want event visibility without standing up a broker, and for
/// debugging the capture path.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingSink;

impl RequestEventSink for LoggingSink {
    fn publish(&self, event: RequestEvent) {
        // serde_json::to_value is infallible on this struct; in the
        // unlikely event it returns Err we simply skip the log line
        // rather than panicking on the request hot path.
        match serde_json::to_string(&event) {
            Ok(json) => tracing::info!(target: "request_event", "{}", json),
            Err(e) => tracing::warn!(
                target: "request_event",
                error = %e,
                "request event serialization failed"
            ),
        }
    }
}

static SINK: OnceLock<Arc<dyn RequestEventSink>> = OnceLock::new();

/// Register the process-wide [`RequestEventSink`]. Returns `Err` if a
/// sink was already registered. Callers should set the sink during
/// startup, before any request enters the pipeline.
pub fn set_request_event_sink(sink: Arc<dyn RequestEventSink>) -> Result<(), &'static str> {
    SINK.set(sink)
        .map_err(|_| "request event sink already registered")
}

/// Hand a completed `RequestEvent` to the registered sink. When no
/// sink is registered (the OSS default), this is a no-op and pays a
/// single relaxed atomic load.
pub fn dispatch_request_event(event: RequestEvent) {
    if let Some(sink) = SINK.get() {
        sink.publish(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A test-only sink that captures every event into a vec for
    /// assertion. The locked Mutex<Vec<...>> approach is fine for the
    /// single-threaded test harness; production sinks should never use
    /// a coarse Mutex on the publish path.
    #[derive(Debug, Default)]
    struct CapturingSink {
        events: Mutex<Vec<RequestEvent>>,
    }

    impl CapturingSink {
        fn new() -> Self {
            Self::default()
        }
        fn captured(&self) -> Vec<RequestEvent> {
            self.events.lock().expect("capture lock").clone()
        }
    }

    impl RequestEventSink for CapturingSink {
        fn publish(&self, event: RequestEvent) {
            self.events.lock().expect("capture lock").push(event);
        }
    }

    fn sample_event() -> RequestEvent {
        RequestEvent::new_started("h".to_string(), ulid::Ulid::new(), "ws_test".to_string())
    }

    #[test]
    fn noop_sink_accepts_events_without_panicking() {
        let sink = NoopSink;
        sink.publish(sample_event());
    }

    #[test]
    fn capturing_sink_collects_published_events() {
        let sink = CapturingSink::new();
        sink.publish(sample_event());
        sink.publish(sample_event());
        assert_eq!(sink.captured().len(), 2);
    }

    #[test]
    fn logging_sink_publishes_without_panicking() {
        // Just exercise the path; we do not capture tracing output
        // here (downstream tracing tests own that). The test confirms
        // serialize-and-log does not panic on a fully-populated event.
        let sink = LoggingSink;
        let mut ev = sample_event();
        ev.user_id = Some("u".to_string());
        ev.session_id = Some(ulid::Ulid::new());
        ev.cost_usd_micros = Some(123);
        sink.publish(ev);
    }

    #[test]
    fn dispatch_is_noop_when_no_sink_registered() {
        // Cannot meaningfully test "no sink" once the global has been
        // set by another test in this module (OnceLock is set-once).
        // This test just confirms the function does not panic.
        dispatch_request_event(sample_event());
    }
}
