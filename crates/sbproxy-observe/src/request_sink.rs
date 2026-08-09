// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Transport adapter: a generic sink for completed
//! [`crate::request_event::RequestEvent`] values.
//!
//! The OSS build ships a [`NoopSink`] default, a [`LoggingSink`] that
//! emits each event as a structured `tracing` log line, and a
//! [`FileEventSink`] that appends NDJSON off the request path. Which
//! one runs is chosen by the top-level `request_events:` config block
//! and installed once at startup by
//! `sbproxy_core::server::lifecycle`. Out-of-tree deployments register
//! their own sink through [`set_request_event_sink`].
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
//! ## Drop accounting
//!
//! Every event a sink discards is counted on
//! `sbproxy_telemetry_dropped_total{kind="request_event",reason=...}`,
//! the same family the usage rollup writer and the alert transports
//! use. The closed reasons are `queue_full` (the file sink's hand-off
//! queue was at capacity), `writer_stopped` (its writer thread is
//! gone), `serialize_error`, and `write_error`. Silent loss is the
//! failure mode this exists to prevent: a sink that swallows an event
//! and says nothing looks exactly like a proxy that served no traffic.
//!
//! ## What this module does NOT do
//!
//! * No cross-event batching on the dispatch side. Each call to
//!   [`dispatch_request_event`] hands one event to the sink
//!   synchronously; a sink that wants batching does it behind its own
//!   queue, the way [`FileEventSink`] drains its channel in batches.
//! * No async. Sinks expose a sync `publish`; async backends spawn a
//!   background task and return immediately. The dispatch site is on
//!   the request hot path, so blocking is forbidden.
//! * No network egress. Shipping events to a broker or an OTLP
//!   collector needs retry, backpressure, and auth decisions that this
//!   file deliberately does not make.

use std::io::Write;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};

use crate::request_event::RequestEvent;

/// `kind` label every request-event drop is counted under on
/// `sbproxy_telemetry_dropped_total`.
const DROP_KIND: &str = "request_event";

/// Bound on [`FileEventSink`]'s hand-off queue. Matches the usage
/// rollup writer's queue: deep enough to absorb a burst while a slow
/// disk catches up, shallow enough that a wedged writer costs bounded
/// memory instead of the process.
const QUEUE_CAPACITY: usize = 8_192;

/// How many queued events the writer thread folds into one flush.
const DRAIN_BATCH: usize = 256;

/// Trait every backend implements. `publish` MUST NOT block on I/O;
/// async backends should hand the event to a background task and
/// return immediately. The contract preserves the request hot path
/// regardless of backend latency.
pub trait RequestEventSink: Send + Sync {
    /// Hand a completed `RequestEvent` off to the backend. Sinks that
    /// fail internally should swallow the failure and count it on
    /// `sbproxy_telemetry_dropped_total{kind="request_event"}`; the
    /// dispatch site does not propagate sink errors.
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

/// A sink that appends each event as one NDJSON line to a file.
///
/// The file write happens on a dedicated writer thread, never on the
/// caller's. [`publish`](RequestEventSink::publish) puts the event on
/// a bounded channel with `try_send` and returns, so the request that
/// produced the event never waits on the disk however slow it is.
///
/// ## Drop policy
///
/// Drop-newest. When the queue is at capacity (8192 events) the
/// incoming event is discarded and
/// `sbproxy_telemetry_dropped_total{kind="request_event",reason="queue_full"}`
/// ticks. Dropping the newest rather than the oldest is the cheaper
/// half of the choice (no re-lock of the queue head) and the safer
/// one: a burst that overruns the writer loses the tail of the burst
/// rather than the events that were already accepted and may already
/// be half written.
///
/// ## Durability
///
/// The writer drains up to 256 events per flush, so an abrupt
/// process exit loses at most the batch in flight. Dropping the
/// sink drains the queue, flushes, and joins the writer thread, which
/// is what an orderly shutdown wants; in production the sink lives in
/// a process-global slot and is never dropped.
pub struct FileEventSink {
    /// `None` only while the sink is being dropped, which is when the
    /// writer thread is told to finish.
    tx: Option<SyncSender<RequestEvent>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FileEventSink {
    /// Open `path` for appending (creating it if absent) and start the
    /// writer thread. Fails only when the file cannot be opened or the
    /// thread cannot be spawned; both are startup problems the caller
    /// reports rather than a per-event failure mode.
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let (tx, rx) = sync_channel::<RequestEvent>(QUEUE_CAPACITY);
        let handle = std::thread::Builder::new()
            .name("sbproxy-request-events".to_string())
            .spawn(move || {
                let mut writer = std::io::BufWriter::new(file);
                let mut batch: Vec<RequestEvent> = Vec::with_capacity(DRAIN_BATCH);
                // `recv` yields every buffered event before it reports
                // disconnection, so the loop exits only once the queue
                // is empty and no sender is left.
                while let Ok(first) = rx.recv() {
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH {
                        match rx.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(_) => break,
                        }
                    }
                    for event in batch.drain(..) {
                        match serde_json::to_string(&event) {
                            Ok(line) => {
                                if writeln!(writer, "{line}").is_err() {
                                    crate::metrics::record_telemetry_dropped(
                                        DROP_KIND,
                                        "write_error",
                                    );
                                }
                            }
                            Err(_) => crate::metrics::record_telemetry_dropped(
                                DROP_KIND,
                                "serialize_error",
                            ),
                        }
                    }
                    // Flush per drained batch rather than per line: the
                    // file stays tail-able without paying a syscall for
                    // every request the proxy serves.
                    if writer.flush().is_err() {
                        crate::metrics::record_telemetry_dropped(DROP_KIND, "write_error");
                    }
                }
                let _ = writer.flush();
            })?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    /// Build a sink over a caller-supplied channel.
    ///
    /// No writer thread is started, so nothing drains unless the caller
    /// drains it. The drop-policy tests use this to hold a queue that
    /// cannot empty underneath an assertion.
    #[cfg(test)]
    fn over_channel(tx: SyncSender<RequestEvent>) -> Self {
        Self {
            tx: Some(tx),
            handle: None,
        }
    }
}

impl RequestEventSink for FileEventSink {
    fn publish(&self, event: RequestEvent) {
        let Some(tx) = self.tx.as_ref() else {
            crate::metrics::record_telemetry_dropped(DROP_KIND, "writer_stopped");
            return;
        };
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                crate::metrics::record_telemetry_dropped(DROP_KIND, "queue_full");
            }
            Err(TrySendError::Disconnected(_)) => {
                crate::metrics::record_telemetry_dropped(DROP_KIND, "writer_stopped");
            }
        }
    }
}

impl Drop for FileEventSink {
    fn drop(&mut self) {
        // Drop the sender before joining. The writer thread's `recv`
        // reports disconnection only once no sender is left, and that
        // is the signal that makes it drain, flush, and return.
        self.tx = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
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

/// Hand a completed `RequestEvent` to the registered sink, and to the
/// `events:` egress when one selects its lifecycle type.
///
/// With neither configured (the OSS default) this is two relaxed atomic
/// loads and nothing else.
///
/// The two consumers are deliberately independent. `request_events:` is
/// the analytics stream and takes every terminating request;
/// [`crate::event_sink`] is the reaction stream and is usually filtered
/// down to a few types. Feeding one from the other would force an
/// operator who wants `policy_denied` in a SIEM to also stand up a
/// per-request envelope sink.
///
/// The egress call comes first so the closure can borrow `event` before
/// it is moved into the sink. It builds nothing unless an egress is
/// installed and selects this event's type, so a `policy_denied`
/// subscription does not pay to serialize every request the proxy
/// serves.
pub fn dispatch_request_event(event: RequestEvent) {
    crate::event_sink::publish_proxy_event(event.event_type, || {
        // The whole envelope becomes the event's `data`. Auditing that
        // for a third-party endpoint: `api_key_id` is the public id or
        // the derived `sk_<hex>` fingerprint and never the secret,
        // `prompt_fingerprint` is salted and non-reversible,
        // `key_provider` and `key_mode` are labels, and no field carries
        // prompt text or a header value. `properties` is the one field
        // whose contents are operator-shaped rather than fixed; it is
        // allowlist-checked, length-capped, and redaction-applied on the
        // capture path before it reaches here, and it is already written
        // to the request-event file and log sinks under the same rules.
        crate::events::ProxyEvent::new(
            event.event_type,
            event.hostname.clone(),
            event.tenant_id.clone().unwrap_or_default(),
            serde_json::to_value(&event).unwrap_or_else(
                |_| serde_json::json!({ "error": "request event did not serialize" }),
            ),
        )
    });
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

    /// The envelope reaches a third-party endpoint verbatim once an
    /// `events:` webhook sink is configured, so the field list is a
    /// disclosure decision. Adding a field to `RequestEvent` fails here
    /// until somebody confirms it cannot carry a credential.
    #[test]
    fn the_egress_payload_carries_only_secret_free_envelope_fields() {
        let mut event = sample_event();
        event.api_key_id = Some("sk_deadbeef".to_string());
        event.key_provider = Some("openai".to_string());
        event.key_mode = Some("native".to_string());
        event.prompt_fingerprint = Some("pf_0011".to_string());
        event.user_id = Some("u-1".to_string());
        event.user_id_source = Some(crate::request_event::UserIdSource::Header);
        event.session_id = Some(ulid::Ulid::new());
        event.parent_session_id = Some(ulid::Ulid::new());
        event.parent_request_id = Some(ulid::Ulid::new());
        event.tenant_id = Some("acme".to_string());
        event.latency_ms = Some(12);
        event.provider = Some("openai".to_string());
        event.model = Some("gpt-4o".to_string());
        event.prompt_tokens_est = Some(10);
        event.tokens_in = Some(10);
        event.tokens_out = Some(2);
        event.tokens_cached = Some(1);
        event.cost_usd_micros = Some(3);
        event.status_code = Some(200);
        event.error_class = Some("upstream_5xx".to_string());
        event.guardrail_category = Some("pii".to_string());
        event.guardrail_action = Some("block".to_string());
        event.request_geo = Some("US".to_string());
        event
            .properties
            .insert("environment".to_string(), "prod".to_string());

        let payload = serde_json::to_value(&event).expect("event serializes");
        let object = payload.as_object().expect("event is a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            vec![
                "api_key_id",
                "cost_usd_micros",
                "error_class",
                "event_type",
                "guardrail_action",
                "guardrail_category",
                "hostname",
                "key_mode",
                "key_provider",
                "latency_ms",
                "model",
                "parent_request_id",
                "parent_session_id",
                "prompt_fingerprint",
                "prompt_tokens_est",
                "properties",
                "provider",
                "request_geo",
                "request_id",
                "session_id",
                "status_code",
                "tenant_id",
                "timestamp_ms",
                "tokens_cached",
                "tokens_in",
                "tokens_out",
                "user_id",
                "user_id_source",
                "workspace_id",
            ],
            "a field was added to RequestEvent. It now ships to any \
             configured events: webhook, so confirm it cannot carry a \
             credential before adding it to this list."
        );
    }

    /// One `sbproxy_telemetry_dropped_total{kind="request_event"}`
    /// series off the default registry. Absent series read as zero,
    /// which is what a first drop of that reason looks like.
    fn dropped_total(reason: &str) -> u64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_telemetry_dropped_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels = metric.get_label();
                let kind_matches = labels
                    .iter()
                    .any(|pair| pair.name() == "kind" && pair.value() == DROP_KIND);
                let reason_matches = labels
                    .iter()
                    .any(|pair| pair.name() == "reason" && pair.value() == reason);
                if kind_matches && reason_matches {
                    return metric.get_counter().value() as u64;
                }
            }
        }
        0
    }

    #[test]
    fn file_sink_writes_every_published_event_as_ndjson() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("request-events.ndjson");

        let first = sample_event();
        let second = sample_event();
        let (first_id, second_id) = (first.request_id, second.request_id);

        let sink = FileEventSink::create(&path).expect("file sink opens");
        sink.publish(first);
        sink.publish(second);
        // Dropping drains the queue, flushes, and joins the writer, so
        // the read below cannot race the background thread.
        drop(sink);

        let written = std::fs::read_to_string(&path).expect("read back the ndjson");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "expected one line per event: {written}");
        assert!(
            lines[0].contains(&first_id.to_string()),
            "first line lost its request id: {}",
            lines[0]
        );
        assert!(
            lines[1].contains(&second_id.to_string()),
            "second line lost its request id: {}",
            lines[1]
        );
        // Each line is a complete JSON document, not a fragment.
        for line in lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line parses as JSON");
            assert_eq!(parsed["workspace_id"], "ws_test");
        }
    }

    #[test]
    fn file_sink_appends_to_an_existing_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("request-events.ndjson");
        std::fs::write(&path, "{\"pre\":true}\n").expect("seed the file");

        let sink = FileEventSink::create(&path).expect("file sink opens");
        sink.publish(sample_event());
        drop(sink);

        let written = std::fs::read_to_string(&path).expect("read back the ndjson");
        assert_eq!(written.lines().count(), 2, "append truncated: {written}");
        assert!(written.starts_with("{\"pre\":true}"));
    }

    #[test]
    fn a_full_queue_drops_the_newest_event_and_counts_it() {
        // A capacity-1 channel whose receiver never receives: the
        // first send takes the one slot and every later one is full.
        let (tx, rx) = sync_channel::<RequestEvent>(1);
        let sink = FileEventSink::over_channel(tx);

        let before = dropped_total("queue_full");
        sink.publish(sample_event());
        sink.publish(sample_event());
        sink.publish(sample_event());
        let after = dropped_total("queue_full");

        assert_eq!(
            after - before,
            2,
            "two of three events overran the queue and both must be counted"
        );
        // The one event that fit is still queued, so the drop policy
        // discarded the newest rather than evicting what was accepted.
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_stopped_writer_drops_the_event_and_counts_it() {
        let (tx, rx) = sync_channel::<RequestEvent>(4);
        drop(rx);
        let sink = FileEventSink::over_channel(tx);

        let before = dropped_total("writer_stopped");
        sink.publish(sample_event());
        let after = dropped_total("writer_stopped");

        assert_eq!(after - before, 1);
    }
}
