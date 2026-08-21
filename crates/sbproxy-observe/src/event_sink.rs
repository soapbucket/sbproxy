// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Egress for the eighteen [`crate::events::EventType`] variants: the
//! `events:` block's file and webhook sinks.
//!
//! # The defect this closes
//!
//! [`crate::events::EventBus`] fans out to handler closures **on the
//! publisher's thread**, in registration order, with the handler map
//! held under a lock for the whole fan-out. That is fine for a closure
//! that increments a counter and wrong for anything that touches a
//! socket: a handler that POSTs to a SIEM makes every request that
//! trips a policy wait for that SIEM. Nothing crossed the process
//! boundary before this module, so the shape had never been paid for,
//! and shipping a synchronous webhook would have been worse than
//! shipping nothing.
//!
//! So this is not a bus handler. Publishing is a bitmask test and one
//! `try_send` on a bounded queue, and everything after that happens on a
//! thread the request has no relationship with. A sink that is slow,
//! wedged, or gone cannot make a request slower than that `try_send`.
//!
//! # Backpressure is a drop, and the drop is counted
//!
//! There is no version of this where a full queue blocks. The queue is
//! bounded at `events.queue_capacity` (default
//! [`crate::event_sink::DEFAULT_QUEUE_CAPACITY`]); when it is full the incoming event is
//! discarded and
//! `sbproxy_events_dropped_total{sink,reason="queue_full"}` ticks.
//!
//! Drop-newest, matching [`crate::request_sink::FileEventSink`]: a burst
//! that overruns the writer loses the tail of the burst rather than
//! events already accepted and possibly already in flight.
//!
//! Every other way an event fails to arrive is counted on the same
//! family under its own reason, so "the SIEM has no denials in it" always
//! has an answer that is not "read the source". The closed set is
//! `queue_full`, `worker_stopped`, `serialize_error`, `write_error`,
//! `http_error`, `delivery_failed`, and `ssrf_rejected`.
//!
//! # Shutdown does not flush
//!
//! Stated plainly because the alternative is an operator assuming it
//! does. The egress lives in a process-global [`std::sync::OnceLock`] and is never
//! dropped, so `SIGTERM` and `SIGKILL` both end the process with
//! whatever is still queued still queued: up to `queue_capacity` events,
//! plus the batch the worker is mid-delivery on.
//!
//! Two things bound the loss rather than eliminating it. The file sink
//! flushes its `BufWriter` after every drained batch, so what reached the
//! file is on the file and not in userspace. The webhook sink delivers
//! one batch at a time and never buffers across batches. What is lost is
//! what had not yet been picked up, and an events stream is a telemetry
//! stream: the tamper-evident, survives-the-process channel is
//! `audit.sink: chain` (see [`crate::audit_chain`]), which is a
//! deliberately different mechanism with a deliberately different
//! durability promise. Do not use `events:` where you need that one.
//!
//! Dropping an [`EventEgress`] value *does* drain, flush, and join, which
//! is what the tests in this module rely on and what an embedder holding
//! one directly gets.
//!
//! # What is not here
//!
//! Kafka, NATS, and EventBridge. Each needs a client library, a
//! partitioning decision, and a delivery-guarantee story that a `try_send`
//! and a best-effort POST do not have, and none of the three is a
//! prerequisite for the thing operators actually asked for, which was
//! getting policy denials into a SIEM without parsing a log file. They
//! are follow-ups; the config refuses their names today rather than
//! accepting them into a sink that would not deliver.
//!
//! Retries are also not here. One attempt per batch, and a failure is
//! counted rather than requeued. A retry queue in front of a bounded
//! queue converts a slow endpoint into dropped events *plus* a stall, and
//! deciding otherwise means deciding how long an event is worth holding,
//! which is a decision this module does not have the information to make.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::Duration;

use crate::events::{EventType, ProxyEvent, ALL_EVENT_TYPES};

/// Default bound on the hand-off queue when `events.queue_capacity` is
/// absent. Matches [`crate::request_sink`]'s reasoning: deep enough to
/// absorb a burst while a slow sink catches up, shallow enough that a
/// wedged sink costs bounded memory instead of the process.
pub const DEFAULT_QUEUE_CAPACITY: usize = 4_096;

/// How many queued events the worker folds into one file flush or one
/// webhook POST.
const DRAIN_BATCH: usize = 256;

/// Per-attempt HTTP timeout for the webhook sink.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Which [`EventType`]s an egress delivers.
///
/// A bitmask rather than a `HashSet` because the test runs on the
/// request path, once per candidate event, before anything is allocated:
/// it has to be cheaper than the event it is deciding not to build.
///
/// `u32` holds the eighteen bits [`ALL_EVENT_TYPES`] declares with room to
/// spare. A nineteenth variant is caught by that array's fixed length
/// long before it reaches the width of this word. (`u16` held the
/// original thirteen; the five key-lifecycle types of WOR-2571 pushed
/// the bit count past sixteen, where a debug build's shift-overflow
/// check turns `1 << index` into a panic rather than a wrong mask.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventTypeMask(u32);

impl EventTypeMask {
    /// Every event type. What an `events:` block with no `types:` filter
    /// resolves to.
    pub fn all() -> Self {
        let mut bits = 0u32;
        for event_type in ALL_EVENT_TYPES {
            bits |= 1 << event_type.index();
        }
        Self(bits)
    }

    /// Exactly the named types.
    pub fn from_types(types: &[EventType]) -> Self {
        let mut bits = 0u32;
        for event_type in types {
            bits |= 1 << event_type.index();
        }
        Self(bits)
    }

    /// Whether this mask selects `event_type`.
    pub fn contains(&self, event_type: EventType) -> bool {
        self.0 & (1 << event_type.index()) != 0
    }

    /// Whether the mask selects nothing. An egress with an empty mask
    /// would accept configuration and deliver nothing, which is the
    /// shape the config validator refuses.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

/// Where a running egress delivers.
///
/// `Debug` is hand written on the webhook arm. A derive would print
/// `signing_secret`, and this type is reachable from log lines that
/// describe boot.
#[derive(Clone)]
pub enum EventSinkTarget {
    /// Append each event as one NDJSON line to a file.
    File {
        /// Output path. Created if absent, appended to if present.
        path: PathBuf,
    },
    /// POST batches of events to an HTTP endpoint.
    Webhook {
        /// Destination URL. Validated against the SSRF guard at
        /// construction and again before every batch.
        url: String,
        /// Resolved HMAC-SHA256 signing key, or `None` for an unsigned
        /// POST. Comes from the secret-reference machinery; a literal
        /// never reaches here from a config field.
        signing_secret: Option<String>,
    },
}

impl std::fmt::Debug for EventSinkTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File { path } => formatter
                .debug_struct("EventSinkTarget::File")
                .field("path", path)
                .finish(),
            Self::Webhook {
                url,
                signing_secret,
            } => formatter
                .debug_struct("EventSinkTarget::Webhook")
                .field("url", url)
                .field("signed", &signing_secret.is_some())
                .finish(),
        }
    }
}

impl EventSinkTarget {
    /// The `sink` label every drop from this target is counted under.
    pub fn label(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Webhook { .. } => "webhook",
        }
    }
}

/// Why [`EventEgress::publish_checked`] or [`publish_proxy_event_checked`]
/// could not hand an event to the worker (WOR-2384).
///
/// [`EventEgress::publish`] and [`publish_proxy_event`] never report
/// this: their whole contract is that a caller on the request path
/// cannot be made to care. `events.fail_closed` exists for the callers
/// that must care, naming event types for which a silent drop is worse
/// than refusing the request that would have produced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPublishError {
    /// The hand-off queue was at `events.queue_capacity`; the event was
    /// discarded rather than blocking the caller.
    QueueFull,
    /// The worker thread is gone, or the egress is mid-[`Drop`]. Nothing
    /// will ever drain this queue again.
    WorkerStopped,
    /// No egress is installed, or the installed egress's `types:` filter
    /// does not select this event type. Either way nothing was ever
    /// going to deliver it, which [`publish_proxy_event_checked`] treats
    /// as the same fact [`EventEgress::publish_checked`] cannot see on
    /// its own: there was no egress instance to ask.
    NoSinkConfigured,
}

impl EventPublishError {
    /// Stable label, matching the `reason` this same failure is counted
    /// under on `sbproxy_events_dropped_total` where one applies.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::WorkerStopped => "worker_stopped",
            Self::NoSinkConfigured => "no_sink_configured",
        }
    }
}

impl std::fmt::Display for EventPublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for EventPublishError {}

/// A running event egress: a bounded queue, a worker thread draining it,
/// and the type filter the producer side tests against.
pub struct EventEgress {
    /// `None` only while the egress is being dropped, which is the
    /// signal that makes the worker drain and finish.
    tx: Option<SyncSender<ProxyEvent>>,
    handle: Option<std::thread::JoinHandle<()>>,
    types: EventTypeMask,
    sink_label: &'static str,
}

impl std::fmt::Debug for EventEgress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventEgress")
            .field("sink", &self.sink_label)
            .field("types", &self.types)
            .field("running", &self.handle.is_some())
            .finish()
    }
}

impl EventEgress {
    /// Open `target`, start its worker thread, and return the handle the
    /// publish path talks to.
    ///
    /// Fails only on startup problems the caller can report: a file that
    /// cannot be opened, a webhook URL the SSRF guard refuses, an HTTP
    /// client or Tokio runtime that will not build, a thread that will
    /// not spawn. Everything after this is a counted drop rather than an
    /// error, because the caller by then is a request being refused and
    /// has nothing useful to do with one.
    pub fn start(
        target: EventSinkTarget,
        types: EventTypeMask,
        queue_capacity: usize,
    ) -> anyhow::Result<Self> {
        let sink_label = target.label();
        let (tx, rx) = sync_channel::<ProxyEvent>(queue_capacity);

        let handle = match target {
            EventSinkTarget::File { path } => start_file_worker(&path, rx)?,
            EventSinkTarget::Webhook {
                url,
                signing_secret,
            } => start_webhook_worker(url, signing_secret, rx)?,
        };

        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            types,
            sink_label,
        })
    }

    /// Whether this egress was configured to deliver `event_type`.
    pub fn wants(&self, event_type: EventType) -> bool {
        self.types.contains(event_type)
    }

    /// Hand one event to the worker, or count the reason it could not be
    /// handed over.
    ///
    /// Never blocks and never fails from the caller's side. This is the
    /// whole contract: the function runs on the request path and the
    /// only thing it is allowed to cost is a bounded `try_send`.
    pub fn publish(&self, event: ProxyEvent) {
        let Some(tx) = self.tx.as_ref() else {
            crate::metrics::record_events_dropped(self.sink_label, "worker_stopped");
            return;
        };
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                crate::metrics::record_events_dropped(self.sink_label, "queue_full");
            }
            Err(TrySendError::Disconnected(_)) => {
                crate::metrics::record_events_dropped(self.sink_label, "worker_stopped");
            }
        }
    }

    /// Hand one event to the worker, reporting a delivery failure back
    /// to the caller instead of only counting it (WOR-2384).
    ///
    /// Same non-blocking `try_send` as [`Self::publish`], and the same
    /// drop-reason metric increments on every failing path, so a sink
    /// mixing fail-closed and best-effort event types still gets one
    /// consistent `sbproxy_events_dropped_total` count. The only
    /// difference is the return value: [`Self::publish`]'s whole
    /// contract is that a request-path caller cannot be made to care
    /// whether delivery worked, and this is for the caller that must.
    ///
    /// Cannot itself return [`EventPublishError::NoSinkConfigured`]: an
    /// `EventEgress` that exists is, by definition, configured for
    /// something. That case belongs to [`publish_proxy_event_checked`],
    /// which is the one that knows whether an egress exists at all.
    pub fn publish_checked(&self, event: ProxyEvent) -> Result<(), EventPublishError> {
        let Some(tx) = self.tx.as_ref() else {
            crate::metrics::record_events_dropped(self.sink_label, "worker_stopped");
            return Err(EventPublishError::WorkerStopped);
        };
        match tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                crate::metrics::record_events_dropped(self.sink_label, "queue_full");
                Err(EventPublishError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                crate::metrics::record_events_dropped(self.sink_label, "worker_stopped");
                Err(EventPublishError::WorkerStopped)
            }
        }
    }

    /// Build an egress over a caller-supplied channel with no worker.
    ///
    /// Nothing drains unless the caller drains it, which is how the
    /// drop-policy tests hold a queue that cannot empty underneath an
    /// assertion.
    #[cfg(test)]
    fn over_channel(
        tx: SyncSender<ProxyEvent>,
        types: EventTypeMask,
        sink_label: &'static str,
    ) -> Self {
        Self {
            tx: Some(tx),
            handle: None,
            types,
            sink_label,
        }
    }

    /// Test-only: an egress whose queue nothing ever drains (WOR-2384).
    ///
    /// `handle` stays `None`, exactly like `over_channel` above: no
    /// worker thread is spawned, so nothing ever calls `recv` on the
    /// receiving half and `queue_capacity` publishes permanently occupy
    /// the channel's slots. Every publish after that observes `Full`
    /// straight from `std::sync::mpsc`'s own bounded-queue bookkeeping,
    /// not from a race against a real drain loop, which is what makes
    /// the resulting [`EventPublishError::QueueFull`] deterministic
    /// rather than a timing bet -- a real worker (even an artificially
    /// slow one) still drains the instant it gets scheduled, and a
    /// caller cannot control when that happens.
    ///
    /// The receiver half is deliberately kept alive rather than
    /// dropped: an `mpsc` channel reports `Disconnected` (mapped to
    /// [`EventPublishError::WorkerStopped`]) once its receiver is gone,
    /// even if the buffer itself has room, so a first version of this
    /// function that let the receiver fall out of scope at the end of
    /// the function body made the very first publish fail closed for
    /// the wrong reason -- disconnection, not fullness -- rather than
    /// queuing at all. `Box::leak` fixes that with the least surface:
    /// the receiver is never read from (so nothing here can ever drain
    /// the fullness this constructor exists to guarantee) and never
    /// dropped (so the channel never reports disconnected), which is
    /// exactly "connected and undrained." Leaking is fine for a
    /// test-only, once-per-test-process handle: nothing ever needs the
    /// receiver back, and it is one bounded, small allocation for the
    /// rest of the process's life either way.
    ///
    /// This exists as its own function, rather than exposing
    /// `over_channel` itself, because `#[cfg(test)]` items compile only
    /// into the crate that declares them: `sbproxy-observe`'s own test
    /// binary can already see `over_channel`, but a *different* crate's
    /// tests link against the normal (non-test) `rlib`, where a
    /// `#[cfg(test)]` item simply does not exist. `sbproxy-core`'s
    /// WOR-2384 queue-full dispatch test needs exactly this shape from
    /// across that boundary.
    ///
    /// A literal permanently-parked worker *thread* was the other way
    /// to get a queue that never drains, and was rejected: [`Drop`]
    /// joins `handle` unconditionally once `tx` clears, and a thread
    /// whose loop is only `std::thread::park()` never returns, so the
    /// join -- and the whole test process -- would hang at teardown.
    /// Spawning no thread at all sidesteps that hazard entirely, the
    /// same way `over_channel` already does for this crate's own tests.
    ///
    /// `#[doc(hidden)]`: a cross-crate test seam, not part of the
    /// supported API surface (this crate is internal to begin with; see
    /// the workspace `CLAUDE.md`'s public-surface list). Named to match
    /// the `..._for_test` seams `sbproxy_extension::mcp::federation`
    /// exposes for the same reason (`seed_tools_for_test` and
    /// siblings).
    #[doc(hidden)]
    pub fn never_drained_for_test(
        types: EventTypeMask,
        sink_label: &'static str,
        queue_capacity: usize,
    ) -> Self {
        let (tx, rx) = sync_channel::<ProxyEvent>(queue_capacity);
        // Keep the channel connected without ever draining it: see the
        // doc comment above for why leaking (rather than dropping, or
        // storing and later reading) is the correct choice here.
        Box::leak(Box::new(rx));
        Self {
            tx: Some(tx),
            handle: None,
            types,
            sink_label,
        }
    }
}

impl Drop for EventEgress {
    fn drop(&mut self) {
        // Drop the sender first. The worker's `recv` reports
        // disconnection only once no sender is left, and that is what
        // makes it drain, flush, and return.
        self.tx = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Pull up to [`DRAIN_BATCH`] events, blocking for the first.
///
/// Returns an empty vec once the channel is disconnected and drained,
/// which is the worker's exit condition. `recv` yields every buffered
/// event before it reports disconnection, so a shutdown never strands a
/// value that was already accepted.
fn drain_batch(rx: &Receiver<ProxyEvent>) -> Vec<ProxyEvent> {
    let mut batch = Vec::new();
    match rx.recv() {
        Ok(first) => batch.push(first),
        Err(_) => return batch,
    }
    while batch.len() < DRAIN_BATCH {
        match rx.try_recv() {
            Ok(event) => batch.push(event),
            Err(_) => break,
        }
    }
    batch
}

/// Start the NDJSON file worker.
fn start_file_worker(
    path: &Path,
    rx: Receiver<ProxyEvent>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                anyhow::anyhow!(
                    "events.path {}: cannot create the directory {}: {error}",
                    path.display(),
                    parent.display()
                )
            })?;
        }
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| anyhow::anyhow!("events.path {}: {error}", path.display()))?;

    let handle = std::thread::Builder::new()
        .name("sbproxy-events-file".to_string())
        .spawn(move || {
            let mut writer = std::io::BufWriter::new(file);
            loop {
                let batch = drain_batch(&rx);
                if batch.is_empty() {
                    break;
                }
                for event in batch {
                    match serde_json::to_string(&event) {
                        Ok(line) => {
                            if writeln!(writer, "{line}").is_err() {
                                crate::metrics::record_events_dropped("file", "write_error");
                            }
                        }
                        Err(_) => {
                            crate::metrics::record_events_dropped("file", "serialize_error");
                        }
                    }
                }
                // Flush per drained batch rather than per line: the file
                // stays tail-able without paying a syscall per event, and
                // an abrupt exit loses at most one batch.
                if writer.flush().is_err() {
                    crate::metrics::record_events_dropped("file", "write_error");
                }
            }
            let _ = writer.flush();
        })?;
    Ok(handle)
}

/// Start the webhook worker.
///
/// The runtime and the HTTP client are built here rather than inside the
/// thread so a failure to build either is a startup error the operator
/// sees, not a worker that exits silently one millisecond after boot
/// reported success.
///
/// A current-thread runtime on a dedicated std thread, for the same
/// reason the policy-bus drain and the OTLP metrics reader use one: there
/// is no ambient multi-thread Tokio runtime at the point telemetry is
/// installed, because Pingora builds its runtimes later.
fn start_webhook_worker(
    url: String,
    signing_secret: Option<String>,
    rx: Receiver<ProxyEvent>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    if !allow_private_urls() {
        if let Err(reason) = sbproxy_security::ssrf::validate_url(&url) {
            anyhow::bail!("events.url is refused by the SSRF guard: {reason}");
        }
    }

    let client = reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .map_err(|error| anyhow::anyhow!("events webhook client: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("events webhook runtime: {error}"))?;

    let handle = std::thread::Builder::new()
        .name("sbproxy-events-webhook".to_string())
        .spawn(move || loop {
            let batch = drain_batch(&rx);
            if batch.is_empty() {
                break;
            }
            runtime.block_on(deliver_batch(
                &client,
                &url,
                signing_secret.as_deref(),
                &batch,
            ));
        })?;
    Ok(handle)
}

/// POST one batch. One attempt, no retry; see the module docs.
///
/// Every failure path counts once per event in the batch rather than
/// once per batch, so the metric answers "how many events did my SIEM
/// not get" rather than "how many POSTs failed", which is the question
/// an operator reconciling two systems is actually asking.
async fn deliver_batch(
    client: &reqwest::Client,
    url: &str,
    signing_secret: Option<&str>,
    batch: &[ProxyEvent],
) {
    let count = batch.len() as u64;

    if !allow_private_urls() {
        let target = url.to_string();
        let verdict =
            tokio::task::spawn_blocking(move || sbproxy_security::ssrf::validate_url(&target))
                .await;
        match verdict {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => {
                tracing::error!(
                    target: "events",
                    reason = %reason,
                    "events webhook url failed SSRF validation; batch dropped"
                );
                count_batch_drop("webhook", "ssrf_rejected", count);
                return;
            }
            Err(error) => {
                tracing::error!(
                    target: "events",
                    error = %error,
                    "events webhook SSRF validation task failed; batch dropped"
                );
                count_batch_drop("webhook", "ssrf_rejected", count);
                return;
            }
        }
    }

    let envelope = serde_json::json!({
        "source": "sbproxy",
        "version": env!("CARGO_PKG_VERSION"),
        "events": batch,
    });
    let body = match serde_json::to_vec(&envelope) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(target: "events", error = %error, "events batch would not serialize");
            count_batch_drop("webhook", "serialize_error", count);
            return;
        }
    };

    let timestamp = chrono::Utc::now().timestamp();
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", concat!("sbproxy/", env!("CARGO_PKG_VERSION")))
        .header("X-Sbproxy-Event", "proxy_events")
        .header("X-Sbproxy-Event-Count", count.to_string())
        .header("X-Sbproxy-Timestamp", timestamp.to_string());
    if let Some(secret) = signing_secret {
        if let Some(signature) = sign_batch(secret, &body, timestamp) {
            request = request.header("X-Sbproxy-Signature", signature);
        }
    }

    match request.body(body).send().await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(
                target: "events",
                status = %response.status(),
                count,
                "events webhook returned non-success; batch dropped"
            );
            count_batch_drop("webhook", "http_error", count);
        }
        Err(error) => {
            // Not `error = %error`: a `reqwest::Error` Display ends with
            // " for url ({url})", and the events webhook is the same
            // shape of operator secret this file already refuses to log
            // above (WOR-2629).
            tracing::warn!(
                target: "events",
                error = %sbproxy_httpkit::request_error_summary(&error),
                count,
                "events webhook delivery failed; batch dropped"
            );
            count_batch_drop("webhook", "delivery_failed", count);
        }
    }
}

/// Count one drop per event in a failed batch.
fn count_batch_drop(sink: &'static str, reason: &'static str, count: u64) {
    for _ in 0..count {
        crate::metrics::record_events_dropped(sink, reason);
    }
}

/// `v1=<hex>` HMAC-SHA256 over `<timestamp>.<body>`, the same
/// construction the alert webhook signs with, so a receiver already
/// verifying one verifies the other with the same code.
///
/// `None` only if the HMAC will not accept the key, which
/// `SimpleHmac` never does for any byte length. Returning an `Option`
/// rather than unwrapping keeps a would-be-impossible failure from being
/// the one thing that can abort a delivery thread.
fn sign_batch(secret: &str, body: &[u8], timestamp: i64) -> Option<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

/// Tests point the webhook sink at a loopback stub, which is exactly what
/// the SSRF guard exists to refuse. Compiled out of the shipping binary.
#[cfg(test)]
fn allow_private_urls() -> bool {
    true
}

#[cfg(not(test))]
fn allow_private_urls() -> bool {
    false
}

/// The process-wide egress, or nothing when `events:` is absent or set to
/// `sink: none`.
static EGRESS: OnceLock<EventEgress> = OnceLock::new();

/// Register the process-wide egress. Returns `Err` if one is already
/// registered.
///
/// Startup-only and set-once, the same shape as the request-event sink
/// and the session ledger. A reload does not re-register: swapping a
/// live sink would either strand a queue nothing will drain or open a
/// second file that looks like a gap in the first.
pub fn install_event_egress(egress: EventEgress) -> Result<(), &'static str> {
    EGRESS
        .set(egress)
        .map_err(|_| "event egress already registered")
}

/// Whether an installed egress would even attempt to deliver
/// `event_type` (WOR-2384).
///
/// The single predicate [`publish_proxy_event`] and
/// [`publish_proxy_event_checked`] both gate their `build` closure on:
/// they call this rather than re-deriving `EGRESS.get().is_some_and(..)`
/// themselves, so the "would anything accept this" question has exactly
/// one implementation instead of three that have to be kept in
/// agreement by hand. Exposed publicly too, for a caller with its own
/// expensive prerequisites to a publish call (a per-tenant sequence
/// number, a redaction pass) to check first and skip building them
/// entirely rather than paying for work nobody will receive, the same
/// way `build` itself is skipped.
pub fn wants_event(event_type: EventType) -> bool {
    EGRESS.get().is_some_and(|egress| egress.wants(event_type))
}

/// Publish an event, building it only if somebody is listening.
///
/// `build` runs only when [`wants_event`] says yes. That ordering is
/// the point: bridging a request-path funnel into this costs one
/// relaxed load and one bitmask test on a proxy with no `events:`
/// block, and a `policy_denied` sink does not pay to serialize every
/// completed request.
pub fn publish_proxy_event(event_type: EventType, build: impl FnOnce() -> ProxyEvent) {
    if !wants_event(event_type) {
        return;
    }
    // `wants_event` returning `true` already proved `EGRESS` is set,
    // and it is a set-once `OnceLock` that never reverts to unset, so
    // this second lookup cannot legitimately miss; the `else` exists
    // only because the compiler cannot see that invariant.
    let Some(egress) = EGRESS.get() else {
        return;
    };
    egress.publish(build());
}

/// [`publish_proxy_event`]'s fail-closed sibling (WOR-2384): `build`
/// still runs only when [`wants_event`] says yes, but a caller that
/// must know whether delivery worked gets `Err` back instead of a
/// fire-and-forget guarantee it cannot verify.
///
/// `Err(`[`EventPublishError::NoSinkConfigured`]`)` covers both "no
/// egress is installed" and "an egress is installed but its `types:`
/// filter does not select `event_type`", which is exactly what
/// [`wants_event`] answers `false` for. A caller deciding whether to
/// refuse a request cannot act on the difference between those two: in
/// both, nothing was ever going to deliver this event.
pub fn publish_proxy_event_checked(
    event_type: EventType,
    build: impl FnOnce() -> ProxyEvent,
) -> Result<(), EventPublishError> {
    if !wants_event(event_type) {
        return Err(EventPublishError::NoSinkConfigured);
    }
    // See `publish_proxy_event`'s matching comment: this cannot
    // legitimately miss once `wants_event` has already said yes.
    let Some(egress) = EGRESS.get() else {
        return Err(EventPublishError::NoSinkConfigured);
    };
    egress.publish_checked(build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    fn event(event_type: EventType) -> ProxyEvent {
        ProxyEvent::new(
            event_type,
            "api.example.com".to_string(),
            "acme".to_string(),
            serde_json::json!({"reason": "rate_limit"}),
        )
    }

    /// One `sbproxy_events_dropped_total{sink,reason}` series off the
    /// default registry. An absent series reads as zero, which is what a
    /// first drop of that pair looks like.
    fn dropped(sink: &str, reason: &str) -> u64 {
        for family in prometheus::gather() {
            if family.name() != "sbproxy_events_dropped_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels = metric.get_label();
                let sink_matches = labels
                    .iter()
                    .any(|pair| pair.name() == "sink" && pair.value() == sink);
                let reason_matches = labels
                    .iter()
                    .any(|pair| pair.name() == "reason" && pair.value() == reason);
                if sink_matches && reason_matches {
                    return metric.get_counter().value() as u64;
                }
            }
        }
        0
    }

    #[test]
    fn mask_all_selects_every_declared_type() {
        let mask = EventTypeMask::all();
        for event_type in ALL_EVENT_TYPES {
            assert!(mask.contains(event_type), "all() dropped {event_type:?}");
        }
        assert!(!mask.is_empty());
    }

    #[test]
    fn mask_from_types_selects_only_the_named_ones() {
        let mask = EventTypeMask::from_types(&[EventType::PolicyDenied, EventType::AuthDenied]);
        assert!(mask.contains(EventType::PolicyDenied));
        assert!(mask.contains(EventType::AuthDenied));
        assert!(!mask.contains(EventType::CacheHit));
        assert!(!mask.contains(EventType::RequestCompleted));
        assert!(EventTypeMask::from_types(&[]).is_empty());
    }

    #[test]
    fn debug_never_prints_the_signing_secret() {
        let target = EventSinkTarget::Webhook {
            url: "https://siem.example.com/ingest".to_string(),
            signing_secret: Some("super-secret-value".to_string()),
        };
        let rendered = format!("{target:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "the signing secret reached a Debug render: {rendered}"
        );
        assert!(rendered.contains("signed: true"), "{rendered}");
    }

    #[test]
    fn a_full_queue_drops_the_newest_event_and_counts_it() {
        // A capacity-1 channel whose receiver never receives: the first
        // send takes the slot and every later one finds it full.
        let (tx, rx) = sync_channel::<ProxyEvent>(1);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "file");

        let before = dropped("file", "queue_full");
        egress.publish(event(EventType::PolicyDenied));
        egress.publish(event(EventType::PolicyDenied));
        egress.publish(event(EventType::PolicyDenied));
        let after = dropped("file", "queue_full");

        assert_eq!(
            after - before,
            2,
            "two of three events overran the queue and both must be counted"
        );
        // The accepted event is still queued: the policy discarded the
        // newest rather than evicting something already taken.
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_full_queue_does_not_block_the_publisher() {
        let (tx, _rx) = sync_channel::<ProxyEvent>(1);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "file");

        // Fill it, then overrun it hard. A `send` instead of a
        // `try_send` would park the caller here forever, because
        // nothing is draining.
        let started = Instant::now();
        for _ in 0..10_000 {
            egress.publish(event(EventType::PolicyDenied));
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "publishing into a full queue took {elapsed:?}; the publish path blocked"
        );
    }

    /// WOR-2571: the drop path is type-agnostic by construction, and
    /// that is exactly why nothing but this test says so for the
    /// key-lifecycle kinds. A future per-type branch in `publish` (a
    /// special case for a "critical" type, say) would make a full
    /// queue silently uncountable for whichever types the branch
    /// forgot, and this is the test that would catch it for the five
    /// WOR-2571 kinds.
    #[test]
    fn a_full_queue_counts_drops_for_every_key_lifecycle_kind() {
        let egress = EventEgress::never_drained_for_test(EventTypeMask::all(), "file", 1);
        // The single slot is taken; every publish after this drops.
        egress.publish(event(EventType::KeyMinted));

        let before = dropped("file", "queue_full");
        for kind in [
            EventType::KeyMinted,
            EventType::KeyRevoked,
            EventType::KeyRotated,
            EventType::KeyBlocked,
            EventType::CredentialResolved,
        ] {
            egress.publish(event(kind));
        }
        let after = dropped("file", "queue_full");

        assert_eq!(
            after - before,
            5,
            "each overrun key-lifecycle publish must be counted"
        );
    }

    #[test]
    fn a_stopped_worker_drops_the_event_and_counts_it() {
        let (tx, rx) = sync_channel::<ProxyEvent>(4);
        drop(rx);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "webhook");

        let before = dropped("webhook", "worker_stopped");
        egress.publish(event(EventType::AuthDenied));
        let after = dropped("webhook", "worker_stopped");

        assert_eq!(after - before, 1);
    }

    #[test]
    fn file_sink_writes_one_ndjson_line_per_event() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nested").join("events.ndjson");

        let egress = EventEgress::start(
            EventSinkTarget::File { path: path.clone() },
            EventTypeMask::all(),
            16,
        )
        .expect("file egress starts");
        egress.publish(event(EventType::PolicyDenied));
        egress.publish(event(EventType::AuthDenied));
        // Dropping drains, flushes, and joins, so the read cannot race
        // the worker.
        drop(egress);

        let written = std::fs::read_to_string(&path).expect("read back the ndjson");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "expected one line per event: {written}");

        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 parses");
        assert_eq!(first["event_type"], "policy_denied");
        assert_eq!(first["hostname"], "api.example.com");
        assert_eq!(first["tenant_id"], "acme");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 parses");
        assert_eq!(second["event_type"], "auth_denied");
    }

    #[test]
    fn file_sink_appends_rather_than_truncating() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("events.ndjson");
        std::fs::write(&path, "{\"pre\":true}\n").expect("seed the file");

        let egress = EventEgress::start(
            EventSinkTarget::File { path: path.clone() },
            EventTypeMask::all(),
            16,
        )
        .expect("file egress starts");
        egress.publish(event(EventType::CacheHit));
        drop(egress);

        let written = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(written.lines().count(), 2, "append truncated: {written}");
        assert!(written.starts_with("{\"pre\":true}"));
    }

    /// Read one HTTP request off `socket` until its declared body has
    /// arrived, then answer `204`.
    ///
    /// A single `read` is not enough: hyper is free to put the headers
    /// and the body in separate segments, and a stub that asserts on
    /// whatever the first read happened to contain is a test that passes
    /// on this machine.
    fn read_request_and_ack(socket: &mut TcpStream) -> String {
        let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8 * 1024];
        loop {
            let read = match socket.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw);
            let Some(header_end) = text.find("\r\n\r\n") else {
                continue;
            };
            let declared = text[..header_end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if raw.len() >= header_end + 4 + declared {
                break;
            }
        }
        let _ = socket.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        let _ = socket.flush();
        String::from_utf8_lossy(&raw).to_string()
    }

    #[test]
    fn webhook_sink_posts_a_signed_batch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        let received = Arc::new(std::sync::Mutex::new(String::new()));
        let sink_side = received.clone();

        let stub = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let request = read_request_and_ack(&mut socket);
                if let Ok(mut slot) = sink_side.lock() {
                    *slot = request;
                }
            }
        });

        let egress = EventEgress::start(
            EventSinkTarget::Webhook {
                url: format!("http://{addr}/ingest"),
                signing_secret: Some("shhh".to_string()),
            },
            EventTypeMask::from_types(&[EventType::PolicyDenied]),
            16,
        )
        .expect("webhook egress starts");
        egress.publish(event(EventType::PolicyDenied));
        drop(egress);
        let _ = stub.join();

        let request = received.lock().map(|slot| slot.clone()).unwrap_or_default();
        let lowered = request.to_ascii_lowercase();
        assert!(
            lowered.contains("x-sbproxy-signature: v1="),
            "the batch was not signed: {request}"
        );
        assert!(
            lowered.contains("x-sbproxy-event-count: 1"),
            "the batch did not declare its size: {request}"
        );
        assert!(
            request.contains("policy_denied"),
            "the event never reached the wire: {request}"
        );
        assert!(
            !request.contains("shhh"),
            "the signing secret was transmitted rather than used as a key: {request}"
        );
    }

    #[test]
    fn a_dead_sink_does_not_stall_the_publisher() {
        // A listener that accepts and then says nothing. Each POST hangs
        // until the client-side timeout, so the worker is provably stuck
        // for seconds while the assertions below run.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind blackhole");
        let addr = listener.local_addr().expect("blackhole addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let keep_open = Arc::new(std::sync::Mutex::new(Vec::new()));
        let held = keep_open.clone();

        let blackhole = std::thread::spawn(move || {
            if let Ok((socket, _)) = listener.accept() {
                // Hold the socket open without ever answering, then let
                // the listener drop so later connects are refused fast.
                if let Ok(mut slot) = held.lock() {
                    slot.push(socket);
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        let egress = EventEgress::start(
            EventSinkTarget::Webhook {
                url: format!("http://{addr}/ingest"),
                signing_secret: None,
            },
            EventTypeMask::all(),
            64,
        )
        .expect("webhook egress starts");

        // Give the worker a first event so it commits to a POST that will
        // never be answered, then publish while it is wedged.
        egress.publish(event(EventType::PolicyDenied));
        let deadline = Instant::now() + Duration::from_secs(5);
        while accepted.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the stub never accepted, so the worker was not actually wedged"
        );

        let started = Instant::now();
        for _ in 0..64 {
            egress.publish(event(EventType::PolicyDenied));
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(250),
            "publishing while the sink was wedged took {elapsed:?}; the request \
             path is waiting on the sink"
        );

        // Release the blackhole before the drop joins the worker, so the
        // test does not sit out the full HTTP timeout.
        if let Ok(mut slot) = keep_open.lock() {
            slot.clear();
        }
        drop(egress);
        let _ = blackhole.join();
    }

    #[test]
    fn an_unselected_type_is_never_queued() {
        let (tx, rx) = sync_channel::<ProxyEvent>(8);
        let egress = EventEgress::over_channel(
            tx,
            EventTypeMask::from_types(&[EventType::PolicyDenied]),
            "file",
        );

        // `wants` is what `publish_proxy_event` gates on, so an
        // unselected type never reaches `publish` and never costs a
        // payload build.
        assert!(egress.wants(EventType::PolicyDenied));
        assert!(!egress.wants(EventType::CacheHit));

        egress.publish(event(EventType::PolicyDenied));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn publish_proxy_event_does_not_build_when_nothing_is_installed() {
        // The global is set-once and other tests in this binary may have
        // set it, so this asserts the property that holds either way:
        // the closure is never invoked for a type no installed egress
        // selects, and never invoked at all when none is installed.
        let built = AtomicUsize::new(0);
        publish_proxy_event(EventType::ProviderSelected, || {
            built.fetch_add(1, Ordering::SeqCst);
            event(EventType::ProviderSelected)
        });
        let invocations = built.load(Ordering::SeqCst);
        match EGRESS.get() {
            None => assert_eq!(
                invocations, 0,
                "the payload was built with no egress installed"
            ),
            Some(egress) => assert_eq!(
                invocations,
                usize::from(egress.wants(EventType::ProviderSelected)),
                "the payload build did not follow the type filter"
            ),
        }
    }

    // --- WOR-2384: publish_checked / publish_proxy_event_checked ---

    #[test]
    fn publish_checked_succeeds_when_the_queue_has_room() {
        let (tx, rx) = sync_channel::<ProxyEvent>(4);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "file");

        assert!(egress
            .publish_checked(event(EventType::McpGovernanceDecision))
            .is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn publish_checked_reports_queue_full_rather_than_dropping_silently() {
        // Same capacity-1, never-drained setup as
        // `a_full_queue_drops_the_newest_event_and_counts_it`, but this
        // is the call a fail-closed caller actually makes: it needs the
        // `Err` back, not just the counter tick, so it can refuse the
        // request that would otherwise serve un-evidenced.
        let (tx, _rx) = sync_channel::<ProxyEvent>(1);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "file");

        let before = dropped("file", "queue_full");
        assert!(egress
            .publish_checked(event(EventType::McpGovernanceDecision))
            .is_ok());
        let second = egress.publish_checked(event(EventType::McpGovernanceDecision));
        let after = dropped("file", "queue_full");

        assert_eq!(second, Err(EventPublishError::QueueFull));
        assert_eq!(
            after - before,
            1,
            "the overrun attempt must still be counted"
        );
    }

    #[test]
    fn publish_checked_reports_worker_stopped_rather_than_dropping_silently() {
        let (tx, rx) = sync_channel::<ProxyEvent>(4);
        drop(rx);
        let egress = EventEgress::over_channel(tx, EventTypeMask::all(), "webhook");

        let before = dropped("webhook", "worker_stopped");
        let result = egress.publish_checked(event(EventType::McpGovernanceDecision));
        let after = dropped("webhook", "worker_stopped");

        assert_eq!(result, Err(EventPublishError::WorkerStopped));
        assert_eq!(after - before, 1);
    }

    #[test]
    fn publish_proxy_event_checked_reports_no_sink_configured_when_nothing_wants_it() {
        // Same defensive shape as
        // `publish_proxy_event_does_not_build_when_nothing_is_installed`:
        // other tests in this binary may already have set the
        // process-global egress, so this asserts the property that
        // holds either way rather than assuming a fresh process.
        let result = publish_proxy_event_checked(EventType::McpGovernanceDecision, || {
            event(EventType::McpGovernanceDecision)
        });
        match EGRESS.get() {
            None => assert_eq!(result, Err(EventPublishError::NoSinkConfigured)),
            Some(egress) if !egress.wants(EventType::McpGovernanceDecision) => {
                assert_eq!(result, Err(EventPublishError::NoSinkConfigured))
            }
            Some(_) => {
                // Some earlier test in this binary installed an egress
                // that wants this type; either outcome is then a real
                // attempt at that egress's actual queue, not a
                // configuration gap this test is checking for.
            }
        }
    }

    #[test]
    fn event_publish_error_as_str_matches_the_drop_reason_labels() {
        // These are the same strings `record_events_dropped` counts
        // failures under, so a caller formatting one into a log line or
        // an error message stays consistent with the metric.
        assert_eq!(EventPublishError::QueueFull.as_str(), "queue_full");
        assert_eq!(EventPublishError::WorkerStopped.as_str(), "worker_stopped");
        assert_eq!(
            EventPublishError::NoSinkConfigured.as_str(),
            "no_sink_configured"
        );
    }

    #[test]
    fn publish_proxy_event_checked_invocation_and_outcome_match_wants_event() {
        // WOR-2384 addendum: an earlier version of this test re-derived
        // the same `EGRESS.get().is_some_and(|e| e.wants(..))`
        // expression inline and compared it to `wants_event()`, which
        // cannot ever disagree with an identical copy of itself. This
        // drives the real `publish_proxy_event_checked` with a counting
        // closure instead, the same pattern
        // `publish_proxy_event_does_not_build_when_nothing_is_installed`
        // uses, and checks what it actually did against `wants_event`'s
        // independently-computed answer.
        let built = AtomicUsize::new(0);
        let wanted = wants_event(EventType::McpGovernanceDecision);
        let result = publish_proxy_event_checked(EventType::McpGovernanceDecision, || {
            built.fetch_add(1, Ordering::SeqCst);
            event(EventType::McpGovernanceDecision)
        });
        let invoked = built.load(Ordering::SeqCst) == 1;

        assert_eq!(
            invoked, wanted,
            "the build closure ran ({invoked}) but wants_event said {wanted}"
        );
        if !wanted {
            assert_eq!(
                result,
                Err(EventPublishError::NoSinkConfigured),
                "an unwanted type must report NoSinkConfigured rather than attempting delivery"
            );
        }
        // When `wanted` is true, `result` depends on the real queue
        // state of whatever egress another test in this binary
        // installed (`Ok`, `QueueFull`, and `WorkerStopped` are all
        // legitimate outcomes there), so only the not-wanted case has
        // one correct answer to assert on here.
    }
}
