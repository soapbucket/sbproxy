// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Egress for the twenty-two [`crate::events::EventType`] variants: the
//! `events:` block's file and webhook sinks.
//!
//! # The defect this closes
//!
//! [`crate::events::EventBus`] fans out to handler closures **on the
//! publisher's thread**, in registration order, over the subscriber
//! snapshot it takes when `publish` is entered. The handler map is
//! unlocked before the first handler runs, so one slow handler no longer
//! stalls every other publisher, but it still stalls its own. That is
//! fine for a closure that increments a counter and wrong for anything
//! that touches a socket: a handler that POSTs to a SIEM makes the
//! request that trips a policy wait for that SIEM. Nothing crossed the
//! process boundary before this module, so the shape had never been paid
//! for, and shipping a synchronous webhook would have been worse than
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
//! `http_error`, `delivery_failed`, `ssrf_rejected`, and
//! `egress_denied`.
//!
//! # The collector is a governed destination
//!
//! The webhook sink does not dial for itself. It hands its POST to
//! [`sbproxy_security::governed_egress`], the one bounded redirect loop
//! every credential-carrying egress path in this workspace goes
//! through, and so gets three things it did not have before (WOR-2612):
//! the dial is pinned to the addresses the SSRF guard just resolved
//! rather than to a second lookup, the destination is authorized
//! against the `egress:` block's webhook allowlist when the operator
//! has armed one, and a redirect is re-authorized rather than followed.
//!
//! That last one is why this matters at all. The batch carries an
//! HMAC-SHA256 signature over its own body, in a header
//! (`X-Sbproxy-Signature`) that no HTTP client's built-in credential
//! stripping has ever heard of, and a 307 replays a body verbatim. A
//! collector answering `Location: http://169.254.169.254/` used to
//! receive the whole signed envelope. Now the hop is refused, counted
//! under `egress_denied`, and visible in `GET /api/egress`.
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

/// Ceiling on the bytes read from a collector's reply.
///
/// Nothing here reads the reply body; only the status decides whether
/// the batch landed. The cap exists because something has to: a
/// collector that answers a 256-event POST with a gigabyte of prose
/// would otherwise be an unbounded allocation on the delivery thread,
/// and "we never look at it" is not a bound. 64 KiB is far more than
/// any error payload a SIEM sends back and small enough that a wedged
/// one cannot cost memory worth measuring.
const WEBHOOK_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The attribution the webhook sink stamps on every egress refusal and
/// inventory row. Configuration-scoped by construction: there is one
/// `events:` block per process, so this is a constant rather than
/// anything derived from the URL.
const WEBHOOK_EGRESS_ORIGIN: &str = "events";

/// Headers the governed loop must strip before any cross-origin replay,
/// on top of the always-sensitive set it applies itself.
///
/// `X-Sbproxy-Signature` is the whole reason this list is not empty. It
/// is an HMAC over `<timestamp>.<body>` keyed with `signing_secret`, and
/// reqwest's built-in credential stripping knows about `Authorization`,
/// `Cookie`, and `Proxy-Authorization` and nothing else, so a custom
/// signature header rides a redirect untouched. The timestamp goes with
/// it because the two are one construction: a receiver that has the
/// pair has the whole signed statement.
const WEBHOOK_SENSITIVE_HEADERS: [&str; 2] = ["x-sbproxy-signature", "x-sbproxy-timestamp"];

/// Which [`EventType`]s an egress delivers.
///
/// A bitmask rather than a `HashSet` because the test runs on the
/// request path, once per candidate event, before anything is allocated:
/// it has to be cheaper than the event it is deciding not to build.
///
/// `u32` holds the twenty-two bits [`ALL_EVENT_TYPES`] declares with room to
/// spare. A twenty-third variant is caught by that array's fixed length
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
            sbproxy_util::secure_fs::create_dir_all_owner_only(parent).map_err(|error| {
                anyhow::anyhow!(
                    "events.path {}: cannot create the directory {}: {error}",
                    path.display(),
                    parent.display()
                )
            })?;
        }
    }
    // Owner-only. Decision events name the tenant, the rule, and what
    // was refused; a world-readable NDJSON feed on a shared host is a
    // map of the operator's policy surface.
    let file = sbproxy_util::secure_fs::open_append_owner_only(path)
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
    if let Some(allowlist) = ssrf_allowlist() {
        if let Err(reason) = sbproxy_security::ssrf::validate_url_with_allowlist(&url, &allowlist) {
            anyhow::bail!("events.url is refused by the SSRF guard: {reason}");
        }
    }

    // No redirect policy of its own. Every hop this sink is willing to
    // take is decided by `sbproxy_security::governed_egress`, which
    // re-authorizes the destination and refuses to replay a signed body
    // at a host the operator never named; a client that followed a 307
    // on its own would hand the whole signed envelope over before that
    // loop ever saw the `Location`.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .map_err(|error| anyhow::anyhow!("events webhook client: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("events webhook runtime: {error}"))?;

    let handle = std::thread::Builder::new()
        .name("sbproxy-events-webhook".to_string())
        .spawn(move || {
            let mut collector: Option<PinnedCollector> = None;
            loop {
                let batch = drain_batch(&rx);
                if batch.is_empty() {
                    break;
                }
                runtime.block_on(deliver_batch(
                    &mut collector,
                    &client,
                    &url,
                    signing_secret.as_deref(),
                    &batch,
                ));
            }
        })?;
    Ok(handle)
}

/// The collector's client, pinned to the addresses the SSRF guard most
/// recently resolved for it.
///
/// The guard re-resolves the configured URL before every batch, and the
/// dial has to use that exact answer: letting reqwest run its own
/// lookup afterwards is what leaves the rebinding window open, because
/// the address that passed the check and the address that gets
/// connected to are then two different queries. Pinning closes it.
///
/// Cached across batches rather than rebuilt per batch, keyed on the
/// address set itself, so a steady collector keeps one connection pool
/// and its keep-alive instead of paying a fresh TCP and TLS handshake
/// for every POST. A collector that genuinely moves gets a new client
/// on the batch after the move.
struct PinnedCollector {
    addrs: Vec<std::net::SocketAddr>,
    client: reqwest::Client,
}

/// POST one batch. One attempt, no retry; see the module docs.
///
/// Every failure path counts once per event in the batch rather than
/// once per batch, so the metric answers "how many events did my SIEM
/// not get" rather than "how many POSTs failed", which is the question
/// an operator reconciling two systems is actually asking.
///
/// Delivery goes through [`sbproxy_security::governed_egress`] rather
/// than a bare `send()`. Three properties come from that and none of
/// them held before (WOR-2612): the dial is pinned to the addresses the
/// SSRF guard just resolved, so the check and the connect cannot
/// disagree; the destination is authorized against the
/// [`sbproxy_security::egress::EgressPurpose::Webhook`] allowlist when
/// the operator has armed one; and a redirect is re-authorized rather
/// than followed, so a collector answering 307 with a `Location` on the
/// link-local range does not receive the signed envelope.
async fn deliver_batch(
    collector: &mut Option<PinnedCollector>,
    client: &reqwest::Client,
    url: &str,
    signing_secret: Option<&str>,
    batch: &[ProxyEvent],
) {
    let count = batch.len() as u64;

    if let Some(allowlist) = ssrf_allowlist() {
        let target = url.to_string();
        let verdict = tokio::task::spawn_blocking(move || {
            sbproxy_security::ssrf::validate_url_resolved(&target, &allowlist)
        })
        .await;
        match verdict {
            Ok(Ok(resolved)) => {
                if !pin_collector(collector, &resolved) {
                    // No pinned client means no dial. Falling back to
                    // the shared re-resolving client would give back
                    // the pin defense silently, which is worse than
                    // dropping a batch an operator can see on the
                    // counter.
                    tracing::error!(
                        target: "events",
                        reason = "client_build_failed",
                        "events webhook has no pinned client for the collector; batch dropped"
                    );
                    count_batch_drop("webhook", "egress_denied", count);
                    return;
                }
            }
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

    let request = match request.body(body).build() {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(target: "events", error = %error, "events batch request would not build");
            count_batch_drop("webhook", "delivery_failed", count);
            return;
        }
    };

    let gate = webhook_egress_gate();
    let dial = collector.as_ref().map(|pinned| &pinned.client);
    let governed = sbproxy_security::governed_egress::GovernedEgress {
        purpose: sbproxy_security::egress::EgressPurpose::Webhook,
        authorizer: gate.as_ref(),
        resolver: &sbproxy_security::egress::CachedSystemResolver,
        origin: WEBHOOK_EGRESS_ORIGIN,
        // One `events:` block serves the whole process, so there is no
        // per-tenant attribution to give a refusal here. `"unset"` is
        // the documented way to say that rather than folding this
        // sink's refusals into some tenant's series.
        tenant: "unset",
        sensitive_headers: &WEBHOOK_SENSITIVE_HEADERS,
        max_response_bytes: WEBHOOK_MAX_RESPONSE_BYTES,
        no_redirect_client: dial.unwrap_or(client),
        timeout: WEBHOOK_TIMEOUT,
    };

    match governed.send(request).await {
        Ok(response) if (200u16..300).contains(&response.status) => {}
        Ok(response) => {
            tracing::warn!(
                target: "events",
                status = response.status,
                count,
                "events webhook returned non-success; batch dropped"
            );
            count_batch_drop("webhook", "http_error", count);
        }
        Err(sbproxy_security::governed_egress::GovernedEgressError::Denied(reason)) => {
            // The closed reason is already on the warn line, the
            // `sbproxy_egress_refused_total` counter, the `GET
            // /api/egress` row, and the typed `egress_refused` event
            // that `record_egress_refused` publishes. What is left to
            // say here is what it cost this feed, which is the batch.
            tracing::warn!(
                target: "events",
                reason = reason.as_label(),
                count,
                "events webhook destination refused by egress authorization; batch dropped"
            );
            count_batch_drop("webhook", "egress_denied", count);
        }
        Err(error) => {
            // `reason`, a closed label off `GovernedEgressError`, rather
            // than the error's own Display. The governed client returns a
            // bounded enum that never holds a URL, so the webhook's path,
            // which is the credential on Slack-shaped collectors, cannot
            // reach this line by construction rather than by redaction
            // (WOR-2612, WOR-2629).
            tracing::warn!(
                target: "events",
                reason = error.as_label(),
                count,
                "events webhook delivery failed; batch dropped"
            );
            count_batch_drop("webhook", "delivery_failed", count);
        }
    }
}

/// The `Webhook` slot of the process-wide configured-gate registry.
///
/// A named function with a literal purpose in it, rather than the read
/// spelled inline, so the one thing this sink asks the registry for is
/// greppable and testable by name. The registry is an exact-key map:
/// this asks for `Webhook`, and `arm_egress_gates_from_config` in
/// `sbproxy_core::server::lifecycle` is what has to write that key. It
/// did not, for the whole life of the feature, and the answer here was
/// `None` for every config anyone could write (WOR-2612).
pub(crate) fn webhook_egress_gate() -> Option<sbproxy_security::egress::EgressAuthorizer> {
    sbproxy_security::egress::configured_gate(sbproxy_security::egress::EgressPurpose::Webhook)
}

/// Point `collector` at `resolved`'s addresses, rebuilding its client
/// only when the address set actually changed.
///
/// Returns false when the pinned client would not build, which the
/// caller turns into a dropped batch. There is deliberately no
/// unpinned fallback: see the call site.
fn pin_collector(
    collector: &mut Option<PinnedCollector>,
    resolved: &sbproxy_security::ssrf::ResolvedUrl,
) -> bool {
    if resolved.addrs.is_empty() {
        // `validate_url_resolved` returns an empty address set on one
        // branch only: an allowlisted hostname it could not resolve
        // (split-horizon DNS answering at dial time and not before).
        // Production passes an empty allowlist unless
        // `egress.usage_sinks.allow_private` armed hosts, so that
        // branch is rare from here, and the earlier version of this
        // comment described a state the one caller cannot produce.
        // Reaching it anyway means the guard changed shape, and the
        // answer is the same one the rest of this path gives: a batch
        // with nothing to pin to is dropped, not sent through a
        // re-resolving client that would hand back the defense
        // silently.
        *collector = None;
        return false;
    }
    if collector
        .as_ref()
        .is_some_and(|pinned| pinned.addrs == resolved.addrs)
    {
        return true;
    }
    let built = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(WEBHOOK_TIMEOUT)
        .resolve_to_addrs(&resolved.host, &resolved.addrs)
        .build();
    match built {
        Ok(client) => {
            *collector = Some(PinnedCollector {
                addrs: resolved.addrs.clone(),
                client,
            });
            true
        }
        Err(_) => false,
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

/// Process-wide hosts the events webhook SSRF guard exempts from its
/// private-address block.
///
/// Armed from compiled `egress.usage_sinks` when `allow_private` is
/// true (see [`arm_webhook_ssrf_allowlist`]). Empty when that block is
/// absent, unarmed, or `allow_private` is false: the guard still runs
/// and still blocks private addresses. Deny-by-default.
static WEBHOOK_SSRF_ALLOWLIST: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Arm the process-wide events-webhook SSRF host allowlist.
///
/// Called from `arm_egress_gates_from_config` with the hosts compiled
/// from `egress.usage_sinks` when `allow_private` is true, or an empty
/// list otherwise. `start_webhook_worker` reads this list at boot, and
/// `install_event_egress` is set-once, so a SIGHUP cannot newly permit
/// a private collector that was already refused at start. A later
/// reload can still refresh the list for the per-batch check.
pub fn arm_webhook_ssrf_allowlist(hosts: Vec<String>) {
    match WEBHOOK_SSRF_ALLOWLIST.write() {
        Ok(mut slot) => *slot = hosts,
        Err(poisoned) => *poisoned.into_inner() = hosts,
    }
}

/// Hosts currently armed for the events webhook SSRF guard.
fn armed_webhook_ssrf_hosts() -> Vec<String> {
    match WEBHOOK_SSRF_ALLOWLIST.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// The allowlist the SSRF guard runs the collector URL against, or
/// `None` to skip the guard entirely.
///
/// Production answers with the process-wide list armed from
/// `egress.usage_sinks` (empty when that block is absent or
/// `allow_private` is false): the guard runs at boot and again before
/// every batch, and only listed hosts are exempt from its
/// private-address block (WOR-2712).
///
/// Tests point the sink at a loopback stub, which is exactly what the
/// guard exists to refuse, so the test build answers `None` by default.
/// A default rather than a hard-coded skip, because skipping is what
/// left the entire resolve-and-pin path unreachable from the suite:
/// `validate_url_resolved`, `pin_collector`, the pinned dial, and the
/// `client_build_failed` drop all sit inside the block this turns off,
/// and deleting them would have kept every test green. The test
/// module's `SsrfGuard` flips it back on with a host allowlisted, so at
/// least one test drives the real path against a real stub.
#[cfg(not(test))]
fn ssrf_allowlist() -> Option<Vec<String>> {
    Some(armed_webhook_ssrf_hosts())
}

#[cfg(test)]
fn ssrf_allowlist() -> Option<Vec<String>> {
    tests::ssrf_allowlist_override()
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
/// second file that looks like a gap in the first. The webhook
/// destination and the SSRF allowlist `start_webhook_worker` reads at
/// that moment are therefore taken at boot; a SIGHUP cannot newly
/// permit a private collector that was refused at start.
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
    // Two independent consumers, and `build` runs at most once for both.
    // The `events:` egress is one collector with no retries; the notifier
    // (WOR-2669) is many customer-facing subscriptions with retries and a
    // deadletter queue. A proxy with neither configured still pays only two
    // relaxed loads and two bitmask tests here.
    let egress_wants = wants_event(event_type);
    let notifier_wants = crate::notify::wants(event_type.as_str());
    match (egress_wants, notifier_wants) {
        (false, false) => {}
        (true, false) => {
            // `wants_event` returning `true` already proved `EGRESS` is
            // set, and it is a set-once `OnceLock` that never reverts to
            // unset, so this second lookup cannot legitimately miss; the
            // `else` exists only because the compiler cannot see that.
            if let Some(egress) = EGRESS.get() {
                egress.publish(build());
            }
        }
        (false, true) => crate::notify::offer(build()),
        (true, true) => {
            let event = build();
            if let Some(egress) = EGRESS.get() {
                egress.publish(event.clone());
            }
            crate::notify::offer(event);
        }
    }
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
    let egress_wants = wants_event(event_type);
    let notifier_wants = crate::notify::wants(event_type.as_str());
    if !egress_wants && !notifier_wants {
        return Err(EventPublishError::NoSinkConfigured);
    }
    let event = build();
    if notifier_wants {
        crate::notify::offer(event.clone());
    }
    if !egress_wants {
        // The notifier took it, and the notifier is not what
        // `events.fail_closed` is about: that setting names event types a
        // caller would rather refuse a request than lose from the `events:`
        // feed, and a customer-facing webhook subscription is not that
        // feed. Reporting success here would tell a fail-closed caller its
        // SIEM has a record when it does not.
        return Err(EventPublishError::NoSinkConfigured);
    }
    // See `publish_proxy_event`'s matching comment: this cannot
    // legitimately miss once `wants_event` has already said yes.
    let Some(egress) = EGRESS.get() else {
        return Err(EventPublishError::NoSinkConfigured);
    };
    egress.publish_checked(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    /// What [`super::ssrf_allowlist`] answers in the test build.
    ///
    /// `None`, the default, is the historical behavior: skip the guard
    /// so a loopback stub URL is usable at all. [`SsrfGuard`] swaps in
    /// `Some(allowlist)` for the length of one test so the real
    /// resolve-and-pin path runs against that stub instead of being
    /// jumped over.
    static SSRF_ALLOWLIST: std::sync::RwLock<Option<Vec<String>>> = std::sync::RwLock::new(None);

    /// Serializes the tests that flip [`SSRF_ALLOWLIST`]. nextest gives
    /// every test its own process, but the `cargo test` fallback does
    /// not, and a process-wide switch two threads share is exactly the
    /// kind of state that makes a suite pass in one runner and not the
    /// other.
    static SSRF_GUARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(super) fn ssrf_allowlist_override() -> Option<Vec<String>> {
        match SSRF_ALLOWLIST.read() {
            Ok(guard) => guard.as_ref().cloned(),
            Err(poisoned) => poisoned.into_inner().as_ref().cloned(),
        }
    }

    #[test]
    fn arm_webhook_ssrf_allowlist_stores_the_hosts_production_reads() {
        arm_webhook_ssrf_allowlist(vec!["127.0.0.1".to_string()]);
        assert_eq!(
            armed_webhook_ssrf_hosts(),
            vec!["127.0.0.1".to_string()],
            "the process-wide slot is what production ssrf_allowlist() returns"
        );
        arm_webhook_ssrf_allowlist(Vec::new());
        assert!(
            armed_webhook_ssrf_hosts().is_empty(),
            "re-arming empty must restore deny-by-default"
        );
    }

    /// Turns the SSRF guard on, with `hosts` exempt from its
    /// private-address block, until the returned value drops.
    struct SsrfGuard {
        _serialize: std::sync::MutexGuard<'static, ()>,
    }

    impl SsrfGuard {
        fn enforced_for(hosts: &[&str]) -> Self {
            let serialize = match SSRF_GUARD_LOCK.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Ok(mut slot) = SSRF_ALLOWLIST.write() {
                *slot = Some(hosts.iter().map(|host| (*host).to_string()).collect());
            }
            Self {
                _serialize: serialize,
            }
        }
    }

    impl Drop for SsrfGuard {
        fn drop(&mut self) {
            if let Ok(mut slot) = SSRF_ALLOWLIST.write() {
                *slot = None;
            }
        }
    }

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

    /// WOR-2612: a collector that answers 307 with a `Location` at
    /// another origin must not get the signed envelope replayed at that
    /// origin, and the batch must be counted as refused rather than
    /// quietly delivered somewhere else.
    ///
    /// Before the governed loop this test was red twice over: the
    /// webhook client carried reqwest's default `Policy::limited(10)`,
    /// which follows the hop, and reqwest strips only `Authorization`,
    /// `Cookie`, and `Proxy-Authorization` across it, so
    /// `X-Sbproxy-Signature` and the whole event body arrived at the
    /// second stub intact.
    #[test]
    fn a_redirected_batch_never_reaches_the_second_origin() {
        let sink_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        let sink_addr = sink_listener.local_addr().expect("redirect target addr");
        let sink_saw = Arc::new(std::sync::Mutex::new(String::new()));
        let sink_side = sink_saw.clone();
        let sink = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = sink_listener.accept() {
                let request = read_request_and_ack(&mut socket);
                if let Ok(mut slot) = sink_side.lock() {
                    *slot = request;
                }
            }
        });

        let idp_listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let idp_addr = idp_listener.local_addr().expect("collector addr");
        let idp = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = idp_listener.accept() {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let mut scratch = [0u8; 16 * 1024];
                let _ = socket.read(&mut scratch);
                let response = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{sink_addr}/steal\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes());
                let _ = socket.flush();
            }
        });

        let before = dropped("webhook", "egress_denied");
        let egress = EventEgress::start(
            EventSinkTarget::Webhook {
                url: format!("http://{idp_addr}/ingest"),
                signing_secret: Some("shhh".to_string()),
            },
            EventTypeMask::from_types(&[EventType::PolicyDenied]),
            16,
        )
        .expect("webhook egress starts");
        egress.publish(event(EventType::PolicyDenied));
        drop(egress);
        let _ = idp.join();

        let stolen = sink_saw.lock().map(|slot| slot.clone()).unwrap_or_default();
        assert!(
            stolen.is_empty(),
            "the redirect target received the batch: {stolen}"
        );
        assert_eq!(
            dropped("webhook", "egress_denied") - before,
            1,
            "a refused hop must count one drop per event in the batch"
        );

        // Read the assertions off the mutex first, then unblock the
        // redirect target's `accept` so its thread can exit. Joining it
        // before this point would wait for a connection the whole test
        // exists to prove never happens.
        drop(TcpStream::connect(sink_addr));
        let _ = sink.join();
    }

    /// The compiled shape of an armed `usage_sinks:` sub-block: one
    /// allowlist filed under both purposes, the way
    /// `sbproxy_config::compiler::compile_egress_gates` builds it.
    fn usage_sinks_allowlist(host: &str) -> sbproxy_security::egress::EgressAuthorizer {
        usage_sinks_allowlist_with_private(host, false)
    }

    fn usage_sinks_allowlist_with_private(
        host: &str,
        allow_private: bool,
    ) -> sbproxy_security::egress::EgressAuthorizer {
        use sbproxy_security::egress::{
            EgressAuthorizer, EgressConfig, EgressPurpose, PurposeAllowlist,
        };
        use std::collections::{HashMap, HashSet};

        let allowlist = PurposeAllowlist {
            hosts: HashSet::from([host.to_string()]),
            schemes: HashSet::from(["http".to_string(), "https".to_string()]),
            ports: HashSet::from([80u16, 443u16]),
            allow_private,
        };
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::UsageSink, allowlist.clone());
        purposes.insert(EgressPurpose::Webhook, allowlist);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    /// WOR-2612: an operator who arms `egress.usage_sinks` and points
    /// `events.url` somewhere the allowlist does not name gets the batch
    /// refused, not delivered.
    ///
    /// This is the reader half of the blocker. The registry is an
    /// exact-key map: this sink asks it for `EgressPurpose::Webhook`,
    /// nothing ever wrote that key, so `webhook_egress_gate()` answered
    /// `None` for every config, `GovernedEgress::authorize_destination`
    /// took its ungated branch, and the signed batch went to whatever
    /// host `events.url` named without any allowlist, scheme, port, or
    /// private-address rule being consulted. The writer half, that
    /// `arm_egress_gates_from_config` files a compiled `usage_sinks:`
    /// allowlist under `Webhook` as well as `UsageSink`, is pinned by
    /// `every_purpose_the_compiled_egress_section_arms_is_reachable_in_the_registry`
    /// in `sbproxy_core::server::lifecycle`.
    #[test]
    fn an_unlisted_collector_is_refused_and_the_batch_never_leaves() {
        use sbproxy_security::egress::{
            egress_inventory_snapshot, install_configured_gate, EgressPurpose,
        };

        // Same lock `SsrfGuard` holds: this test writes the process-wide
        // `Webhook` gate, and a sibling that clears it mid-delivery
        // would let the stub accept.
        let _serialize = match SSRF_GUARD_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        install_configured_gate(
            EgressPurpose::Webhook,
            Some(usage_sinks_allowlist("collector.internal")),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");
        let reached = Arc::new(AtomicUsize::new(0));
        let reached_side = Arc::clone(&reached);
        let collector = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                reached_side.fetch_add(1, Ordering::SeqCst);
                let _ = read_request_and_ack(&mut socket);
            }
        });

        let before = dropped("webhook", "egress_denied");
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
        // `Drop` closes the channel and joins the delivery thread, so
        // every assertion below runs after the attempt finished.
        drop(egress);

        assert_eq!(
            dropped("webhook", "egress_denied") - before,
            1,
            "a collector the allowlist does not name must count one drop per event"
        );
        assert_eq!(
            reached.load(Ordering::SeqCst),
            0,
            "the unlisted collector accepted a connection, so the batch was sent anyway"
        );

        let row = egress_inventory_snapshot()
            .into_iter()
            .find(|row| {
                row.purpose == "webhook" && row.host == "127.0.0.1" && row.port == addr.port()
            })
            .expect("the refused collector must appear in `GET /api/egress`");
        assert_eq!(row.status, "denied", "{row:?}");
        assert_eq!(row.last_reason, Some("unlisted_host"), "{row:?}");
        assert_eq!(row.origin, "events", "{row:?}");

        install_configured_gate(EgressPurpose::Webhook, None);
        drop(TcpStream::connect(addr));
        let _ = collector.join();
    }

    /// WOR-2612: the dial goes to the addresses the SSRF guard resolved,
    /// not to a lookup the HTTP client runs for itself.
    ///
    /// The pin set names a loopback stub and the URL names a host in the
    /// reserved `.invalid` domain, which no resolver answers for. The
    /// only way this POST can arrive is through the address override
    /// `pin_collector` installed, so the stub receiving it is the pin
    /// doing its job. The `Host` header proves the other half: the
    /// override changes where the connector dials and nothing else, so
    /// TLS SNI and certificate verification still run against the name
    /// the guard checked.
    #[test]
    fn the_dial_goes_to_the_pinned_address_and_not_a_fresh_lookup() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_side = Arc::clone(&seen);
        let stub = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let request = read_request_and_ack(&mut socket);
                if let Ok(mut slot) = seen_side.lock() {
                    *slot = request;
                }
            }
        });

        let resolved = sbproxy_security::ssrf::ResolvedUrl {
            host: "collector.invalid".to_string(),
            port: addr.port(),
            addrs: vec![addr],
            allowlisted: true,
        };
        let mut collector: Option<PinnedCollector> = None;
        assert!(
            pin_collector(&mut collector, &resolved),
            "a resolvable pin set must produce a client"
        );
        let pinned = collector
            .as_ref()
            .expect("a non-empty pin set installs a client");
        assert_eq!(pinned.addrs, vec![addr]);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let sent = runtime.block_on(async {
            pinned
                .client
                .post(format!("http://collector.invalid:{}/ingest", addr.port()))
                .body("{}")
                .send()
                .await
        });
        assert!(
            sent.is_ok(),
            "the pinned client could not reach its pin set: {sent:?}"
        );
        // Join before reading: the stub stores the request it saw after
        // it has already answered, so `send` returning is not proof the
        // string has landed.
        let _ = stub.join();
        let request = seen.lock().map(|slot| slot.clone()).unwrap_or_default();
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: collector.invalid"),
            "the pin must move the dial and leave the Host name alone: {request}"
        );

        // An unchanged address set reuses the client rather than paying
        // a fresh handshake; a set that moved replaces it.
        assert!(pin_collector(&mut collector, &resolved));
        assert_eq!(
            collector.as_ref().map(|pinned| pinned.addrs.clone()),
            Some(vec![addr])
        );
        let moved = sbproxy_security::ssrf::ResolvedUrl {
            addrs: vec![std::net::SocketAddr::from((
                [127, 0, 0, 1],
                addr.port() ^ 1,
            ))],
            ..resolved
        };
        assert!(pin_collector(&mut collector, &moved));
        assert_eq!(
            collector.as_ref().map(|pinned| pinned.addrs.clone()),
            Some(moved.addrs.clone()),
            "a collector that moved must get a client pinned to where it moved to"
        );
    }

    /// WOR-2612: the guard-and-pin block runs on the real delivery path,
    /// not only in the unit test of its parts.
    ///
    /// Every other test in this file leaves the SSRF guard off, because
    /// a loopback stub is exactly what it exists to refuse, and with it
    /// off `deliver_batch` skips `validate_url_resolved`,
    /// `pin_collector`, and the pinned dial entirely: the whole path
    /// could be deleted and the suite would stay green.
    /// [`SsrfGuard`] turns it on with loopback allowlisted, so this one
    /// test drives it end to end and proves the batch went out through
    /// the pinned client the guard's own answer built.
    #[test]
    fn the_real_guard_and_pin_path_delivers_through_the_pinned_client() {
        let _guard = SsrfGuard::enforced_for(&["127.0.0.1"]);
        // This one has to reach the stub, so make sure no sibling test
        // in a shared `cargo test` process left a `Webhook` allowlist
        // armed. nextest gives every test its own process and this is a
        // no-op there.
        sbproxy_security::egress::install_configured_gate(
            sbproxy_security::egress::EgressPurpose::Webhook,
            None,
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_side = Arc::clone(&seen);
        let stub = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let request = read_request_and_ack(&mut socket);
                if let Ok(mut slot) = seen_side.lock() {
                    *slot = request;
                }
            }
        });

        let shared = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(WEBHOOK_TIMEOUT)
            .build()
            .expect("shared client");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut collector: Option<PinnedCollector> = None;
        let before = dropped("webhook", "egress_denied") + dropped("webhook", "ssrf_rejected");
        runtime.block_on(deliver_batch(
            &mut collector,
            &shared,
            &format!("http://{addr}/ingest"),
            Some("shhh"),
            &[event(EventType::PolicyDenied)],
        ));

        assert_eq!(
            dropped("webhook", "egress_denied") + dropped("webhook", "ssrf_rejected"),
            before,
            "the guard refused a batch it was supposed to pass"
        );
        assert_eq!(
            collector.as_ref().map(|pinned| pinned.addrs.clone()),
            Some(vec![addr]),
            "the guard's own answer must be what the dial is pinned to"
        );
        // Join before reading: the stub stores what it saw only after
        // it has answered, so `deliver_batch` returning is not proof
        // the string has landed.
        let _ = stub.join();
        let request = seen.lock().map(|slot| slot.clone()).unwrap_or_default();
        // Lowercased, like `webhook_sink_posts_a_signed_batch` above:
        // hyper writes `HeaderName::as_str()`, which is the canonical
        // lowercase form, so the `X-Sbproxy-Signature` this code spells
        // in title case never appears that way on the wire. Matching on
        // the value as well as the name, so an empty or malformed header
        // cannot read as a signed batch.
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-sbproxy-signature: v1="),
            "the signed batch never arrived: {request}"
        );
    }

    #[test]
    fn usage_sinks_allow_private_listed_host_lets_loopback_webhook_start_and_deliver() {
        // WOR-2712: `allow_private` plus a listed host must reach the
        // SSRF guard, not only the later governed-egress authorizer.
        // Derive the exemption list from a compiled usage_sinks
        // authorizer the way boot does, then drive the existing stub
        // path with that list armed.
        use sbproxy_security::egress::EgressPurpose;

        let authorizer = usage_sinks_allowlist_with_private("127.0.0.1", true);
        let hosts = authorizer.ssrf_private_hosts(EgressPurpose::Webhook);
        assert_eq!(
            hosts,
            vec!["127.0.0.1".to_string()],
            "allow_private must put the listed host on the SSRF allowlist"
        );
        let host_refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let _guard = SsrfGuard::enforced_for(&host_refs);
        // SsrfGuard already serializes against other tests that write
        // the Webhook gate. Clear a sibling's deny_by_default so the
        // stub's ephemeral port is not refused after the SSRF check.
        sbproxy_security::egress::install_configured_gate(
            sbproxy_security::egress::EgressPurpose::Webhook,
            None,
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_side = Arc::clone(&seen);
        let stub = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let request = read_request_and_ack(&mut socket);
                if let Ok(mut slot) = seen_side.lock() {
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
        .expect("loopback collector on an allow_private usage_sinks host must start");
        egress.publish(event(EventType::PolicyDenied));
        drop(egress);
        let _ = stub.join();
        let request = seen.lock().map(|slot| slot.clone()).unwrap_or_default();
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-sbproxy-signature: v1="),
            "the signed batch never arrived: {request}"
        );
    }

    #[test]
    fn loopback_webhook_is_refused_when_usage_sinks_does_not_permit_private() {
        // Inverse of the start-and-deliver test above. Do not flip the
        // process-wide `SsrfGuard` to an empty list here: that override
        // is shared with every other test in a `cargo test` process, and
        // an empty allowlist would refuse sibling loopback stubs that
        // still expect the default skip. The boot-time refusal with the
        // `SSRF guard` message is pinned by the lifecycle tests that
        // compile observe as a non-test crate. This test pins the
        // derivation and the guard's own verdict on that empty list.
        use sbproxy_security::egress::EgressPurpose;

        let authorizer = usage_sinks_allowlist("127.0.0.1");
        let hosts = authorizer.ssrf_private_hosts(EgressPurpose::Webhook);
        assert!(
            hosts.is_empty(),
            "allow_private false must not exempt any host"
        );
        assert!(
            sbproxy_security::egress::EgressAuthorizer::new(Default::default())
                .ssrf_private_hosts(EgressPurpose::Webhook)
                .is_empty(),
            "an absent usage_sinks authorizer must not exempt any host"
        );
        let error = sbproxy_security::ssrf::validate_url_with_allowlist(
            "http://127.0.0.1:9/ingest",
            &hosts,
        )
        .expect_err("an empty SSRF allowlist must refuse loopback");
        assert!(
            error.contains("private") || error.contains("blocked"),
            "the guard must name the private-address block: {error}"
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

    /// WOR-2626: a decision event names the tenant, the rule, and what
    /// was refused, so the NDJSON feed and the directory the sink
    /// creates for it are owner-only.
    ///
    /// The file is pre-created world-readable between the two starts
    /// rather than left to the ambient umask, so this is red before the
    /// fix whatever the runner's umask is.
    ///
    /// What that covers is the *file* assertion, and only that one. The
    /// directory assertion below is umask-dependent and cannot be made
    /// otherwise from inside this crate: a directory has nowhere to put
    /// a starting mode, because the mode it is *created* at is the
    /// claim, and with the fix backed out `create_dir_all` under a
    /// `0o077` umask produces `0o700` and the assertion passes green.
    /// Pinning the umask needs `libc::umask`, which this crate's
    /// `#![forbid(unsafe_code)]` refuses, so that half is proved in
    /// `tests/durable_directory_modes.rs`, an integration test that is
    /// its own crate and pins it.
    #[cfg(unix)]
    #[test]
    fn the_event_file_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        fn mode_of(path: &std::path::Path) -> u32 {
            std::fs::metadata(path)
                .expect("stat the path under test")
                .permissions()
                .mode()
                & 0o7777
        }

        let dir = tempfile::tempdir().expect("temp dir");
        let nested = dir.path().join("nested");
        let path = nested.join("events.ndjson");

        let egress = EventEgress::start(
            EventSinkTarget::File { path: path.clone() },
            EventTypeMask::all(),
            16,
        )
        .expect("file egress starts");
        drop(egress);
        assert_eq!(
            mode_of(&nested),
            0o700,
            "the sink's own directory is world-traversable"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen the event file");
        let egress = EventEgress::start(
            EventSinkTarget::File { path: path.clone() },
            EventTypeMask::all(),
            16,
        )
        .expect("file egress restarts");
        egress.publish(event(EventType::PolicyDenied));
        drop(egress);

        assert_eq!(
            mode_of(&path),
            0o600,
            "the event file is {:o}, not owner-only",
            mode_of(&path)
        );
        assert!(
            std::fs::read_to_string(&path)
                .expect("read back")
                .contains("policy_denied"),
            "tightening must not cost the records"
        );
    }
}
