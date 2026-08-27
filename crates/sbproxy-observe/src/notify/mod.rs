//! Outbound webhook subscriptions: many receivers, per-receiver filters,
//! bounded retries, and a durable deadletter queue with replay.
//!
//! # What this is, next to `events:`
//!
//! [`crate::event_sink`] already POSTs typed proxy events to a collector.
//! One collector, one URL in the config file, one attempt per batch, and a
//! failure is counted rather than kept. That is the right shape for a SIEM
//! feed and the wrong shape for telling *customers* something happened,
//! which is what an operator asks for the moment more than one party wants
//! the same events:
//!
//! * More than one destination, each with its own filter, added and removed
//!   at runtime rather than by editing a config file and reloading.
//! * Its own signing key per destination, so revoking one receiver does not
//!   re-key the others.
//! * A retry, because a customer's endpoint restarting is normal.
//! * Somewhere for a delivery that never landed to go, so "we sent it and
//!   you did not get it" has an answer that is not a log search.
//!
//! Both consume the same [`crate::events::ProxyEvent`]. There is no second
//! event vocabulary here, and that is deliberate: a webhook feed with its
//! own event types drifts from the SIEM feed, and then the two disagree
//! about what happened.
//!
//! # The retry schedule, and where it stops
//!
//! The state of the art for webhook delivery is exponential backoff with
//! jitter over days: Svix and Stripe both retry for roughly three days,
//! fifteen to twenty attempts, with a stable event id across every attempt
//! so a receiver can deduplicate, and a deadletter for whatever is left.
//!
//! This takes the first and third of those and deliberately not the second.
//! Attempts are bounded at [`MAX_ATTEMPTS`] over a few seconds, and
//! everything that survives that goes to the deadletter queue, where an
//! operator or a cron replays it. Retrying for three days means holding a
//! delivery for three days, which is a durable outbound spool with its own
//! scheduler, its own backpressure, and its own operational surface, and a
//! proxy is not a queue service. The deadletter queue plus
//! `POST /admin/notifications/deadletters/{id}/replay` is the recoverable
//! version of the same guarantee, with the holding made explicit rather
//! than implicit.
//!
//! The `event_id` is minted once, when the event enters the queue, and is
//! stable across every attempt and across a replay, exactly as Stripe's and
//! Svix's are, so a receiver that stores seen ids can treat a replay as the
//! duplicate it is. It is not a field of [`ProxyEvent`]: the `events:` feed
//! has no retries and therefore no use for one, and widening a documented
//! wire format to serve a second consumer is how two feeds start disagreeing
//! about what an id means. `X-Sbproxy-Delivery-Id` is fresh per attempt,
//! which is what disambiguates one attempt from another.
//!
//! # Backpressure is a drop, and the drop is counted
//!
//! Publishing is a filter test and one `try_send` on a bounded queue.
//! Nothing on the request path waits for a receiver. A full queue discards
//! the incoming event and ticks
//! `sbproxy_notify_deliveries_total{outcome="dropped"}`, matching
//! [`crate::event_sink`]'s posture and for the same reason: a proxy that
//! blocks on a customer's webhook endpoint is a proxy that customer can
//! stall.
//!
//! # What is not here
//!
//! Ordering. Deliveries are attempted concurrently across subscriptions and
//! a retry reorders against a later event, so a receiver that needs a
//! sequence reads the event's own timestamp rather than arrival order.
//!
//! Fan-out to a subscription that did not exist when the event was
//! published. The subscription snapshot is taken at dispatch.

pub mod admin;
mod store;

use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;

use sbproxy_platform::storage::PersistentKv;

use crate::events::ProxyEvent;
use store::{DeadLetter, NotifyStore, Subscription};

pub use store::{SubscriptionView, MAX_DEADLETTERS, MAX_EVENT_TYPE_FILTERS, MAX_URL_BYTES};

/// How many attempts one delivery gets before it is deadlettered.
pub const MAX_ATTEMPTS: u32 = 3;

/// Backoff before attempt two and attempt three. Full jitter is applied on
/// top, so a receiver coming back up is not hit by every pending delivery on
/// the same millisecond.
const BACKOFF: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

/// Per-attempt HTTP timeout.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the bytes read from a receiver's reply. Nothing reads the
/// body; only the status decides. The cap exists because something has to.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Default bound on the hand-off queue.
pub const DEFAULT_QUEUE_CAPACITY: usize = 4_096;

/// The attribution every egress refusal from this subsystem is stamped with.
const NOTIFY_EGRESS_ORIGIN: &str = "notifications";

/// Headers the governed loop strips before any cross-origin replay, on top
/// of the always-sensitive set it applies itself. The signature and its
/// timestamp are one construction: a receiver holding both holds the whole
/// signed statement, and no HTTP client's built-in credential stripping has
/// heard of either.
const SENSITIVE_HEADERS: [&str; 2] = ["x-sbproxy-signature", "x-sbproxy-timestamp"];

/// Anything the notifier refuses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotifyError {
    /// A field was missing or outside its documented range.
    #[error("invalid {field}: {detail}")]
    Invalid {
        /// Which field. A fixed vocabulary, safe as a metric label.
        field: &'static str,
        /// What was wrong with it.
        detail: String,
    },
    /// No subscription or deadletter under that id.
    #[error("no record {0}")]
    NotFound(String),
    /// The embedded store failed.
    #[error("notifier backend: {0}")]
    Backend(String),
}

impl NotifyError {
    /// Stable, low-cardinality label this refusal is counted under.
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "invalid",
            Self::NotFound(_) => "not_found",
            Self::Backend(_) => "error",
        }
    }

    /// HTTP status an admin handler answers this refusal with.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Invalid { .. } => 400,
            Self::NotFound(_) => 404,
            Self::Backend(_) => 500,
        }
    }
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, NotifyError>;

/// What one attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    /// The receiver answered 2xx.
    Delivered {
        /// The status it answered with.
        status: u16,
    },
    /// Something that might work next time: a timeout, a connection
    /// refused, a 429, a 5xx.
    Retryable {
        /// The status, when the receiver answered at all.
        status: Option<u16>,
        /// A closed-vocabulary reason. Never a URL, never a transport
        /// error's Display, both of which carry the destination.
        reason: &'static str,
    },
    /// Something that will not work next time: a 4xx that is not 408 or
    /// 429, or an egress-authorization refusal, which is a decision the
    /// operator made and not a transient fault.
    Permanent {
        /// The status, when the receiver answered at all.
        status: Option<u16>,
        /// A closed-vocabulary reason.
        reason: &'static str,
    },
}

/// How a delivery reaches a receiver.
///
/// A trait so the retry-and-deadletter logic can be driven without a socket.
/// The production implementation is [`GovernedTransport`], which goes
/// through the same bounded, re-authorizing egress loop every other
/// credential-carrying outbound path in this workspace uses.
#[async_trait::async_trait]
pub(crate) trait DeliveryTransport: Send + Sync {
    /// Make one attempt.
    async fn attempt(
        &self,
        url: &str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> AttemptOutcome;
}

/// The typed envelope a receiver gets.
#[derive(Debug, Serialize)]
struct DeliveryEnvelope<'a> {
    source: &'static str,
    version: &'static str,
    subscription_id: &'a str,
    event_id: &'a str,
    event: &'a ProxyEvent,
}

/// One event on its way out, carrying the id every attempt for it shares.
#[derive(Debug, Clone)]
struct QueuedDelivery {
    event_id: String,
    event: ProxyEvent,
}

/// The notifier: a subscription set, a bounded queue, and a worker.
pub struct Notifier {
    tx: Option<SyncSender<QueuedDelivery>>,
    handle: Option<std::thread::JoinHandle<()>>,
    store: Arc<NotifyStore>,
    /// Snapshot the publish path tests filters against without touching the
    /// store, refreshed whenever a subscription changes.
    subscriptions: arc_swap::ArcSwap<Vec<Subscription>>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Notifier")
            .field("subscriptions", &self.subscriptions.load().len())
            .field("running", &self.handle.is_some())
            .finish()
    }
}

impl Notifier {
    /// Open a notifier over a durable store and start its worker.
    pub async fn start(store: Arc<dyn PersistentKv>, queue_capacity: usize) -> Result<Self> {
        Self::start_with_transport(store, queue_capacity, Arc::new(GovernedTransport::new()?)).await
    }

    pub(crate) async fn start_with_transport(
        store: Arc<dyn PersistentKv>,
        queue_capacity: usize,
        transport: Arc<dyn DeliveryTransport>,
    ) -> Result<Self> {
        let store = Arc::new(NotifyStore::new(store)?);
        let loaded = store.list_subscriptions().await?;
        let subscriptions = arc_swap::ArcSwap::from_pointee(loaded);

        let (tx, rx) = sync_channel(queue_capacity.max(1));
        let worker_store = Arc::clone(&store);
        let snapshot = arc_swap::ArcSwap::from(subscriptions.load_full());
        let handle = std::thread::Builder::new()
            .name("sbproxy-notify".to_string())
            .spawn(move || run_worker(rx, worker_store, transport, snapshot))
            .map_err(|error| NotifyError::Backend(format!("notifier worker: {error}")))?;

        let notifier = Self {
            tx: Some(tx),
            handle: Some(handle),
            store,
            subscriptions,
        };
        metrics::set_subscriptions(notifier.subscriptions.load().len() as i64);
        Ok(notifier)
    }

    /// Whether any active subscription selects `event_type`.
    ///
    /// The publish path calls this before building an event, so a proxy with
    /// no subscription pays one atomic load and a filter scan rather than a
    /// serialization.
    pub fn wants(&self, event_type: &str) -> bool {
        self.subscriptions
            .load()
            .iter()
            .any(|subscription| subscription.active && subscription.selects(event_type))
    }

    /// Hand an event to the worker under a fresh event id. Never blocks; a
    /// full queue drops.
    pub fn offer(&self, event: ProxyEvent) {
        self.offer_delivery(QueuedDelivery {
            event_id: store::mint_event_id(),
            event,
        });
    }

    fn offer_delivery(&self, delivery: QueuedDelivery) {
        let Some(tx) = self.tx.as_ref() else {
            metrics::record_delivery("worker_stopped");
            return;
        };
        match tx.try_send(delivery) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => metrics::record_delivery("dropped"),
            Err(TrySendError::Disconnected(_)) => metrics::record_delivery("worker_stopped"),
        }
    }

    async fn reload(&self) -> Result<()> {
        let loaded = self.store.list_subscriptions().await?;
        metrics::set_subscriptions(loaded.len() as i64);
        self.subscriptions.store(Arc::new(loaded));
        Ok(())
    }

    /// Every subscription, credential-free.
    pub async fn list_subscriptions(&self) -> Result<Vec<SubscriptionView>> {
        Ok(self
            .store
            .list_subscriptions()
            .await?
            .iter()
            .map(SubscriptionView::from)
            .collect())
    }

    /// One subscription, credential-free.
    pub async fn get_subscription(&self, id: &str) -> Result<SubscriptionView> {
        Ok(SubscriptionView::from(
            &self.store.get_subscription(id).await?,
        ))
    }

    /// Create a subscription, minting its signing key.
    ///
    /// The secret is returned once, here, and never again: a receiver that
    /// loses it rotates rather than reads it back. Nothing else in this
    /// module hands it to a caller.
    pub async fn create_subscription(
        &self,
        url: String,
        event_types: Vec<String>,
    ) -> Result<(SubscriptionView, String)> {
        store::validate_subscription(&url, &event_types)?;
        let (signing_key_id, signing_secret) = store::mint_signing_key();
        let now = Utc::now();
        let record = Subscription {
            subscription_id: store::mint_subscription_id(),
            url,
            event_types,
            signing_key_id,
            signing_secret: signing_secret.clone(),
            active: true,
            created_at: now,
            updated_at: now,
        };
        self.store.put_subscription(&record).await?;
        self.reload().await?;
        metrics::record_admin("create");
        Ok((SubscriptionView::from(&record), signing_secret))
    }

    /// Replace a subscription's destination, filters, or active flag,
    /// keeping its id and its signing key.
    pub async fn update_subscription(
        &self,
        id: &str,
        url: Option<String>,
        event_types: Option<Vec<String>>,
        active: Option<bool>,
    ) -> Result<SubscriptionView> {
        let mut record = self.store.get_subscription(id).await?;
        if let Some(url) = url {
            record.url = url;
        }
        if let Some(event_types) = event_types {
            record.event_types = event_types;
        }
        if let Some(active) = active {
            record.active = active;
        }
        store::validate_subscription(&record.url, &record.event_types)?;
        record.updated_at = Utc::now();
        self.store.put_subscription(&record).await?;
        self.reload().await?;
        metrics::record_admin("update");
        Ok(SubscriptionView::from(&record))
    }

    /// Mint a fresh signing key for a subscription, returning the new
    /// secret once. The previous secret stops working immediately: a
    /// receiver that verifies signatures needs the new one before the next
    /// delivery, which is why the response carries the new `signing_key_id`
    /// too.
    pub async fn rotate_signing_key(&self, id: &str) -> Result<(SubscriptionView, String)> {
        let mut record = self.store.get_subscription(id).await?;
        let (signing_key_id, signing_secret) = store::mint_signing_key();
        record.signing_key_id = signing_key_id;
        record.signing_secret = signing_secret.clone();
        record.updated_at = Utc::now();
        self.store.put_subscription(&record).await?;
        self.reload().await?;
        metrics::record_admin("rotate");
        Ok((SubscriptionView::from(&record), signing_secret))
    }

    /// Delete a subscription. Its deadletters stay, because they are a
    /// record of what a receiver missed and deleting the subscription does
    /// not un-miss it.
    pub async fn delete_subscription(&self, id: &str) -> Result<()> {
        self.store.delete_subscription(id).await?;
        self.reload().await?;
        metrics::record_admin("delete");
        Ok(())
    }

    /// Every deadlettered delivery, oldest first.
    pub async fn list_deadletters(&self) -> Result<Vec<DeadLetter>> {
        self.store.list_deadletters().await
    }

    /// Re-offer a deadlettered delivery to the worker and drop the record.
    ///
    /// The record goes before the retry rather than after: keeping it until
    /// the replay succeeded means a replay that fails again writes a second
    /// record for the same event, and an operator draining a queue would
    /// watch it refuse to shrink. The re-offered delivery carries the same
    /// `event_id`, so a receiver that already processed it recognizes the
    /// duplicate.
    pub async fn replay(&self, delivery_id: &str) -> Result<String> {
        let record = self.store.get_deadletter(delivery_id).await?;
        let event: ProxyEvent = serde_json::from_value(record.event.clone())
            .map_err(|error| NotifyError::Backend(format!("deadletter is unreadable: {error}")))?;
        self.store.delete_deadletter(delivery_id).await?;
        metrics::set_deadletters(self.store.list_deadletters().await?.len() as i64);
        let event_id = record.event_id.clone();
        self.offer_delivery(QueuedDelivery {
            event_id: event_id.clone(),
            event,
        });
        metrics::record_admin("replay");
        Ok(event_id)
    }

    /// How many subscriptions and deadletters there are, for the console.
    pub async fn summary(&self) -> Result<NotifierSummary> {
        let subscriptions = self.store.list_subscriptions().await?;
        let deadletters = self.store.list_deadletters().await?;
        Ok(NotifierSummary {
            subscriptions: subscriptions.len(),
            active_subscriptions: subscriptions.iter().filter(|s| s.active).count(),
            deadletters: deadletters.len(),
            deadletter_capacity: MAX_DEADLETTERS,
            max_attempts: MAX_ATTEMPTS,
        })
    }
}

impl Drop for Notifier {
    /// Dropping drains: closing the sender ends the worker's receive loop,
    /// and joining waits for the deliveries already in flight. A process
    /// exit does not do this, because the installed notifier lives in a
    /// `OnceLock` and is never dropped; see the module docs on the same
    /// property of `events:`.
    fn drop(&mut self) {
        self.tx = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// What `GET /admin/notifications` answers with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NotifierSummary {
    /// How many subscriptions exist.
    pub subscriptions: usize,
    /// How many of them are active.
    pub active_subscriptions: usize,
    /// How many deliveries are sitting in the deadletter queue.
    pub deadletters: usize,
    /// The cap past which the oldest deadletter is dropped.
    pub deadletter_capacity: usize,
    /// Attempts a delivery gets before it is deadlettered.
    pub max_attempts: u32,
}

/// The process-wide notifier, when one is installed.
static NOTIFIER: OnceLock<Arc<Notifier>> = OnceLock::new();

/// Install the process-wide notifier. The second call is a no-op and
/// reports it, matching every other set-once global in this crate.
pub fn install(notifier: Arc<Notifier>) -> bool {
    NOTIFIER.set(notifier).is_ok()
}

/// The installed notifier, if any.
pub fn installed() -> Option<&'static Arc<Notifier>> {
    NOTIFIER.get()
}

/// Whether the installed notifier has an active subscription for
/// `event_type`. `false` when none is installed.
pub fn wants(event_type: &str) -> bool {
    NOTIFIER
        .get()
        .is_some_and(|notifier| notifier.wants(event_type))
}

/// Offer an event to the installed notifier, if any.
pub fn offer(event: ProxyEvent) {
    if let Some(notifier) = NOTIFIER.get() {
        notifier.offer(event);
    }
}

// --- the worker ---

fn run_worker(
    rx: Receiver<QueuedDelivery>,
    store: Arc<NotifyStore>,
    transport: Arc<dyn DeliveryTransport>,
    subscriptions: arc_swap::ArcSwap<Vec<Subscription>>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        tracing::error!(target: "notify", "notifier runtime would not build; no delivery will happen");
        return;
    };
    while let Ok(delivery) = rx.recv() {
        let event = &delivery.event;
        // Re-read the store rather than trusting the snapshot taken at
        // start: an admin mutation between two events has to take effect on
        // the second one, and the worker owns no channel to hear about it.
        if let Ok(current) = runtime.block_on(store.list_subscriptions()) {
            subscriptions.store(Arc::new(current));
        }
        let matches: Vec<Subscription> = subscriptions
            .load()
            .iter()
            .filter(|s| s.active && s.selects(event.event_type.as_str()))
            .cloned()
            .collect();
        if matches.is_empty() {
            continue;
        }
        runtime.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for subscription in matches {
                let transport = Arc::clone(&transport);
                let store = Arc::clone(&store);
                let delivery = delivery.clone();
                set.spawn(async move {
                    deliver_with_retries(&*transport, &store, &subscription, &delivery).await;
                });
            }
            while set.join_next().await.is_some() {}
        });
    }
}

/// Attempt one delivery up to [`MAX_ATTEMPTS`] times, then deadletter it.
async fn deliver_with_retries(
    transport: &dyn DeliveryTransport,
    store: &NotifyStore,
    subscription: &Subscription,
    delivery: &QueuedDelivery,
) {
    let event = &delivery.event;
    let body = match serde_json::to_vec(&DeliveryEnvelope {
        source: "sbproxy",
        version: env!("CARGO_PKG_VERSION"),
        subscription_id: &subscription.subscription_id,
        event_id: &delivery.event_id,
        event,
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(target: "notify", error = %error, "notification would not serialize");
            metrics::record_delivery("serialize_error");
            return;
        }
    };

    let mut last: AttemptOutcome = AttemptOutcome::Retryable {
        status: None,
        reason: "not_attempted",
    };
    for attempt in 1..=MAX_ATTEMPTS {
        let timestamp = Utc::now().timestamp();
        let mut headers = vec![
            ("Content-Type", "application/json".to_string()),
            (
                "User-Agent",
                concat!("sbproxy/", env!("CARGO_PKG_VERSION")).to_string(),
            ),
            (
                "X-Sbproxy-Event-Type",
                event.event_type.as_str().to_string(),
            ),
            ("X-Sbproxy-Event-Id", delivery.event_id.clone()),
            (
                "X-Sbproxy-Subscription-Id",
                subscription.subscription_id.clone(),
            ),
            ("X-Sbproxy-Delivery-Id", store::mint_delivery_id()),
            ("X-Sbproxy-Attempt", attempt.to_string()),
            ("X-Sbproxy-Timestamp", timestamp.to_string()),
            (
                "X-Sbproxy-Signing-Key-Id",
                subscription.signing_key_id.clone(),
            ),
        ];
        if let Some(signature) = sign(&subscription.signing_secret, &body, timestamp) {
            headers.push(("X-Sbproxy-Signature", signature));
        }

        last = transport
            .attempt(&subscription.url, headers, body.clone())
            .await;
        match &last {
            AttemptOutcome::Delivered { .. } => {
                metrics::record_delivery("delivered");
                return;
            }
            AttemptOutcome::Permanent { reason, .. } => {
                // warn rather than error: a receiver answering 400 is the
                // receiver's problem, and this path is working correctly by
                // not retrying it.
                tracing::warn!(
                    target: "notify",
                    subscription_id = %subscription.subscription_id,
                    event_type = %event.event_type.as_str(),
                    reason = *reason,
                    "notification refused permanently; deadlettering without a retry"
                );
                break;
            }
            AttemptOutcome::Retryable { reason, .. } => {
                metrics::record_delivery("retried");
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(jittered(BACKOFF[(attempt - 1) as usize])).await;
                } else {
                    tracing::warn!(
                        target: "notify",
                        subscription_id = %subscription.subscription_id,
                        event_type = %event.event_type.as_str(),
                        reason = *reason,
                        attempts = attempt,
                        "notification exhausted its attempts; deadlettering"
                    );
                }
            }
        }
    }

    let (status, reason) = match last {
        AttemptOutcome::Delivered { status } => (Some(status), "delivered"),
        AttemptOutcome::Retryable { status, reason }
        | AttemptOutcome::Permanent { status, reason } => (status, reason),
    };
    let record = DeadLetter {
        delivery_id: store::mint_delivery_id(),
        subscription_id: subscription.subscription_id.clone(),
        event_id: delivery.event_id.clone(),
        event_type: event.event_type.as_str().to_string(),
        attempts: MAX_ATTEMPTS,
        last_status: status,
        last_reason: reason.to_string(),
        moved_at: Utc::now(),
        event: serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
    };
    match store.put_deadletter(&record).await {
        Ok(evicted) => {
            metrics::record_delivery("deadlettered");
            if evicted > 0 {
                // The queue is bounded, so a receiver that is down long
                // enough loses its oldest records. Saying so is the whole
                // difference between a lossy queue and a silently lossy one.
                tracing::warn!(
                    target: "notify",
                    evicted,
                    capacity = MAX_DEADLETTERS,
                    "deadletter queue is at capacity; the oldest records were dropped"
                );
                metrics::record_delivery_by("deadletter_evicted", evicted as u64);
            }
            if let Ok(all) = store.list_deadletters().await {
                metrics::set_deadletters(all.len() as i64);
            }
        }
        Err(error) => {
            tracing::error!(
                target: "notify",
                error = %error,
                "could not write a deadletter; the delivery is lost"
            );
            metrics::record_delivery("deadletter_failed");
        }
    }
}

/// Full jitter: a uniform draw over `[0, base]`, which is what keeps a
/// fleet of pending deliveries from hitting a recovering receiver on the
/// same millisecond.
fn jittered(base: Duration) -> Duration {
    use rand::Rng;
    let millis = base.as_millis().min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(rand::thread_rng().gen_range(0..=millis.max(1)))
}

/// HMAC-SHA256 over `<timestamp>.<body>`, the same construction the
/// `events:` webhook sink signs with, so a receiver that already verifies
/// one verifies the other.
fn sign(secret: &str, body: &[u8], timestamp: i64) -> Option<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

/// The production transport: one POST through the governed egress loop.
pub(crate) struct GovernedTransport {
    client: reqwest::Client,
}

impl GovernedTransport {
    fn new() -> Result<Self> {
        // No redirect policy of its own: every hop is decided by
        // `governed_egress`, which re-authorizes the destination. A client
        // that followed a 307 itself would hand the signed envelope to a
        // host the operator never named before that loop saw the Location.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DELIVERY_TIMEOUT)
            .build()
            .map_err(|error| NotifyError::Backend(format!("notifier client: {error}")))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl DeliveryTransport for GovernedTransport {
    async fn attempt(
        &self,
        url: &str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> AttemptOutcome {
        let mut request = self.client.post(url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let request = match request.body(body).build() {
            Ok(request) => request,
            Err(_) => {
                return AttemptOutcome::Permanent {
                    status: None,
                    reason: "request_build_failed",
                }
            }
        };

        let gate = crate::event_sink::webhook_egress_gate();
        let governed = sbproxy_security::governed_egress::GovernedEgress {
            purpose: sbproxy_security::egress::EgressPurpose::Webhook,
            authorizer: gate.as_ref(),
            resolver: &sbproxy_security::egress::CachedSystemResolver,
            origin: NOTIFY_EGRESS_ORIGIN,
            // A subscription is a destination, not a tenant. Folding these
            // refusals into some tenant's series would be worse than saying
            // there is no tenant attribution to give.
            tenant: "unset",
            sensitive_headers: &SENSITIVE_HEADERS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            no_redirect_client: &self.client,
            timeout: DELIVERY_TIMEOUT,
        };

        match governed.send(request).await {
            Ok(response) if (200u16..300).contains(&response.status) => AttemptOutcome::Delivered {
                status: response.status,
            },
            Ok(response)
                if response.status == 408 || response.status == 429 || response.status >= 500 =>
            {
                AttemptOutcome::Retryable {
                    status: Some(response.status),
                    reason: "http_error",
                }
            }
            Ok(response) => AttemptOutcome::Permanent {
                status: Some(response.status),
                reason: "http_rejected",
            },
            Err(sbproxy_security::governed_egress::GovernedEgressError::Denied(_)) => {
                // An allowlist refusal is a decision the operator made. It
                // will refuse identically next time, so retrying it burns
                // the budget that a real transient failure needs.
                AttemptOutcome::Permanent {
                    status: None,
                    reason: "egress_denied",
                }
            }
            Err(error) => AttemptOutcome::Retryable {
                status: None,
                reason: error.as_label(),
            },
        }
    }
}

pub(crate) mod metrics {
    //! The two families the notifier emits.
    //!
    //! `outcome` is a closed set: `delivered`, `retried`, `dropped`,
    //! `deadlettered`, `deadletter_evicted`, `deadletter_failed`,
    //! `serialize_error`, `worker_stopped`. Nothing is labeled by
    //! subscription id or destination: both are operator-supplied and
    //! unbounded, and a per-destination series set grows with the customer
    //! list rather than with the system.

    use std::sync::LazyLock;

    use prometheus::{
        register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec, Opts,
    };

    static NOTIFY_DELIVERIES: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            Opts::new(
                "sbproxy_notify_deliveries_total",
                "Outbound webhook notification deliveries by outcome, plus the admin mutations that manage them"
            ),
            &["outcome"]
        )
        .expect("register sbproxy_notify_deliveries_total")
    });

    static NOTIFY_QUEUE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
        register_int_gauge_vec!(
            Opts::new(
                "sbproxy_notify_queue",
                "Notifier state by collection: configured subscriptions, and deliveries sitting in the deadletter queue"
            ),
            &["collection"]
        )
        .expect("register sbproxy_notify_queue")
    });

    /// Count one delivery outcome.
    pub(crate) fn record_delivery(outcome: &'static str) {
        NOTIFY_DELIVERIES.with_label_values(&[outcome]).inc();
    }

    /// Count several at once, for the eviction sweep.
    pub(crate) fn record_delivery_by(outcome: &'static str, count: u64) {
        NOTIFY_DELIVERIES
            .with_label_values(&[outcome])
            .inc_by(count);
    }

    /// Count one admin mutation, on the same family so one panel covers
    /// "what is this subsystem doing".
    pub(crate) fn record_admin(operation: &'static str) {
        NOTIFY_DELIVERIES.with_label_values(&[operation]).inc();
    }

    /// Publish the subscription count.
    pub(crate) fn set_subscriptions(count: i64) {
        NOTIFY_QUEUE
            .with_label_values(&["subscriptions"])
            .set(count);
    }

    /// Publish the deadletter depth.
    pub(crate) fn set_deadletters(count: i64) {
        NOTIFY_QUEUE.with_label_values(&["deadletters"]).set(count);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Prometheus panics at runtime on a label-arity mismatch, in
        /// whichever request first reaches the new path.
        #[test]
        fn every_recorder_matches_the_declared_label_arity() {
            record_delivery("delivered");
            record_delivery_by("deadletter_evicted", 2);
            record_admin("create");
            set_subscriptions(3);
            set_deadletters(4);
            assert_eq!(NOTIFY_QUEUE.with_label_values(&["subscriptions"]).get(), 3);
        }
    }
}

#[cfg(test)]
mod tests;
