//! Durable state for the notifier: the subscriptions, and the deliveries
//! that ran out of attempts.
//!
//! Both live in namespaces of the shared embedded store
//! ([`sbproxy_platform::storage::PersistentKv`]), which is what makes them
//! survive a restart without adding a database to the deployment. The
//! reference implementation this replaces kept them in Postgres, behind a
//! feature that had to be on for the subscription CRUD to exist at all.
//!
//! # The signing secret is stored, and that is a decision
//!
//! A subscription's HMAC secret has to be readable at delivery time, so
//! unlike an inbound API key it cannot be stored as a one-way hash. It sits
//! in the record. What follows from that is the store file's mode: it is
//! created owner-only in the `open(2)` call, and it belongs on the same
//! volume an operator already trusts with the config that holds the rest of
//! their secrets. [`SubscriptionView`] is what every read path returns and
//! has no field the secret could occupy, so an admin listing cannot leak one
//! by forgetting to strip it.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use sbproxy_platform::storage::{KvNamespace, PersistentKv};

use super::{NotifyError, Result};

/// Namespace holding one JSON record per subscription.
const SUBSCRIPTIONS: &str = "notify_subscriptions";
/// Namespace holding one JSON record per deadlettered delivery.
const DEADLETTERS: &str = "notify_deadletters";

/// Longest destination URL a subscription may carry.
pub const MAX_URL_BYTES: usize = 2_048;

/// Most event-type filters one subscription may name.
pub const MAX_EVENT_TYPE_FILTERS: usize = 32;

/// Ceiling on stored deadletters.
///
/// A deadletter queue with no bound is a disk-exhaustion primitive driven by
/// a receiver that is down: every event for every subscription lands in it
/// until the volume fills. Past the cap the oldest record is dropped and the
/// drop is counted, which is the lossy-but-visible answer rather than the
/// silently-lossy one.
pub const MAX_DEADLETTERS: usize = 10_000;

/// A stored subscription. Never returned to a caller: see
/// [`SubscriptionView`].
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Subscription {
    pub(super) subscription_id: String,
    pub(super) url: String,
    pub(super) event_types: Vec<String>,
    pub(super) signing_key_id: String,
    pub(super) signing_secret: String,
    pub(super) active: bool,
    /// Whether this subscription may name a wildcard that reaches the
    /// per-request lifecycle events. Defaults to false, including for
    /// records written before the field existed.
    #[serde(default)]
    pub(super) allow_firehose: bool,
    pub(super) created_at: DateTime<Utc>,
    pub(super) updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subscription")
            .field("subscription_id", &self.subscription_id)
            .field("url", &self.url)
            .field("event_types", &self.event_types)
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_secret", &"<redacted>")
            .field("active", &self.active)
            .field("allow_firehose", &self.allow_firehose)
            .finish()
    }
}

impl Subscription {
    /// Whether this subscription asked for `event_type`.
    ///
    /// `*` selects everything, and is refused at validation unless the
    /// subscription set `allow_firehose`. A filter ending in `_*` selects a
    /// family (`key_*`). Anything else is an exact match, so a typo selects
    /// nothing rather than everything, which is the safe direction for a
    /// filter that decides what leaves the network.
    ///
    /// The family form keeps its `_` in the prefix on purpose. The event
    /// vocabulary is `key_minted`, `key_revoked`, `request_completed` and so
    /// on, with `_` as the separator, so `key_*` has to mean "the `key`
    /// family" and not "anything starting with the letters k-e-y". An
    /// unanchored prefix would quietly hand a customer subscribed to
    /// `key_*` a future `keyless_auth_denied`, with no config change on
    /// either side.
    pub(super) fn selects(&self, event_type: &str) -> bool {
        self.event_types.iter().any(|filter| {
            if filter == "*" {
                return true;
            }
            match filter.strip_suffix('*') {
                // The prefix still carries the trailing `_`, so the match
                // is anchored on the separator.
                Some(prefix) => event_type.starts_with(prefix),
                None => filter == event_type,
            }
        })
    }
}

/// The event types published once per terminating request.
///
/// A webhook per request is not a shape this worker can serve: one
/// subscription at 500 rps needs 500 HTTP POSTs a second, and the delivery
/// budget alone is three attempts across up to fifteen seconds. Selecting
/// one of these is a deliberate act, so a wildcard cannot reach them by
/// accident. See [`validate_subscription`].
pub const PER_REQUEST_EVENT_TYPES: [&str; 3] =
    ["request_started", "request_completed", "request_error"];

/// What every read path returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SubscriptionView {
    /// Stable identifier, minted at creation.
    pub subscription_id: String,
    /// Destination the notifier POSTs to.
    pub url: String,
    /// Event-type filters this subscription selected.
    pub event_types: Vec<String>,
    /// Identifier of the signing key, so a receiver rotating a secret can
    /// tell which one signed a delivery. Never the secret itself.
    pub signing_key_id: String,
    /// Whether the notifier delivers to it. An inactive subscription is
    /// kept, not deleted, so a paused receiver keeps its filters and its id.
    pub active: bool,
    /// Whether this subscription was allowed to name a wildcard that
    /// reaches the per-request lifecycle events.
    pub allow_firehose: bool,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it last changed.
    pub updated_at: DateTime<Utc>,
}

impl From<&Subscription> for SubscriptionView {
    fn from(record: &Subscription) -> Self {
        Self {
            subscription_id: record.subscription_id.clone(),
            url: record.url.clone(),
            event_types: record.event_types.clone(),
            signing_key_id: record.signing_key_id.clone(),
            active: record.active,
            allow_firehose: record.allow_firehose,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

/// A delivery that ran out of attempts, kept so an operator can see what
/// their receiver missed and replay it once the receiver is healthy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeadLetter {
    /// Per-record identifier, and the handle the replay route takes.
    pub delivery_id: String,
    /// Which subscription the delivery was for.
    pub subscription_id: String,
    /// The event's stable id, unchanged across every attempt, so a receiver
    /// that already processed it can recognize the replay as a duplicate.
    pub event_id: String,
    /// The event's type.
    pub event_type: String,
    /// How many attempts were made before this record was written.
    pub attempts: u32,
    /// The last HTTP status, when the receiver answered at all.
    pub last_status: Option<u16>,
    /// A bounded, closed-vocabulary reason for the last failure. Never a
    /// URL and never a transport error's own Display, both of which carry
    /// the destination.
    pub last_reason: String,
    /// When the record was written.
    pub moved_at: DateTime<Utc>,
    /// The event body, so a replay sends what was originally meant.
    pub event: serde_json::Value,
}

/// One deadletter without its event body, for the paged listing.
///
/// The body is the largest part of the record and the listing has no use
/// for it: an operator triaging the queue reads the type, the reason, and
/// the age, and the single-record route serves the body of the one they
/// open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeadLetterSummary {
    /// Per-record identifier, and the handle the replay route takes.
    pub delivery_id: String,
    /// Which subscription the delivery was for.
    pub subscription_id: String,
    /// The event's stable id, unchanged across every attempt.
    pub event_id: String,
    /// The event's type.
    pub event_type: String,
    /// How many attempts were made before this record was written.
    pub attempts: u32,
    /// The last HTTP status, when the receiver answered at all.
    pub last_status: Option<u16>,
    /// A bounded, closed-vocabulary reason for the last failure.
    pub last_reason: String,
    /// When the record was written.
    pub moved_at: DateTime<Utc>,
}

impl From<&DeadLetter> for DeadLetterSummary {
    fn from(record: &DeadLetter) -> Self {
        Self {
            delivery_id: record.delivery_id.clone(),
            subscription_id: record.subscription_id.clone(),
            event_id: record.event_id.clone(),
            event_type: record.event_type.clone(),
            attempts: record.attempts,
            last_status: record.last_status,
            last_reason: record.last_reason.clone(),
            moved_at: record.moved_at,
        }
    }
}

/// Subscriptions and deadletters over one embedded store.
pub(super) struct NotifyStore {
    store: Arc<dyn PersistentKv>,
    subscriptions: KvNamespace,
    deadletters: KvNamespace,
    /// Delivery ids in the order they were written, oldest first.
    ///
    /// Deciding whether to evict used to mean listing and JSON-parsing
    /// every stored deadletter, each carrying a full event body, on every
    /// write, and the caller then listed them a second time to set the
    /// gauge. Near the 10,000 cap that is two full-table reads and 20,000
    /// parses per deadlettered delivery, on the one thread every other
    /// subscription's delivery is queued behind. This is the same
    /// information as a list of keys, seeded once at open.
    ///
    /// Delivery ids are `dlv_<ULID>`, and ULIDs sort lexicographically by
    /// mint time, so the store's own key order is already oldest-first and
    /// the seed does not have to parse a record to get it right.
    order: parking_lot::Mutex<std::collections::VecDeque<String>>,
    /// Bound on [`Self::order`], injectable so the eviction arithmetic and
    /// the drop path are testable without writing ten thousand records.
    capacity: usize,
}

impl NotifyStore {
    pub(super) async fn open_with_capacity(
        store: Arc<dyn PersistentKv>,
        capacity: usize,
    ) -> Result<Self> {
        let namespace = |name: &str| {
            KvNamespace::new(name).map_err(|error| NotifyError::Backend(error.to_string()))
        };
        let deadletters = namespace(DEADLETTERS)?;
        let mut keys: Vec<String> = store
            .list(&deadletters)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        keys.sort();
        Ok(Self {
            store,
            subscriptions: namespace(SUBSCRIPTIONS)?,
            deadletters,
            order: parking_lot::Mutex::new(keys.into()),
            capacity: capacity.max(1),
        })
    }

    /// How many deadletters are stored, without reading the store.
    pub(super) fn deadletter_count(&self) -> usize {
        self.order.lock().len()
    }

    /// The cap past which the oldest deadletter is dropped.
    pub(super) fn deadletter_capacity(&self) -> usize {
        self.capacity
    }

    /// Every subscription, in id order.
    pub(super) async fn list_subscriptions(&self) -> Result<Vec<Subscription>> {
        let stored = self
            .store
            .list(&self.subscriptions)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?;
        let mut out = Vec::with_capacity(stored.len());
        for (_, entry) in stored {
            out.push(serde_json::from_slice(&entry.value).map_err(|error| {
                NotifyError::Backend(format!("stored subscription is unreadable: {error}"))
            })?);
        }
        Ok(out)
    }

    pub(super) async fn get_subscription(&self, id: &str) -> Result<Subscription> {
        let entry = self
            .store
            .get(&self.subscriptions, id)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?
            .ok_or_else(|| NotifyError::NotFound(id.to_string()))?;
        serde_json::from_slice(&entry.value).map_err(|error| {
            NotifyError::Backend(format!("stored subscription is unreadable: {error}"))
        })
    }

    pub(super) async fn put_subscription(&self, record: &Subscription) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            NotifyError::Backend(format!("could not encode subscription: {error}"))
        })?;
        self.store
            .put(&self.subscriptions, &record.subscription_id, &bytes)
            .await
            .map(|_| ())
            .map_err(|error| NotifyError::Backend(error.to_string()))
    }

    pub(super) async fn delete_subscription(&self, id: &str) -> Result<()> {
        // Read first, so deleting an id that never existed is a 404 rather
        // than a silent success an operator reads as "it is gone now".
        self.get_subscription(id).await?;
        self.store
            .delete(&self.subscriptions, id)
            .await
            .map(|_| ())
            .map_err(|error| NotifyError::Backend(error.to_string()))
    }

    pub(super) async fn get_deadletter(&self, delivery_id: &str) -> Result<DeadLetter> {
        let entry = self
            .store
            .get(&self.deadletters, delivery_id)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?
            .ok_or_else(|| NotifyError::NotFound(delivery_id.to_string()))?;
        serde_json::from_slice(&entry.value).map_err(|error| {
            NotifyError::Backend(format!("stored deadletter is unreadable: {error}"))
        })
    }

    /// Write a deadletter, evicting the oldest record when the queue is at
    /// its cap. Returns how many records were evicted to make room.
    pub(super) async fn put_deadletter(&self, record: &DeadLetter) -> Result<usize> {
        // Chosen before the write, from the in-memory order, so the cost
        // of one deadletter is one delete per evicted record plus one put
        // rather than a full-table read and parse.
        let stale: Vec<String> = {
            let order = self.order.lock();
            // `>=` rather than `>`: the write below adds one, so a queue
            // already at the cap has to give up a record before it lands.
            order
                .iter()
                .take(order.len().saturating_sub(self.capacity - 1))
                .cloned()
                .collect()
        };
        let mut evicted = 0;
        for delivery_id in &stale {
            self.store
                .delete(&self.deadletters, delivery_id)
                .await
                .map_err(|error| NotifyError::Backend(error.to_string()))?;
            evicted += 1;
        }
        let bytes = serde_json::to_vec(record).map_err(|error| {
            NotifyError::Backend(format!("could not encode deadletter: {error}"))
        })?;
        self.store
            .put(&self.deadletters, &record.delivery_id, &bytes)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?;
        {
            let mut order = self.order.lock();
            for delivery_id in &stale {
                order.retain(|id| id != delivery_id);
            }
            order.push_back(record.delivery_id.clone());
        }
        Ok(evicted)
    }

    /// One page of deadletters, oldest first, without their event bodies.
    ///
    /// Paged because the whole queue is up to [`MAX_DEADLETTERS`] records
    /// each carrying a request-envelope-sized event, and the console
    /// fetches this on mount and after every action. The bodies are not in
    /// the summary for the same reason: a replay does not need them at the
    /// caller, and the single-record route serves the one an operator is
    /// actually looking at.
    pub(super) async fn page_deadletters(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<DeadLetterSummary>, Option<String>)> {
        let page: Vec<String> = {
            let order = self.order.lock();
            order
                .iter()
                .skip_while(|id| after.is_some_and(|cursor| id.as_str() <= cursor))
                .take(limit + 1)
                .cloned()
                .collect()
        };
        let more = page.len() > limit;
        let mut out = Vec::with_capacity(page.len().min(limit));
        for delivery_id in page.iter().take(limit) {
            // A record the order knows about but the store does not is a
            // concurrent delete, not an error worth failing a listing over.
            if let Ok(record) = self.get_deadletter(delivery_id).await {
                out.push(DeadLetterSummary::from(&record));
            }
        }
        let cursor = more.then(|| out.last().map(|last| last.delivery_id.clone()));
        Ok((out, cursor.flatten()))
    }

    pub(super) async fn delete_deadletter(&self, delivery_id: &str) -> Result<()> {
        self.store
            .delete(&self.deadletters, delivery_id)
            .await
            .map(|_| ())
            .map_err(|error| NotifyError::Backend(error.to_string()))?;
        self.order.lock().retain(|id| id != delivery_id);
        Ok(())
    }
}

/// Mint a subscription id.
pub(super) fn mint_subscription_id() -> String {
    format!("sub_{}", Ulid::new())
}

/// Mint a delivery id. Fresh per attempt and per deadletter record, unlike
/// the event id, which is stable across every attempt and every replay.
pub(super) fn mint_delivery_id() -> String {
    format!("dlv_{}", Ulid::new())
}

/// Mint the event id every attempt for one queued event shares.
pub(super) fn mint_event_id() -> String {
    format!("evt_{}", Ulid::new())
}

/// Mint a signing key id and a signing secret.
///
/// The secret is 32 bytes of `OsRng` hex, which is what an HMAC-SHA256 key
/// wants: the receiver's verifier takes the same bytes, so there is no
/// asymmetric key to distribute and no JWKS endpoint to stand up.
pub(super) fn mint_signing_key() -> (String, String) {
    use rand::RngCore;
    let mut buffer = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buffer);
    (format!("k_{}", Ulid::new()), hex::encode(buffer))
}

/// Validate a destination and a filter list before anything is stored.
///
/// `allow_firehose` is the switch on two refusals rather than one setting:
/// a wildcard that reaches the per-request lifecycle events is a webhook
/// per request, which this worker cannot serve, so it is refused unless the
/// operator said so in the same call.
pub(super) fn validate_subscription(
    url: &str,
    event_types: &[String],
    allow_firehose: bool,
) -> Result<()> {
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(NotifyError::Invalid {
            field: "url",
            detail: format!("must be 1..={MAX_URL_BYTES} bytes, got {}", url.len()),
        });
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(NotifyError::Invalid {
            field: "url",
            detail: "must be an http:// or https:// URL".into(),
        });
    }
    if event_types.is_empty() || event_types.len() > MAX_EVENT_TYPE_FILTERS {
        return Err(NotifyError::Invalid {
            field: "event_types",
            detail: format!("must name 1..={MAX_EVENT_TYPE_FILTERS} filters"),
        });
    }
    for filter in event_types {
        if filter == "*" {
            if !allow_firehose {
                return Err(NotifyError::Invalid {
                    field: "event_types",
                    detail: "\"*\" selects the per-request lifecycle events too, which is one                              webhook delivery per request; name the events you want, or set                              allow_firehose: true to say you meant it"
                        .into(),
                });
            }
            continue;
        }
        let candidate = filter.strip_suffix('*').unwrap_or(filter);
        if candidate.is_empty()
            || !candidate
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(NotifyError::Invalid {
                field: "event_types",
                detail: format!(
                    "{:?} is not an event name, a family prefix like key_*, or *",
                    filter
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(64)
                        .collect::<String>()
                ),
            });
        }
        // A family prefix that would sweep in a per-request lifecycle
        // event is the same firehose `*` is, just spelled differently.
        // Naming one of the three exactly is not: that is the operator
        // picking it, and the set is bounded by what they typed.
        if filter.ends_with('*')
            && !allow_firehose
            && PER_REQUEST_EVENT_TYPES
                .iter()
                .any(|event| event.starts_with(candidate))
        {
            return Err(NotifyError::Invalid {
                field: "event_types",
                detail: format!(
                    "{candidate:?}* selects a per-request lifecycle event, which is one                      webhook delivery per request; name the events you want, or set                      allow_firehose: true to say you meant it"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    fn subscription(filters: &[&str]) -> Subscription {
        Subscription {
            subscription_id: "sub_1".into(),
            url: "https://receiver.example.com/hook".into(),
            event_types: filters.iter().map(|f| (*f).to_string()).collect(),
            signing_key_id: "k_1".into(),
            signing_secret: "secret".into(),
            active: true,
            allow_firehose: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}/sbproxy_notify_store_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn deadletter(n: usize) -> DeadLetter {
        DeadLetter {
            delivery_id: format!("dlv_{n:04}"),
            subscription_id: "sub_1".into(),
            event_id: format!("evt_{n:04}"),
            event_type: "key_minted".into(),
            attempts: 3,
            last_status: Some(500),
            last_reason: "http_error".into(),
            moved_at: Utc::now(),
            event: serde_json::json!({"filler": "x".repeat(64)}),
        }
    }

    /// A filter that decides what leaves the network has to fail closed on
    /// a typo. `key_mintedd` selects nothing, not everything.
    #[test]
    fn a_filter_matches_exactly_a_family_or_everything() {
        let all = subscription(&["*"]);
        assert!(all.selects("key_minted"));
        assert!(all.selects("anything_at_all"));

        let family = subscription(&["key_"]);
        assert!(
            !family.selects("key_minted"),
            "a bare prefix is not a family"
        );

        let exact = subscription(&["key_minted", "key_revoked"]);
        assert!(exact.selects("key_minted"));
        assert!(!exact.selects("key_rotated"));
        assert!(!subscription(&["key_mintedd"]).selects("key_minted"));
    }

    /// The vocabulary is `key_minted`, `key_revoked`, and so on: nothing
    /// in it contains a dot. The family form therefore has to anchor on
    /// `_`, or a customer subscribed to the key family starts receiving a
    /// future `keyless_auth_denied` with no config change on either side.
    #[test]
    fn a_wildcard_family_anchors_on_the_event_name_separator() {
        let family = subscription(&["key_*"]);
        assert!(family.selects("key_minted"));
        assert!(family.selects("key_revoked"));
        assert!(!family.selects("policy_denied"));
        assert!(
            !family.selects("keyless_auth_denied"),
            "an unanchored prefix would hand this to the key family"
        );
    }

    #[test]
    fn the_debug_impl_never_prints_the_signing_secret() {
        let rendered = format!("{:?}", subscription(&["*"]));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret\""));
    }

    #[test]
    fn validation_refuses_the_shapes_the_docs_forbid() {
        assert!(validate_subscription("https://a.example/h", &["*".into()], true).is_ok());
        assert!(validate_subscription("ftp://a.example/h", &["*".into()], true).is_err());
        assert!(validate_subscription("https://a.example/h", &[], true).is_err());
        assert!(validate_subscription("", &["*".into()], true).is_err());
        assert!(
            validate_subscription("https://a.example/h", &["Key Minted".into()], false).is_err()
        );
        // A control character in a filter cannot forge a line in the error.
        let refusal = validate_subscription("https://a.example/h", &["a\nb".into()], false)
            .expect_err("control characters are refused");
        assert!(!refusal.to_string().contains('\n'));
    }

    /// The console shipped this form pre-filled with `*`, so the shortest
    /// path through the page was: paste a URL, click subscribe, and receive
    /// one webhook delivery per proxied request from a worker that cannot
    /// serve them. A wildcard now has to be said out loud.
    #[test]
    fn a_wildcard_reaching_the_per_request_events_needs_the_operator_to_say_so() {
        let refusal = validate_subscription("https://a.example/h", &["*".into()], false)
            .expect_err("a bare wildcard is a firehose");
        assert!(refusal.to_string().contains("allow_firehose"), "{refusal}");

        // Spelled as a family rather than as `*`, and refused the same way.
        assert!(
            validate_subscription("https://a.example/h", &["request_*".into()], false).is_err()
        );
        assert!(validate_subscription("https://a.example/h", &["request_*".into()], true).is_ok());

        // A family that reaches none of them is unaffected.
        assert!(validate_subscription("https://a.example/h", &["key_*".into()], false).is_ok());

        // And naming one exactly is the operator picking it, which is the
        // case the flag is not for.
        assert!(
            validate_subscription("https://a.example/h", &["request_error".into()], false).is_ok()
        );
    }

    /// Neither loss path had a test: the eviction arithmetic that drops the
    /// oldest record at the cap, and the count the gauge and the summary
    /// both read. `MAX_DEADLETTERS` is 10,000, so the cap is injectable
    /// rather than reached by writing ten thousand records.
    #[tokio::test]
    async fn the_deadletter_queue_evicts_the_oldest_at_its_cap_and_counts_what_it_holds() {
        let path = temp_path();
        let backing = std::sync::Arc::new(
            sbproxy_platform::storage::EmbeddedKvStore::open(&path, "notifications").expect("open"),
        );
        let store = NotifyStore::open_with_capacity(backing.clone(), 3)
            .await
            .expect("store");

        for n in 0..3 {
            assert_eq!(store.put_deadletter(&deadletter(n)).await.expect("put"), 0);
        }
        assert_eq!(store.deadletter_count(), 3);

        // The fourth costs the first.
        assert_eq!(store.put_deadletter(&deadletter(3)).await.expect("put"), 1);
        assert_eq!(store.deadletter_count(), 3);
        assert!(store.get_deadletter("dlv_0000").await.is_err());
        assert!(store.get_deadletter("dlv_0003").await.is_ok());

        // The page is oldest first, bounded, and carries no event body.
        let (page, cursor) = store.page_deadletters(None, 2).await.expect("page");
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].delivery_id, "dlv_0001");
        assert_eq!(cursor.as_deref(), Some("dlv_0002"));
        let (rest, done) = store
            .page_deadletters(cursor.as_deref(), 2)
            .await
            .expect("page");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].delivery_id, "dlv_0003");
        assert!(done.is_none());
        assert!(!serde_json::to_string(&page)
            .expect("json")
            .contains("filler"));

        // A restart re-seeds the order from the store rather than starting
        // empty and reporting a drained queue.
        drop(store);
        let reopened = NotifyStore::open_with_capacity(backing, 3)
            .await
            .expect("reopen");
        assert_eq!(reopened.deadletter_count(), 3);

        drop(reopened);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_minted_signing_key_is_fresh_every_time() {
        let (first_kid, first_secret) = mint_signing_key();
        let (second_kid, second_secret) = mint_signing_key();
        assert_ne!(first_kid, second_kid);
        assert_ne!(first_secret, second_secret);
        assert_eq!(first_secret.len(), 64, "32 bytes as hex");
    }
}
