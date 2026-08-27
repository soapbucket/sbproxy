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
            .finish()
    }
}

impl Subscription {
    /// Whether this subscription asked for `event_type`.
    ///
    /// `*` selects everything. A prefix filter ending in `.*` selects a
    /// family (`key.*`). Anything else is an exact match, so a typo selects
    /// nothing rather than everything, which is the safe direction for a
    /// filter that decides what leaves the network.
    pub(super) fn selects(&self, event_type: &str) -> bool {
        self.event_types.iter().any(|filter| {
            if filter == "*" {
                return true;
            }
            match filter.strip_suffix(".*") {
                Some(prefix) => event_type.starts_with(prefix),
                None => filter == event_type,
            }
        })
    }
}

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

/// Subscriptions and deadletters over one embedded store.
pub(super) struct NotifyStore {
    store: Arc<dyn PersistentKv>,
    subscriptions: KvNamespace,
    deadletters: KvNamespace,
}

impl NotifyStore {
    pub(super) fn new(store: Arc<dyn PersistentKv>) -> Result<Self> {
        let namespace = |name: &str| {
            KvNamespace::new(name).map_err(|error| NotifyError::Backend(error.to_string()))
        };
        Ok(Self {
            store,
            subscriptions: namespace(SUBSCRIPTIONS)?,
            deadletters: namespace(DEADLETTERS)?,
        })
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

    /// Every deadletter, oldest first.
    pub(super) async fn list_deadletters(&self) -> Result<Vec<DeadLetter>> {
        let stored = self
            .store
            .list(&self.deadletters)
            .await
            .map_err(|error| NotifyError::Backend(error.to_string()))?;
        let mut out: Vec<DeadLetter> = Vec::with_capacity(stored.len());
        for (_, entry) in stored {
            out.push(serde_json::from_slice(&entry.value).map_err(|error| {
                NotifyError::Backend(format!("stored deadletter is unreadable: {error}"))
            })?);
        }
        out.sort_by_key(|record| record.moved_at);
        Ok(out)
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
        let existing = self.list_deadletters().await?;
        let mut evicted = 0;
        // `>=` rather than `>`: the write below adds one, so a queue
        // already at the cap has to give up a record before it lands.
        for stale in existing
            .iter()
            .take(existing.len().saturating_sub(MAX_DEADLETTERS - 1))
        {
            self.store
                .delete(&self.deadletters, &stale.delivery_id)
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
        Ok(evicted)
    }

    pub(super) async fn delete_deadletter(&self, delivery_id: &str) -> Result<()> {
        self.store
            .delete(&self.deadletters, delivery_id)
            .await
            .map(|_| ())
            .map_err(|error| NotifyError::Backend(error.to_string()))
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
pub(super) fn validate_subscription(url: &str, event_types: &[String]) -> Result<()> {
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
        let candidate = filter.strip_suffix(".*").unwrap_or(filter);
        if filter == "*" {
            continue;
        }
        if candidate.is_empty()
            || !candidate
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(NotifyError::Invalid {
                field: "event_types",
                detail: format!(
                    "{:?} is not an event name, a family prefix like key.*, or *",
                    filter
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(64)
                        .collect::<String>()
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(filters: &[&str]) -> Subscription {
        Subscription {
            subscription_id: "sub_1".into(),
            url: "https://receiver.example.com/hook".into(),
            event_types: filters.iter().map(|f| (*f).to_string()).collect(),
            signing_key_id: "k_1".into(),
            signing_secret: "secret".into(),
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
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

    #[test]
    fn a_wildcard_family_selects_its_prefix_only() {
        let family = subscription(&["key.*"]);
        assert!(family.selects("key.minted"));
        assert!(!family.selects("policy.denied"));
    }

    #[test]
    fn the_debug_impl_never_prints_the_signing_secret() {
        let rendered = format!("{:?}", subscription(&["*"]));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret\""));
    }

    #[test]
    fn validation_refuses_the_shapes_the_docs_forbid() {
        assert!(validate_subscription("https://a.example/h", &["*".into()]).is_ok());
        assert!(validate_subscription("ftp://a.example/h", &["*".into()]).is_err());
        assert!(validate_subscription("https://a.example/h", &[]).is_err());
        assert!(validate_subscription("", &["*".into()]).is_err());
        assert!(validate_subscription("https://a.example/h", &["Key Minted".into()]).is_err());
        // A control character in a filter cannot forge a line in the error.
        let refusal = validate_subscription("https://a.example/h", &["a\nb".into()])
            .expect_err("control characters are refused");
        assert!(!refusal.to_string().contains('\n'));
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
