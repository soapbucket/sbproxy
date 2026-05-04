//! R1.4 outbound webhook framework.
//!
//! Per `docs/adr-webhook-security.md` (A1.9), this module ships the OSS half
//! of the outbound webhook story: per-tenant signing (Ed25519 default,
//! HMAC-SHA256 fallback), dual-key rotation window, exponential-backoff
//! retries with deadletter handoff, and a per-tenant subscription registry
//! interface.
//!
//! Wave 2 (E2.4) consumes this framework to emit `wallet.low_balance`,
//! `agent.registered`, and the rest of the customer notification surface.
//!
//! ## Surface area
//!
//! - [`Notifier`] is the dispatch entrypoint. Construct it with a
//!   [`NotifierStore`] adapter and call [`Notifier::dispatch`] to deliver
//!   an event to every matching subscription.
//! - [`NotifierStore`] is the subscription + deadletter persistence trait.
//!   The OSS crate ships [`InMemoryStore`]; a Postgres adapter is provided
//!   out of tree (Wave 2, E2.4).
//! - [`SigningKey`] selects between Ed25519 and HMAC-SHA256 per
//!   subscription. [`Subscription`] carries an optional `previous_key`
//!   that drives the dual-key 30-day rotation window.
//! - [`verify_signature`] validates an `Sbproxy-Signature` header on the
//!   receiving side; both customer-side libraries and the e2e suite share
//!   this one verification function.
//!
//! ## Retry schedule
//!
//! 1s, 5s, 30s, 5m, 30m. After the fifth failure the framework enqueues
//! the event to the deadletter queue. The schedule is exposed so tests
//! can override it.
//!
//! ## Headers per ADR
//!
//! Every successful POST carries:
//! - `Content-Type: application/json`
//! - `Sbproxy-Event-Id: <event_id>` (ULID, stable across retries)
//! - `Sbproxy-Event-Type: <event_type>`
//! - `Sbproxy-Tenant: <tenant_id>`
//! - `Sbproxy-Timestamp: <unix-ms>`
//! - `Sbproxy-Signature: <kid>=<base64-sig>[, <prev-kid>=<base64-prev-sig>]`
//! - W3C TraceContext (`traceparent`, `tracestate`) when `OutboundEvent`
//!   carries one. R1.1 propagates the active span; we just forward.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use prometheus::{register_int_counter_vec, IntCounterVec};
use sha2::Sha256;
use std::sync::OnceLock;

use crate::trace_ctx::w3c::TraceContext;

// --- Constants ---

/// Default exponential-backoff schedule per ADR A1.9 §"Retry policy".
/// Each entry is the delay between successive attempts. After this list is
/// exhausted the event moves to the deadletter queue.
pub const DEFAULT_RETRY_SCHEDULE: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
];

/// Default per-attempt timeout per ADR §"Retry policy".
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

// --- Signing keys ---

/// Per-subscription signing key. The framework signs every outbound
/// delivery with whichever variant the subscription holds.
#[derive(Debug, Clone)]
pub enum SigningKey {
    /// Ed25519 asymmetric signing (the preferred default per ADR).
    /// `key_id` is the JWKS `kid` attribute that the customer uses to
    /// look up the matching public key.
    Ed25519 {
        /// JWKS key id for verification.
        key_id: String,
        /// Ed25519 secret signing key.
        secret: Ed25519SigningKey,
    },
    /// HMAC-SHA256 symmetric signing (fallback for legacy ingestion
    /// pipelines that cannot verify Ed25519).
    HmacSha256 {
        /// Stable identifier for the shared secret.
        key_id: String,
        /// 32+ byte shared secret. Shorter secrets are accepted but
        /// emit a warning at construction time.
        secret: Vec<u8>,
    },
}

impl SigningKey {
    /// Return the `key_id` (`kid`) for this signing key.
    pub fn key_id(&self) -> &str {
        match self {
            SigningKey::Ed25519 { key_id, .. } => key_id,
            SigningKey::HmacSha256 { key_id, .. } => key_id,
        }
    }

    /// Return the algorithm identifier (`ed25519` or `hmac-sha256`).
    pub fn algorithm(&self) -> &'static str {
        match self {
            SigningKey::Ed25519 { .. } => "ed25519",
            SigningKey::HmacSha256 { .. } => "hmac-sha256",
        }
    }

    /// Sign `message` and return the raw signature bytes.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519 { secret, .. } => secret.sign(message).to_bytes().to_vec(),
            SigningKey::HmacSha256 { secret, .. } => {
                // unwrap-safe: HMAC accepts any key length.
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .expect("hmac-sha256 accepts arbitrary key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// Public counterpart of [`SigningKey`] used by [`verify_signature`].
///
/// Customers receiving webhooks deserialize this from their stored
/// secret (HMAC) or from the JWKS published at
/// `/.well-known/sbproxy-webhook-keys` (Ed25519).
#[derive(Debug, Clone)]
pub enum VerificationKey {
    /// Ed25519 public verifying key.
    Ed25519 {
        /// JWKS key id.
        key_id: String,
        /// 32-byte Ed25519 public key.
        public: VerifyingKey,
    },
    /// HMAC-SHA256 shared secret. The verifier holds the same bytes as
    /// the signer.
    HmacSha256 {
        /// Stable identifier for the shared secret.
        key_id: String,
        /// Shared secret (same bytes as the signer).
        secret: Vec<u8>,
    },
}

impl VerificationKey {
    /// Return the `key_id` (`kid`) for this verification key.
    pub fn key_id(&self) -> &str {
        match self {
            VerificationKey::Ed25519 { key_id, .. } => key_id,
            VerificationKey::HmacSha256 { key_id, .. } => key_id,
        }
    }
}

// --- Subscription model ---

/// A customer-registered webhook subscription.
///
/// Wave 1 ships only the in-memory representation; Wave 2 adds the
/// Postgres-backed registry behind the [`NotifierStore`] trait.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Tenant that owns this subscription.
    pub tenant_id: String,
    /// Destination URL. `https://` enforced in production deployments;
    /// `http://` is allowed only for local-dev / e2e fixtures.
    pub url: String,
    /// Event types this subscription matches. `*` matches everything.
    /// Prefixes like `wallet.*` are supported via [`event_type_matches`].
    pub event_types: Vec<String>,
    /// Active signing key (used for new deliveries).
    pub signing_key: SigningKey,
    /// Previous signing key during the dual-key rotation window. When
    /// present the framework appends a second signature so customers
    /// caching either public key can verify.
    pub previous_key: Option<SigningKey>,
    /// When the rotation began. Operators / scheduled rotators clear
    /// `previous_key` after `rotation.dual_window_days` (default 30).
    pub key_rotated_at: Option<DateTime<Utc>>,
}

/// Return `true` when the subscription's `event_types` filter matches a
/// concrete event type.
///
/// Matching rules per ADR §"Per-tenant subscription registry":
/// - `*` matches every event type.
/// - `wallet.*` matches `wallet.low_balance`, `wallet.topup_succeeded`, ...
/// - Any other entry must match the event type exactly.
pub fn event_type_matches(filters: &[String], event_type: &str) -> bool {
    for filter in filters {
        if filter == "*" {
            return true;
        }
        if let Some(prefix) = filter.strip_suffix(".*") {
            if event_type == prefix
                || event_type.starts_with(prefix)
                    && event_type.as_bytes().get(prefix.len()) == Some(&b'.')
            {
                return true;
            }
        } else if filter == event_type {
            return true;
        }
    }
    false
}

// --- Events ---

/// A single outbound event waiting to be delivered.
///
/// `event_id` is a ULID (lexicographically sortable, time-ordered) and
/// remains stable across retry attempts so customer-side idempotency
/// works correctly. The `Sbproxy-Delivery-Id` header rotates per attempt
/// (assigned inside the dispatcher); `event_id` does not.
#[derive(Debug, Clone)]
pub struct OutboundEvent {
    /// ULID; stable across retries.
    pub event_id: String,
    /// Event type, e.g. `"wallet.low_balance"`.
    pub event_type: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// JSON payload that the customer endpoint receives verbatim.
    pub payload: serde_json::Value,
    /// Wall-clock creation time. Used for the `Sbproxy-Timestamp` header
    /// and the signing input.
    pub created_at: DateTime<Utc>,
    /// Optional W3C TraceContext to propagate to the customer endpoint.
    /// R1.1 (OTel) populates this from the active span when available.
    pub trace_context: Option<TraceContext>,
}

impl OutboundEvent {
    /// Build a new event with a fresh ULID and `created_at = now()`.
    pub fn new(
        tenant_id: impl Into<String>,
        event_type: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_id: ulid::Ulid::new().to_string(),
            event_type: event_type.into(),
            tenant_id: tenant_id.into(),
            payload,
            created_at: Utc::now(),
            trace_context: None,
        }
    }

    /// Attach a W3C TraceContext (R1.1 propagation hook).
    pub fn with_trace_context(mut self, ctx: TraceContext) -> Self {
        self.trace_context = Some(ctx);
        self
    }
}

/// A failed delivery that has exhausted its retry budget.
#[derive(Debug, Clone)]
pub struct DeadletterItem {
    /// The original event.
    pub event: OutboundEvent,
    /// Subscription that this delivery targeted.
    pub subscription_url: String,
    /// Tenant ownership (also on the event, duplicated here for convenient
    /// querying without unpacking the event).
    pub tenant_id: String,
    /// Number of attempts made before giving up.
    pub attempt_count: u32,
    /// Last status code returned (None if the failure was a transport error).
    pub last_status: Option<u16>,
    /// Stringified last error.
    pub last_error: String,
    /// When the deadletter was enqueued.
    pub moved_at: DateTime<Utc>,
}

// --- Persistence trait ---

/// Persistence trait for subscriptions and deadletter entries.
///
/// The OSS crate ships [`InMemoryStore`] for tests and single-process
/// deployments. A Postgres adapter (matching the schema in ADR §
/// "Deadletter queue") is provided out of tree in Wave 2.
pub trait NotifierStore: Send + Sync {
    /// Return every subscription that matches `(tenant_id, event_type)`.
    fn list_subscriptions(&self, tenant_id: &str, event_type: &str) -> Vec<Subscription>;
    /// Append `item` to the deadletter queue.
    fn enqueue_deadletter(&self, item: DeadletterItem);
    /// Iterate the deadletter queue (newest-first by `moved_at` is
    /// suggested but not required).
    fn iter_deadletter(&self) -> Box<dyn Iterator<Item = DeadletterItem> + '_>;
}

/// In-memory [`NotifierStore`]. The OSS default; suitable for tests and
/// single-instance dev deployments. Production multi-replica deployments
/// use an out-of-tree Postgres adapter.
pub struct InMemoryStore {
    subscriptions: Mutex<Vec<Subscription>>,
    deadletter: Mutex<Vec<DeadletterItem>>,
}

impl InMemoryStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self {
            subscriptions: Mutex::new(Vec::new()),
            deadletter: Mutex::new(Vec::new()),
        }
    }

    /// Insert a subscription. Used by tests and the Wave 2 registry CRUD
    /// path until the Postgres adapter ships.
    pub fn add_subscription(&self, sub: Subscription) {
        self.subscriptions
            .lock()
            .expect("subscriptions lock")
            .push(sub);
    }

    /// Number of deadlettered events currently held. Test helper.
    pub fn deadletter_len(&self) -> usize {
        self.deadletter.lock().expect("deadletter lock").len()
    }

    /// Return a clone of every deadletter entry. Test helper.
    pub fn deadletter_snapshot(&self) -> Vec<DeadletterItem> {
        self.deadletter.lock().expect("deadletter lock").clone()
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NotifierStore for InMemoryStore {
    fn list_subscriptions(&self, tenant_id: &str, event_type: &str) -> Vec<Subscription> {
        self.subscriptions
            .lock()
            .expect("subscriptions lock")
            .iter()
            .filter(|s| s.tenant_id == tenant_id && event_type_matches(&s.event_types, event_type))
            .cloned()
            .collect()
    }

    fn enqueue_deadletter(&self, item: DeadletterItem) {
        self.deadletter.lock().expect("deadletter lock").push(item);
    }

    fn iter_deadletter(&self) -> Box<dyn Iterator<Item = DeadletterItem> + '_> {
        let snap = self.deadletter.lock().expect("deadletter lock").clone();
        Box::new(snap.into_iter())
    }
}

// --- Metrics ---

/// `sbproxy_outbound_webhook_attempts_total{tenant_id,event_type,result}`
/// per ADR §"Audit and observability". The `result` label is one of
/// `success`, `client_error`, `server_error`, `transport_error`,
/// `deadletter`.
fn attempts_counter() -> &'static IntCounterVec {
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_outbound_webhook_attempts_total",
            "Outbound webhook delivery attempts grouped by tenant, event type, and result",
            &["tenant_id", "event_type", "result"],
        )
        .expect("outbound webhook attempts counter registers")
    })
}

fn record_attempt(tenant_id: &str, event_type: &str, result: &str) {
    attempts_counter()
        .with_label_values(&[tenant_id, event_type, result])
        .inc();
}

// --- Notifier ---

/// Outbound webhook dispatcher.
///
/// Holds a shared [`reqwest::Client`] (connection pool reuse) and a
/// reference to the persistence layer. Dispatch is async; the framework
/// drives the retry loop on the caller's runtime.
pub struct Notifier {
    store: Arc<dyn NotifierStore>,
    client: reqwest::Client,
    retry_schedule: Vec<Duration>,
    attempt_timeout: Duration,
}

impl Notifier {
    /// Build a notifier with the default retry schedule (per ADR
    /// §"Retry policy") and a 10s per-attempt timeout.
    pub fn new(store: Arc<dyn NotifierStore>) -> Self {
        Self::with_schedule(
            store,
            DEFAULT_RETRY_SCHEDULE.to_vec(),
            DEFAULT_ATTEMPT_TIMEOUT,
        )
    }

    /// Build a notifier with an explicit retry schedule and per-attempt
    /// timeout. Test entrypoint for compressing the 35-minute production
    /// schedule into millisecond delays.
    pub fn with_schedule(
        store: Arc<dyn NotifierStore>,
        retry_schedule: Vec<Duration>,
        attempt_timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                "sbproxy-webhook/",
                env!("CARGO_PKG_VERSION"),
                " (+https://docs.sbproxy.dev/webhooks)",
            ))
            .build()
            .expect("reqwest client for outbound webhook notifier");

        Self {
            store,
            client,
            retry_schedule,
            attempt_timeout,
        }
    }

    /// Dispatch `event` to every subscription that matches.
    ///
    /// Returns the number of subscriptions that received the event (each
    /// dispatch returns immediately after the first attempt; retries run
    /// inside per-subscription tokio tasks). For tests, prefer
    /// [`Notifier::dispatch_blocking`] which awaits all delivery
    /// attempts to completion.
    pub fn dispatch(&self, event: OutboundEvent) -> usize {
        let subs = self
            .store
            .list_subscriptions(&event.tenant_id, &event.event_type);
        let n = subs.len();
        for sub in subs {
            let event = event.clone();
            let store = Arc::clone(&self.store);
            let client = self.client.clone();
            let schedule = self.retry_schedule.clone();
            let timeout = self.attempt_timeout;
            tokio::spawn(async move {
                deliver_with_retries(client, store, sub, event, schedule, timeout).await;
            });
        }
        n
    }

    /// Like [`Notifier::dispatch`] but awaits every per-subscription
    /// delivery (and its retries) to completion before returning.
    /// Used by tests and the e2e suite. Production paths use
    /// [`Notifier::dispatch`].
    pub async fn dispatch_blocking(&self, event: OutboundEvent) -> usize {
        let subs = self
            .store
            .list_subscriptions(&event.tenant_id, &event.event_type);
        let n = subs.len();
        let mut handles = Vec::with_capacity(n);
        for sub in subs {
            let event = event.clone();
            let store = Arc::clone(&self.store);
            let client = self.client.clone();
            let schedule = self.retry_schedule.clone();
            let timeout = self.attempt_timeout;
            handles.push(tokio::spawn(async move {
                deliver_with_retries(client, store, sub, event, schedule, timeout).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        n
    }
}

// --- Delivery loop ---

/// Drive a single subscription's delivery: sign, POST, retry per the
/// schedule, and on exhaustion enqueue to the deadletter queue.
async fn deliver_with_retries(
    client: reqwest::Client,
    store: Arc<dyn NotifierStore>,
    sub: Subscription,
    event: OutboundEvent,
    schedule: Vec<Duration>,
    attempt_timeout: Duration,
) {
    let max_attempts = (schedule.len() as u32).saturating_add(1);
    let body = match serde_json::to_vec(&event.payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                tenant_id = %event.tenant_id,
                event_id = %event.event_id,
                error = %e,
                "outbound webhook: payload serialization failed (drop)",
            );
            return;
        }
    };

    let mut last_status: Option<u16> = None;
    let mut last_error = String::new();

    for attempt in 1..=max_attempts {
        match send_attempt(&client, &sub, &event, &body, attempt_timeout).await {
            Ok(status) if (200..300).contains(&status) => {
                record_attempt(&event.tenant_id, &event.event_type, "success");
                tracing::debug!(
                    tenant_id = %event.tenant_id,
                    event_id = %event.event_id,
                    attempt,
                    status,
                    "outbound webhook delivered",
                );
                return;
            }
            Ok(status) => {
                let bucket = if (400..500).contains(&status) {
                    "client_error"
                } else {
                    "server_error"
                };
                record_attempt(&event.tenant_id, &event.event_type, bucket);
                last_status = Some(status);
                last_error = format!("non-2xx status {status}");
                tracing::warn!(
                    tenant_id = %event.tenant_id,
                    event_id = %event.event_id,
                    attempt,
                    status,
                    "outbound webhook non-2xx response",
                );
            }
            Err(e) => {
                record_attempt(&event.tenant_id, &event.event_type, "transport_error");
                last_error = e.to_string();
                tracing::warn!(
                    tenant_id = %event.tenant_id,
                    event_id = %event.event_id,
                    attempt,
                    error = %e,
                    "outbound webhook transport error",
                );
            }
        }

        // Exhausted: deadletter.
        if attempt as usize > schedule.len() {
            break;
        }
        let delay = schedule[(attempt - 1) as usize];
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    record_attempt(&event.tenant_id, &event.event_type, "deadletter");
    let item = DeadletterItem {
        subscription_url: sub.url.clone(),
        tenant_id: event.tenant_id.clone(),
        attempt_count: max_attempts,
        last_status,
        last_error,
        moved_at: Utc::now(),
        event,
    };
    store.enqueue_deadletter(item);
}

/// Single attempt: build headers, sign, POST, return the response status.
async fn send_attempt(
    client: &reqwest::Client,
    sub: &Subscription,
    event: &OutboundEvent,
    body: &[u8],
    attempt_timeout: Duration,
) -> Result<u16, reqwest::Error> {
    let timestamp_ms = event.created_at.timestamp_millis();
    let signing_input = build_signing_input(timestamp_ms, body);
    let signature_header = build_signature_header(&signing_input, sub);

    let mut req = client
        .post(&sub.url)
        .timeout(attempt_timeout)
        .header("Content-Type", "application/json")
        .header("Sbproxy-Event-Id", &event.event_id)
        .header("Sbproxy-Event-Type", &event.event_type)
        .header("Sbproxy-Tenant", &event.tenant_id)
        .header("Sbproxy-Timestamp", timestamp_ms.to_string())
        .header("Sbproxy-Signature", signature_header);

    if let Some(ctx) = &event.trace_context {
        req = req.header("traceparent", ctx.to_traceparent());
        if let Some(ts) = &ctx.tracestate {
            req = req.header("tracestate", ts);
        }
    }

    let resp = req.body(body.to_vec()).send().await?;
    Ok(resp.status().as_u16())
}

/// Build the canonical signing input: `<timestamp_ms>.<raw_body>`.
///
/// Matching Stripe's `<timestamp>.<payload>` convention so customer-side
/// verifiers built for Stripe can be adapted with minimal surgery.
fn build_signing_input(timestamp_ms: i64, body: &[u8]) -> Vec<u8> {
    let prefix = format!("{timestamp_ms}.");
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Build the `Sbproxy-Signature` header value.
///
/// Format: `<kid>=<base64-sig>`, with a comma-separated second entry
/// when a `previous_key` is set (dual-key rotation window).
fn build_signature_header(signing_input: &[u8], sub: &Subscription) -> String {
    let primary_sig = sub.signing_key.sign(signing_input);
    let primary_b64 = base64::engine::general_purpose::STANDARD.encode(&primary_sig);
    let mut header = format!("{}={}", sub.signing_key.key_id(), primary_b64);

    if let Some(prev) = &sub.previous_key {
        let prev_sig = prev.sign(signing_input);
        let prev_b64 = base64::engine::general_purpose::STANDARD.encode(&prev_sig);
        header.push_str(&format!(", {}={}", prev.key_id(), prev_b64));
    }

    header
}

// --- Verification (customer-side helper) ---

/// Verification error returned by [`verify_signature`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// `Sbproxy-Signature` header was missing or malformed.
    #[error("malformed signature header: {0}")]
    Malformed(String),
    /// None of the candidate `kid`s in the header matched `key`.
    #[error("no matching kid in signature header")]
    UnknownKid,
    /// Cryptographic verification failed.
    #[error("signature verification failed")]
    BadSignature,
    /// Timestamp parse failed (not numeric or out of range).
    #[error("timestamp parse error: {0}")]
    BadTimestamp(String),
    /// Timestamp older than `tolerance`.
    #[error("timestamp outside tolerance window")]
    StaleTimestamp,
}

/// Verify an `Sbproxy-Signature` header against the request body.
///
/// `signature_header` is the raw header value (`<kid>=<sig>` or
/// `<kid>=<sig>, <prev-kid>=<prev-sig>`). `timestamp_header` is the
/// `Sbproxy-Timestamp` header value (ms since epoch). `body` is the
/// raw request body bytes.
///
/// `key` is the customer's verification key. During the dual-key
/// window the customer holds two keys (current + previous); they can
/// call `verify_signature` once per key, or pass each in turn.
///
/// If `tolerance` is `Some`, the function rejects signatures whose
/// timestamp is more than `tolerance` away from `now_ms`. Pass `None`
/// to skip the freshness check (e.g. when replaying from the deadletter).
pub fn verify_signature(
    signature_header: &str,
    timestamp_header: &str,
    body: &[u8],
    key: &VerificationKey,
    tolerance: Option<Duration>,
    now_ms: i64,
) -> Result<(), VerifyError> {
    let timestamp_ms: i64 = timestamp_header
        .parse()
        .map_err(|e: std::num::ParseIntError| VerifyError::BadTimestamp(e.to_string()))?;

    if let Some(tol) = tolerance {
        let drift_ms = (now_ms - timestamp_ms).unsigned_abs();
        if drift_ms > tol.as_millis() as u64 {
            return Err(VerifyError::StaleTimestamp);
        }
    }

    // Parse `<kid>=<sig>[, <kid2>=<sig2>...]`. The header may carry a
    // primary and a previous kid during the dual-key window; we accept
    // the entry whose kid matches the verifier's `key_id`.
    for entry in signature_header.split(',') {
        let entry = entry.trim();
        let (kid, sig_b64) = entry
            .split_once('=')
            .ok_or_else(|| VerifyError::Malformed(format!("missing '=' in entry {entry:?}")))?;
        let kid = kid.trim();
        if kid != key.key_id() {
            continue;
        }
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.trim())
            .map_err(|e| VerifyError::Malformed(format!("base64 decode: {e}")))?;
        let signing_input = build_signing_input(timestamp_ms, body);
        return match key {
            VerificationKey::Ed25519 { public, .. } => {
                let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
                    .map_err(|e| VerifyError::Malformed(format!("ed25519 sig length: {e}")))?;
                public
                    .verify(&signing_input, &sig)
                    .map_err(|_| VerifyError::BadSignature)?;
                Ok(())
            }
            VerificationKey::HmacSha256 { secret, .. } => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .expect("hmac accepts arbitrary key length");
                mac.update(&signing_input);
                mac.verify_slice(&sig_bytes)
                    .map_err(|_| VerifyError::BadSignature)?;
                Ok(())
            }
        };
    }

    // Header parsed cleanly but no entry's kid matched the verifier's key.
    Err(VerifyError::UnknownKid)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519Key;
    use rand::RngCore;

    /// Build a reusable Ed25519 keypair for tests.
    fn ed25519_keypair() -> (Ed25519Key, VerifyingKey) {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let signing = Ed25519Key::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    /// Build a reusable HMAC secret.
    fn hmac_secret() -> Vec<u8> {
        let mut s = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    }

    /// Test-only HTTP server that captures the headers + body of every
    /// request. We use a raw tokio listener rather than wiremock to keep
    /// the dev-dependency surface tiny.
    struct CaptureServer {
        addr: std::net::SocketAddr,
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        // Returned status code per attempt index. If exhausted, returns 200.
        responses: Arc<Mutex<Vec<u16>>>,
    }

    #[derive(Clone)]
    struct CapturedRequest {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl CaptureServer {
        async fn start(responses: Vec<u16>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let captured = Arc::new(Mutex::new(Vec::new()));
            let responses = Arc::new(Mutex::new(responses));

            let captured_clone = Arc::clone(&captured);
            let responses_clone = Arc::clone(&responses);
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let captured = Arc::clone(&captured_clone);
                    let responses = Arc::clone(&responses_clone);
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 65536];
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                        let (head, body) = match raw.split_once("\r\n\r\n") {
                            Some(p) => p,
                            None => return,
                        };
                        // If there's a Content-Length and we haven't read the
                        // full body yet, drain more bytes so we capture it
                        // accurately.
                        let mut headers = Vec::new();
                        let mut content_length: usize = 0;
                        for line in head.split("\r\n").skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                let k = k.trim().to_string();
                                let v = v.trim().to_string();
                                if k.eq_ignore_ascii_case("content-length") {
                                    content_length = v.parse().unwrap_or(0);
                                }
                                headers.push((k, v));
                            }
                        }
                        let mut body_bytes = body.as_bytes().to_vec();
                        while body_bytes.len() < content_length {
                            let mut chunk = vec![0u8; content_length - body_bytes.len()];
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(m) => body_bytes.extend_from_slice(&chunk[..m]),
                            }
                        }
                        captured.lock().unwrap().push(CapturedRequest {
                            headers,
                            body: body_bytes,
                        });

                        let status = {
                            let mut r = responses.lock().unwrap();
                            if r.is_empty() {
                                200
                            } else {
                                r.remove(0)
                            }
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });

            Self {
                addr,
                captured,
                responses,
            }
        }

        fn url(&self) -> String {
            format!("http://{}/", self.addr)
        }

        fn captured(&self) -> Vec<CapturedRequest> {
            self.captured.lock().unwrap().clone()
        }

        // The harness owns the response queue via Arc; this getter is
        // here to keep the field used so dead-code lints stay quiet
        // when we don't read it back.
        #[allow(dead_code)]
        fn responses_remaining(&self) -> usize {
            self.responses.lock().unwrap().len()
        }
    }

    fn header_value<'a>(req: &'a CapturedRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    // --- Test 1: Ed25519 signature ---

    #[tokio::test]
    async fn dispatch_signs_with_ed25519() {
        let server = CaptureServer::start(vec![200]).await;
        let (signing, verifying) = ed25519_keypair();

        let store = Arc::new(InMemoryStore::new());
        store.add_subscription(Subscription {
            tenant_id: "tenant_42".to_string(),
            url: server.url(),
            event_types: vec!["wallet.low_balance".to_string()],
            signing_key: SigningKey::Ed25519 {
                key_id: "kid_a".to_string(),
                secret: signing,
            },
            previous_key: None,
            key_rotated_at: None,
        });

        let notifier = Notifier::with_schedule(store.clone(), vec![], Duration::from_secs(2));
        let event = OutboundEvent::new(
            "tenant_42",
            "wallet.low_balance",
            serde_json::json!({"balance_cents": 100}),
        );
        let n = notifier.dispatch_blocking(event.clone()).await;
        assert_eq!(n, 1);

        let captured = server.captured();
        assert_eq!(captured.len(), 1);
        let req = &captured[0];

        let sig_header = header_value(req, "sbproxy-signature").unwrap();
        let ts_header = header_value(req, "sbproxy-timestamp").unwrap();
        assert_eq!(
            header_value(req, "sbproxy-event-id").unwrap(),
            event.event_id
        );
        assert_eq!(
            header_value(req, "sbproxy-event-type").unwrap(),
            "wallet.low_balance"
        );
        assert_eq!(header_value(req, "sbproxy-tenant").unwrap(), "tenant_42");

        let key = VerificationKey::Ed25519 {
            key_id: "kid_a".to_string(),
            public: verifying,
        };
        verify_signature(sig_header, ts_header, &req.body, &key, None, 0)
            .expect("ed25519 signature verifies");
    }

    // --- Test 2: HMAC signature ---

    #[tokio::test]
    async fn dispatch_signs_with_hmac() {
        let server = CaptureServer::start(vec![200]).await;
        let secret = hmac_secret();

        let store = Arc::new(InMemoryStore::new());
        store.add_subscription(Subscription {
            tenant_id: "tenant_42".to_string(),
            url: server.url(),
            event_types: vec!["wallet.*".to_string()],
            signing_key: SigningKey::HmacSha256 {
                key_id: "kid_h".to_string(),
                secret: secret.clone(),
            },
            previous_key: None,
            key_rotated_at: None,
        });

        let notifier = Notifier::with_schedule(store.clone(), vec![], Duration::from_secs(2));
        let event = OutboundEvent::new(
            "tenant_42",
            "wallet.topup_succeeded",
            serde_json::json!({"amount_cents": 5000}),
        );
        notifier.dispatch_blocking(event).await;

        let captured = server.captured();
        assert_eq!(captured.len(), 1);
        let req = &captured[0];
        let sig_header = header_value(req, "sbproxy-signature").unwrap();
        let ts_header = header_value(req, "sbproxy-timestamp").unwrap();

        let key = VerificationKey::HmacSha256 {
            key_id: "kid_h".to_string(),
            secret,
        };
        verify_signature(sig_header, ts_header, &req.body, &key, None, 0)
            .expect("hmac signature verifies");

        // A wrong key must reject.
        let wrong_key = VerificationKey::HmacSha256 {
            key_id: "kid_h".to_string(),
            secret: vec![0u8; 32],
        };
        assert!(matches!(
            verify_signature(sig_header, ts_header, &req.body, &wrong_key, None, 0),
            Err(VerifyError::BadSignature)
        ));
    }

    // --- Test 3: Dual-key rotation window ---

    #[tokio::test]
    async fn dual_key_window_emits_both_signatures() {
        let server = CaptureServer::start(vec![200]).await;
        let (primary_signing, primary_verifying) = ed25519_keypair();
        let (previous_signing, previous_verifying) = ed25519_keypair();

        let store = Arc::new(InMemoryStore::new());
        store.add_subscription(Subscription {
            tenant_id: "tenant_42".to_string(),
            url: server.url(),
            event_types: vec!["*".to_string()],
            signing_key: SigningKey::Ed25519 {
                key_id: "kid_new".to_string(),
                secret: primary_signing,
            },
            previous_key: Some(SigningKey::Ed25519 {
                key_id: "kid_old".to_string(),
                secret: previous_signing,
            }),
            key_rotated_at: Some(Utc::now()),
        });

        let notifier = Notifier::with_schedule(store.clone(), vec![], Duration::from_secs(2));
        let event = OutboundEvent::new(
            "tenant_42",
            "agent.registered",
            serde_json::json!({"id": 1}),
        );
        notifier.dispatch_blocking(event).await;

        let captured = server.captured();
        assert_eq!(captured.len(), 1);
        let req = &captured[0];
        let sig_header = header_value(req, "sbproxy-signature").unwrap();
        let ts_header = header_value(req, "sbproxy-timestamp").unwrap();

        // Header carries both kids.
        assert!(sig_header.contains("kid_new="));
        assert!(sig_header.contains("kid_old="));

        // Both signatures verify against their respective public keys.
        let new_key = VerificationKey::Ed25519 {
            key_id: "kid_new".to_string(),
            public: primary_verifying,
        };
        let old_key = VerificationKey::Ed25519 {
            key_id: "kid_old".to_string(),
            public: previous_verifying,
        };
        verify_signature(sig_header, ts_header, &req.body, &new_key, None, 0)
            .expect("primary kid verifies");
        verify_signature(sig_header, ts_header, &req.body, &old_key, None, 0)
            .expect("previous kid verifies");
    }

    // --- Test 4: Retry then deadletter ---

    #[tokio::test]
    async fn retry_then_deadletter() {
        // Production schedule is 5 retry slots (1s, 5s, 30s, 5m, 30m) so
        // the loop runs 6 attempts (initial + 5 retries) before
        // deadlettering. Compress the schedule to ms and queue 6 x 500s
        // so every attempt fails and the event lands in the deadletter.
        let server = CaptureServer::start(vec![500, 500, 500, 500, 500, 500]).await;
        let (signing, _verifying) = ed25519_keypair();

        let store = Arc::new(InMemoryStore::new());
        store.add_subscription(Subscription {
            tenant_id: "tenant_42".to_string(),
            url: server.url(),
            event_types: vec!["*".to_string()],
            signing_key: SigningKey::Ed25519 {
                key_id: "kid".to_string(),
                secret: signing,
            },
            previous_key: None,
            key_rotated_at: None,
        });

        let schedule = vec![
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        ];
        let notifier = Notifier::with_schedule(store.clone(), schedule, Duration::from_secs(2));

        let event = OutboundEvent::new("tenant_42", "wallet.low_balance", serde_json::json!({}));
        notifier.dispatch_blocking(event.clone()).await;

        // We expect exactly 6 attempts (initial + 5 retries) before the
        // schedule exhaustion guard fires.
        let captured = server.captured();
        assert_eq!(
            captured.len(),
            6,
            "expected 6 attempts (1 initial + 5 retries), got {}",
            captured.len()
        );

        // Deadletter must hold exactly one entry.
        assert_eq!(store.deadletter_len(), 1);
        let dl = store.deadletter_snapshot().pop().unwrap();
        assert_eq!(dl.tenant_id, "tenant_42");
        assert_eq!(dl.event.event_id, event.event_id);
        assert_eq!(dl.last_status, Some(500));
        assert_eq!(dl.attempt_count, 6);
    }

    // --- Bonus coverage: event_type filter matching ---

    #[test]
    fn event_type_filter_matches_wildcard_prefix_exact() {
        let f = vec!["wallet.*".to_string(), "agent.registered".to_string()];
        assert!(event_type_matches(&f, "wallet.low_balance"));
        assert!(event_type_matches(&f, "wallet.topup_succeeded"));
        assert!(event_type_matches(&f, "agent.registered"));
        assert!(!event_type_matches(&f, "agent.revoked"));
        assert!(!event_type_matches(&f, "billing.invoice"));

        let star = vec!["*".to_string()];
        assert!(event_type_matches(&star, "anything.at.all"));
    }

    #[test]
    fn event_type_filter_does_not_overmatch_prefix() {
        // `wallet.*` must not match `walletx.foo`.
        let f = vec!["wallet.*".to_string()];
        assert!(!event_type_matches(&f, "walletx.foo"));
    }
}
