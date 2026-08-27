//! Idempotency-Key middleware.
//!
//! Implements the cached-retry, conflict, and single-flight semantics.
//! The middleware sits ahead of policies in the handler chain.
//! It is opt-in per origin via
//! the `idempotency:` config block.
//!
//! Flow:
//!
//! 1. Read the `Idempotency-Key` header.
//! 2. Absent: pass through. The rate-limit middleware consumes
//!    a slot per the normal flow.
//! 3. Present, nothing stored: **claim** the key with a lease, process
//!    the request, capture the response, and publish it under the
//!    claim. TTL 24 h.
//! 4. Present, a completed response stored, body hash matches: return
//!    the cached response. Set the request-context flag
//!    `IdempotencyOutcome::CacheHit` so the rate-limit middleware
//!    skips token-bucket consumption.
//! 5. Present, a completed response stored, body hash differs: return
//!    409 `ledger.idempotency_conflict`. Set
//!    `IdempotencyOutcome::Conflict`; the rate-limit middleware DOES
//!    consume a slot, as a DoS protection rule.
//! 6. Present, another request holds a live claim: wait for that
//!    request's response for a bounded time and replay it, or return
//!    409 `ledger.idempotency_in_flight` when the wait runs out. The
//!    upstream is never contacted twice for one key.
//!
//! # Single-flight, and why it is shaped this way (WOR-2609)
//!
//! Before the claim existed, this module was an independent `get`
//! followed, after the response was final, by a `put`. Fifty parallel
//! retries of one payment POST all missed, all reached the upstream,
//! and all charged the card. The `get` proved nothing about what any
//! other request was doing, which is the whole reason the feature
//! exists.
//!
//! The shape here is the one the field converged on:
//!
//! * **An atomic claim with a lease.** `draft-ietf-httpapi-idempotency-key-header`
//!   requires a resource server to answer `409 Conflict` while a request
//!   with the same key is still being processed, which presumes the
//!   server knows one is in flight. Stripe's implementation
//!   (<https://stripe.com/blog/idempotency>) locks the key row for the
//!   duration of the request and stamps a `locked_at` timestamp so a
//!   process that dies does not hold the key forever. That is the lease.
//! * **`SET NX PX` plus a fencing token, released by compare-and-swap.**
//!   The single-node Redis lock recipe, and the same primitive this
//!   workspace already uses for ACME order leases (WOR-1774, WOR-2633).
//!   The token is what stops an owner that paused past its lease from
//!   overwriting the response the next owner published.
//! * **Waiters poll rather than subscribe.** Redis pub/sub can drop the
//!   release message and wedge a waiter, so the published recipe
//!   retries with backoff; polling also means one wait loop serves the
//!   memory and the shared backend identically instead of two code
//!   paths with two sets of bugs.
//!
//! The one place this goes further than Stripe is the bounded wait. An
//! immediate 409 is correct and is what the draft mandates as a floor,
//! but a follower that waits a few seconds usually gets the owner's real
//! response, so the client sees its answer instead of an error while
//! still never producing a second side effect. The 409 remains the
//! fallback when the wait runs out.
//!
//! What a follower deliberately does **not** do is take over an expired
//! lease. By the time it is waiting it has already drained its request
//! body to hash it, and a drained body cannot be handed to the upstream,
//! so a follower that inherited the key would have to answer without
//! calling anything. It returns 409 instead and the client's retry, a
//! fresh request with an undrained body, is what takes the key over.
//!
//! Cache backends:
//!
//! - `InMemoryIdempotencyCache` for tests and single-instance
//!   deployments. Allocated once per origin, so its keyspace is
//!   origin-local by construction. Claims and completed responses live
//!   in one map under one mutex, so the claim is atomic by
//!   construction.
//! - `KvIdempotencyCache` for Redis-backed deployments. It wraps any
//!   `sbproxy_platform::storage::KVStore` impl, which keeps the OSS
//!   build redis-client-agnostic (the platform crate already pulls
//!   in the redis driver behind a feature flag and exposes the
//!   resulting blobs through the unified `KVStore` trait). One store
//!   serves the whole cluster, so this backend namespaces every key on
//!   the owning origin's tenant and origin id.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, StatusCode};
use sbproxy_platform::storage::KVStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// --- Public surface ---

/// Default TTL for idempotency entries: 24 h layer 2.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// How long a claim holds a key before another request may take it over.
///
/// This is the bound on how long a crashed or disconnected request can
/// wedge one key: nothing else. It is deliberately longer than any
/// upstream call is expected to take, because a lease that expires while
/// its owner is still working lets a retry through to the upstream,
/// which is the duplicate this module exists to prevent. Sixty seconds
/// covers the slow tail of a normal API call; an origin whose upstream
/// routinely runs longer than that wants a larger value, and
/// [`crate::idempotency`] carries it on the compiled origin so a config
/// key can be added without touching this module.
pub const DEFAULT_CLAIM_LEASE_SECS: u64 = 60;

/// How long a follower waits for the claim holder's response before it
/// gives up and answers 409.
///
/// Three seconds is short enough that a client's connection budget is
/// not spent waiting on somebody else's request, and long enough that
/// the overlapping-retry case this exists for (a client that timed out
/// locally and immediately retried) resolves into a replay rather than
/// an error.
pub const DEFAULT_CLAIM_WAIT_MS: u64 = 3_000;

/// First interval between two polls of a key a follower is waiting on.
const WAIT_POLL_MIN: Duration = Duration::from_millis(5);

/// Ceiling on the poll interval. The backoff doubles from
/// [`WAIT_POLL_MIN`] up to this, so a wait that runs its full budget
/// costs a bounded number of reads rather than one per five
/// milliseconds. Fifty waiters on one key at the ceiling are twenty
/// reads a second each, which a shared store does not notice.
const WAIT_POLL_MAX: Duration = Duration::from_millis(50);

/// HTTP header carrying the agent's idempotency key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// Cached response captured for a successfully processed request.
///
/// The status, headers, and body are replayed verbatim on subsequent
/// retries that match the cached body hash. Headers are stored as a
/// flat `(name, value)` list rather than a `HeaderMap` so the type
/// round-trips through `serde_json` cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedResponse {
    /// HTTP status code as a `u16`.
    pub status: u16,
    /// Response headers as flat name / value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body. May be empty.
    pub body: Vec<u8>,
    /// SHA-256 hash of the original request body, hex-encoded.
    /// Compared against subsequent retries to detect conflicts.
    pub request_body_hash: [u8; 32],
    /// Wall-clock expiry as Unix seconds. The middleware treats
    /// `now_unix() >= expires_at` as a cache miss so a stale row in
    /// the backing store does not get replayed.
    pub expires_at_unix: u64,
}

/// What is stored under one idempotency key right now.
///
/// Read-only: [`IdempotencyCache::peek`] answers with this and changes
/// nothing, which is what a follower polling for the owner's response
/// needs. Taking the key is [`IdempotencyCache::try_claim`].
#[derive(Debug, Clone, PartialEq)]
pub enum EntryState {
    /// Nothing is stored, or what is stored has expired.
    Absent,
    /// Another request holds a live claim, expiring at this Unix second.
    InFlight {
        /// Unix second the holder's lease runs out. A follower uses it
        /// only for diagnostics: it never takes the key over.
        lease_expires_at_unix: u64,
    },
    /// A completed response is stored.
    Completed(Box<CachedResponse>),
}

/// The outcome of trying to take an idempotency key.
///
/// [`ClaimState::Claimed`] carries the RAII handle: the holder either
/// publishes a response through [`record_response`] or drops it, and
/// dropping releases the key immediately rather than leaving the next
/// request to wait out the whole lease.
#[derive(Debug)]
pub enum ClaimState {
    /// This caller owns the key and must publish or release it.
    Claimed(IdempotencyClaim),
    /// Another request holds a live claim.
    InFlight {
        /// Unix second the holder's lease runs out.
        lease_expires_at_unix: u64,
    },
    /// A completed response is already stored under this key.
    Completed(Box<CachedResponse>),
}

/// What a backend's [`IdempotencyCache::try_claim`] answers, before the
/// RAII handle is attached.
///
/// Backends return this rather than [`ClaimState`] because the handle
/// needs an owning `Arc` of the cache in order to release itself on
/// drop, and `&self` cannot produce one.
#[derive(Debug)]
pub enum TryClaim {
    /// The caller now holds the key under this fencing token.
    Claimed {
        /// Fencing token. A publish is refused unless the stored claim
        /// still carries it, so an owner that stalled past its lease
        /// cannot overwrite the response its successor published.
        owner: u128,
        /// Whether this claim replaced a lapsed one rather than taking
        /// an empty key. Counted separately: a nonzero takeover rate
        /// means requests are dying mid-flight.
        took_over: bool,
    },
    /// Another request holds a live claim.
    InFlight {
        /// Unix second the holder's lease runs out.
        lease_expires_at_unix: u64,
    },
    /// A completed response is already stored under this key.
    Completed(Box<CachedResponse>),
}

/// A held claim on one idempotency key.
///
/// Dropping without publishing releases the key. That is the whole
/// reason this is a handle rather than a token: `request_filter` and
/// `response_body_filter` are long functions with many early returns,
/// a request can be cancelled at any await point, and every one of
/// those paths would otherwise leave a key claimed until its lease ran
/// out, answering 409 to every retry in between.
pub struct IdempotencyClaim {
    cache: Arc<dyn IdempotencyCache>,
    workspace_id: String,
    key: String,
    owner: u128,
    published: bool,
}

impl IdempotencyClaim {
    /// The key this claim holds.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The workspace this claim is scoped to.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// The fencing token, for backends to compare against what is
    /// stored.
    pub fn owner(&self) -> u128 {
        self.owner
    }
}

impl std::fmt::Debug for IdempotencyClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cache is not `Debug` and the key is caller-supplied, so
        // this prints the scope and the fencing token and nothing else.
        f.debug_struct("IdempotencyClaim")
            .field("workspace_id", &self.workspace_id)
            .field("owner", &self.owner)
            .field("published", &self.published)
            .finish_non_exhaustive()
    }
}

impl Drop for IdempotencyClaim {
    fn drop(&mut self) {
        if !self.published {
            self.cache.release(self);
        }
    }
}

/// Result of running the middleware before the handler chain.
///
/// The proxy's rate-limit middleware reads this flag and skips token
/// consumption only when [`IdempotencyOutcome::CacheHit`] is set.
#[derive(Debug)]
pub enum IdempotencyOutcome {
    /// No `Idempotency-Key` header was present. Pass through.
    NotApplicable,
    /// A stored response matched this request's body. Replay it.
    /// Rate-limit middleware MUST NOT consume a slot.
    CacheHit(Box<CachedResponse>),
    /// A stored response exists but the body hash differs. Return 409
    /// `ledger.idempotency_conflict`. Rate-limit middleware DOES
    /// consume a slot.
    Conflict,
    /// Another request holds a live claim on this key and did not
    /// finish inside the wait budget. Return 409
    /// `ledger.idempotency_in_flight`; the upstream is not contacted.
    InFlight,
    /// This caller took the key. The request must be processed and the
    /// response published via [`record_response`] with the claim.
    Miss {
        /// SHA-256 hash of the request body.
        body_hash: [u8; 32],
        /// The held claim. Dropping it releases the key.
        claim: IdempotencyClaim,
    },
}

impl IdempotencyOutcome {
    /// Convenience: whether this outcome represents a cache hit on a
    /// matching body. The rate-limit middleware reads this flag.
    pub fn is_cache_hit(&self) -> bool {
        matches!(self, IdempotencyOutcome::CacheHit(_))
    }

    /// Convenience: whether this outcome represents an idempotency
    /// conflict (a stored response exists but the body differs).
    pub fn is_conflict(&self) -> bool {
        matches!(self, IdempotencyOutcome::Conflict)
    }
}

/// Cache backend trait.
///
/// Every implementation is scoped so that two callers reaching different
/// origins with the same idempotency key never read each other's entries.
/// How that scoping is achieved differs by backend and is the
/// implementation's responsibility, not the caller's:
/// [`InMemoryIdempotencyCache`] is allocated per origin and additionally
/// keys on `workspace_id`, while [`KvIdempotencyCache`] shares one store
/// across the whole cluster and folds the origin's identity into every
/// storage key.
///
/// Every implementation must also make [`Self::try_claim`] atomic
/// against every other caller that can reach the same key, including
/// callers in other processes when the backend is shared. There is no
/// default implementation of it for exactly that reason: a backend that
/// silently let every caller claim would compile, pass every
/// single-request test, and reinstate the stampede.
///
/// The `complete` call is responsible for honoring the embedded
/// `expires_at_unix` field; backends that support native TTLs SHOULD
/// use them, but the middleware also re-checks expiry on every read
/// so a backend without TTLs (in-memory in tests) stays correct.
pub trait IdempotencyCache: Send + Sync {
    /// Read what is stored under `(workspace_id, key)` without taking
    /// it. Expired rows read as [`EntryState::Absent`].
    fn peek(&self, workspace_id: &str, key: &str) -> EntryState;

    /// Atomically take `(workspace_id, key)` for `lease_secs`, or
    /// report what is already there.
    ///
    /// A claim whose lease has run out is takeable; the implementation
    /// reports that as `took_over` so the takeover rate is visible.
    fn try_claim(&self, workspace_id: &str, key: &str, lease_secs: u64) -> TryClaim;

    /// Publish `response` under a claim this caller still holds.
    ///
    /// Refused, silently but counted, when the stored claim no longer
    /// carries `claim.owner()`: that owner was superseded after its
    /// lease lapsed, and the response it is holding answers a request
    /// nobody is waiting for any more.
    fn complete(&self, claim: &IdempotencyClaim, response: CachedResponse);

    /// Release a claim this caller holds without publishing anything,
    /// so the next request can take the key immediately.
    ///
    /// A no-op when the claim was already superseded.
    fn release(&self, claim: &IdempotencyClaim);

    /// Short, closed-set name of this backend, used as the `backend`
    /// label on the idempotency metrics.
    ///
    /// The label was the literal `"default"` at every recording site, so
    /// a deployment running one origin on `memory` and another on `redis`
    /// rendered both as one series and an unreachable Redis was
    /// indistinguishable from normal cold traffic.
    fn backend_label(&self) -> &'static str;
}

// --- Body hashing ---

/// SHA-256 hash a request body for the idempotency-conflict check.
///
/// Empty bodies hash to the SHA-256 of the empty string; that is fine
/// because a retry with an empty body produces the same hash.
pub fn hash_body(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(body);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(out.as_slice());
    buf
}

// --- Header extraction ---

/// Extract the `Idempotency-Key` header value, trimmed.
///
/// Returns `None` when the header is absent or empty after trim.
pub fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(IDEMPOTENCY_KEY_HEADER)?;
    let s = v.to_str().ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// --- Claiming ---

/// Take `(workspace_id, key)`, or report what is already there.
///
/// The free function rather than a trait method because the returned
/// [`IdempotencyClaim`] releases itself on drop and therefore has to own
/// a handle to the cache.
pub fn claim(
    cache: &Arc<dyn IdempotencyCache>,
    workspace_id: &str,
    key: &str,
    lease_secs: u64,
) -> ClaimState {
    let backend = cache.backend_label();
    let lease = if lease_secs == 0 {
        DEFAULT_CLAIM_LEASE_SECS
    } else {
        lease_secs
    };
    match cache.try_claim(workspace_id, key, lease) {
        TryClaim::Claimed { owner, took_over } => {
            sbproxy_observe::metrics::record_idempotency_cache_result(
                backend,
                if took_over { "takeover" } else { "claimed" },
            );
            ClaimState::Claimed(IdempotencyClaim {
                cache: Arc::clone(cache),
                workspace_id: workspace_id.to_string(),
                key: key.to_string(),
                owner,
                published: false,
            })
        }
        TryClaim::InFlight {
            lease_expires_at_unix,
        } => {
            sbproxy_observe::metrics::record_idempotency_cache_result(backend, "in_flight");
            ClaimState::InFlight {
                lease_expires_at_unix,
            }
        }
        TryClaim::Completed(response) => ClaimState::Completed(response),
    }
}

/// Wait for the request holding `key` to publish its response.
///
/// Returns the published response, or `None` when the budget runs out or
/// the holder vanished without publishing. `None` is a 409 at the call
/// site, never a pass through to the upstream: a follower that reached
/// here has already drained its request body and has nothing left to
/// send.
///
/// The poll runs on a blocking thread rather than on the caller's. A
/// shared backend's read is a network round trip, and a proxy worker
/// that blocks on one stops serving every other connection assigned to
/// it.
pub async fn await_completion(
    cache: &Arc<dyn IdempotencyCache>,
    workspace_id: &str,
    key: &str,
    budget: Duration,
) -> Option<CachedResponse> {
    let backend = cache.backend_label();
    let deadline = std::time::Instant::now() + budget;
    let mut interval = WAIT_POLL_MIN;
    loop {
        let state = {
            let cache = Arc::clone(cache);
            let workspace_id = workspace_id.to_string();
            let key = key.to_string();
            match tokio::task::spawn_blocking(move || cache.peek(&workspace_id, &key)).await {
                Ok(state) => state,
                // The blocking pool is gone or the task panicked. Treat
                // it as "cannot tell", which is the same answer as a
                // wait that ran out.
                Err(_) => EntryState::Absent,
            }
        };
        match state {
            EntryState::Completed(response) => {
                sbproxy_observe::metrics::record_idempotency_cache_result(backend, "coalesced");
                return Some(*response);
            }
            // The holder released without publishing, or its lease
            // lapsed. Either way there is no response coming and this
            // request cannot produce one.
            EntryState::Absent => {
                sbproxy_observe::metrics::record_idempotency_cache_result(backend, "wait_timeout");
                return None;
            }
            EntryState::InFlight { .. } => {}
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            sbproxy_observe::metrics::record_idempotency_cache_result(backend, "wait_timeout");
            return None;
        }
        let nap = interval.min(deadline.saturating_duration_since(now));
        tokio::time::sleep(nap).await;
        interval = (interval * 2).min(WAIT_POLL_MAX);
    }
}

// --- Middleware entry point ---

/// Inspect the inbound request and decide which branch of the
/// idempotency flow applies, taking the key when nothing holds it.
///
/// The caller passes the workspace id (already resolved by the auth
/// chain), the request headers, and the request body. This is the
/// entry point for callers that already have the whole body in hand;
/// the streaming proxy path claims in `request_filter` before the body
/// exists and hashes later.
///
/// A follower that finds a live claim waits up to `wait` for the
/// holder's response and replays it when the bodies match.
pub async fn check_request(
    cache: &Arc<dyn IdempotencyCache>,
    workspace_id: &str,
    headers: &HeaderMap,
    body: &[u8],
    lease_secs: u64,
    wait: Duration,
) -> IdempotencyOutcome {
    let backend = cache.backend_label();
    let Some(key) = extract_idempotency_key(headers) else {
        sbproxy_observe::metrics::record_idempotency_cache_result(backend, "not_applicable");
        return IdempotencyOutcome::NotApplicable;
    };

    let body_hash = hash_body(body);
    let start = std::time::Instant::now();
    let claimed = claim(cache, workspace_id, &key, lease_secs);
    let elapsed = start.elapsed().as_secs_f64();
    sbproxy_observe::metrics::record_idempotency_cache_duration(backend, elapsed);

    let stored = match claimed {
        ClaimState::Claimed(claim) => {
            sbproxy_observe::metrics::record_idempotency_cache_result(backend, "miss");
            return IdempotencyOutcome::Miss { body_hash, claim };
        }
        ClaimState::Completed(stored) => *stored,
        ClaimState::InFlight { .. } => {
            match await_completion(cache, workspace_id, &key, wait).await {
                Some(stored) => stored,
                None => return IdempotencyOutcome::InFlight,
            }
        }
    };

    if stored.request_body_hash == body_hash {
        sbproxy_observe::metrics::record_idempotency_cache_result(backend, "hit");
        IdempotencyOutcome::CacheHit(Box::new(stored))
    } else {
        sbproxy_observe::metrics::record_idempotency_cache_result(backend, "conflict");
        IdempotencyOutcome::Conflict
    }
}

/// Captured response payload, supplied to [`record_response`] after
/// the handler chain finishes processing a claimed request.
///
/// Grouped into a struct so the public surface stays under
/// `clippy::too_many_arguments` while keeping every required field
/// explicit at call sites.
#[derive(Debug, Clone)]
pub struct RecordedResponse {
    /// HTTP status code as a `u16`.
    pub status: u16,
    /// Response headers as flat name / value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body. May be empty.
    pub body: Vec<u8>,
    /// SHA-256 hash of the original request body.
    pub body_hash: [u8; 32],
    /// TTL in seconds. Zero is normalised to [`DEFAULT_TTL_SECS`] so a
    /// caller misconfig does not flip the row to permanently expired.
    pub ttl_secs: u64,
}

/// Publish the response captured after the handler chain finishes
/// processing a claimed request, and release the claim.
///
/// Consumes the claim: publishing is the one way out of a claim that
/// does not release the key, and taking it by value is what makes that
/// a compile-time fact rather than a convention.
pub fn record_response(mut claim: IdempotencyClaim, recorded: RecordedResponse) {
    let ttl = if recorded.ttl_secs == 0 {
        DEFAULT_TTL_SECS
    } else {
        recorded.ttl_secs
    };
    let expires_at_unix = now_unix().saturating_add(ttl);
    let resp = CachedResponse {
        status: recorded.status,
        headers: recorded.headers,
        body: recorded.body,
        request_body_hash: recorded.body_hash,
        expires_at_unix,
    };
    claim.cache.complete(&claim, resp);
    // Set after the publish, not before: `complete` may refuse a
    // superseded claim, and a claim that was refused is not this
    // caller's to release either. The successor owns the key now.
    claim.published = true;
}

/// Build the 409 conflict body:
/// `{"error":"ledger.idempotency_conflict", ...}`.
///
/// Returned as `(status, content_type, body_bytes)` so the calling
/// handler can stamp a response without depending on a particular
/// HTTP framework type.
pub fn conflict_response() -> (StatusCode, &'static str, Vec<u8>) {
    let body = serde_json::json!({
        "error": "ledger.idempotency_conflict",
        "message": "Idempotency-Key already used with a different request body.",
    });
    (
        StatusCode::CONFLICT,
        "application/json",
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

/// Build the 409 in-flight body:
/// `{"error":"ledger.idempotency_in_flight", ...}`.
///
/// The answer to a retry that arrived while the original request is
/// still being processed and did not finish inside the wait budget.
/// `draft-ietf-httpapi-idempotency-key-header` names 409 for this case;
/// the distinct error code is so a client can tell "retry this in a
/// moment" from "you reused a key with a different body", which are the
/// same status and opposite instructions.
pub fn in_flight_response() -> (StatusCode, &'static str, Vec<u8>) {
    let body = serde_json::json!({
        "error": "ledger.idempotency_in_flight",
        "message": "A request with this Idempotency-Key is still being processed. Retry with the same key.",
    });
    (
        StatusCode::CONFLICT,
        "application/json",
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

// --- Helpers ---

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A fresh fencing token.
///
/// 128 bits from the system CSPRNG. It is a fence, not a secret, but it
/// has to be unguessable enough that two claims never collide across a
/// fleet, and a counter would collide the first time two nodes restarted
/// together.
fn new_owner_token() -> u128 {
    use ring::rand::SecureRandom as _;
    let mut buf = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut buf).is_err() {
        // The CSPRNG is unavailable, which on every supported platform
        // means the process is in no shape to serve traffic. Fall back
        // to a clock-plus-address token rather than panicking on a
        // request path: it is weaker than random but still unique
        // enough that this claim does not silently share a fence with
        // another.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        return nanos ^ ((&buf as *const u8 as u128) << 64);
    }
    u128::from_be_bytes(buf)
}

/// The fencing token, on the wire.
///
/// A `u128` cannot round-trip through an internally tagged enum: serde
/// buffers the variant's fields into its `Content` type to find the tag
/// first, and `Content` has no 128-bit case, so the value serializes and
/// then fails to deserialize. That failure is silent in the shape that
/// matters here (a row that will not parse reads as an absent key, and
/// an absent key is claimable by everyone), so the token travels as
/// zero-padded hex instead. It also reads better than a 39-digit integer
/// when an operator pulls the row out of Redis by hand.
mod owner_hex {
    pub(super) fn serialize<S: serde::Serializer>(
        value: &u128,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:032x}"))
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<u128, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        u128::from_str_radix(&raw, 16).map_err(serde::de::Error::custom)
    }
}

/// One row in a backend: a claim, or the response that answered it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StoredEntry {
    /// A request holds this key until `lease_expires_at_unix`.
    InFlight {
        #[serde(with = "owner_hex")]
        owner: u128,
        lease_expires_at_unix: u64,
    },
    /// The response that request produced.
    Completed(CachedResponse),
}

impl StoredEntry {
    /// The read-only view, with expiry applied.
    fn state(&self, now: u64) -> EntryState {
        match self {
            StoredEntry::Completed(response) if response.expires_at_unix > now => {
                EntryState::Completed(Box::new(response.clone()))
            }
            StoredEntry::InFlight {
                lease_expires_at_unix,
                ..
            } if *lease_expires_at_unix > now => EntryState::InFlight {
                lease_expires_at_unix: *lease_expires_at_unix,
            },
            _ => EntryState::Absent,
        }
    }

    /// Whether this row is still live at `now`. A dead row is takeable.
    fn is_live(&self, now: u64) -> bool {
        !matches!(self.state(now), EntryState::Absent)
    }
}

// --- In-memory cache ---

/// Default cap on the in-memory idempotency map (WOR-1693). Idempotency
/// keys are unique per logical request and, before this bound, were only
/// evicted when the same key was re-read, so the memory backend grew
/// without limit under normal traffic (each entry holds a full response
/// body). The bound is a 100,000-entry cap; overflow evicts the
/// least-recently-used entry, whose only effect is
/// that a replay of that key past the cap re-executes instead of
/// serving from cache, the same as after a restart.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// In-memory [`IdempotencyCache`] for tests and single-instance
/// deployments. Backed by a bounded LRU keyed by `(workspace_id, key)`.
/// Entries are evicted lazily on read after they expire, and the LRU
/// cap bounds total memory regardless of expiry.
///
/// Claims and completed responses share one map under one mutex, which
/// is what makes [`Self::try_claim`] atomic: read, decide, and write
/// happen without releasing the lock, so two threads racing the same
/// key cannot both come away owning it. The lock is never held across
/// an await, and nothing inside it allocates unboundedly.
pub struct InMemoryIdempotencyCache {
    inner: parking_lot::Mutex<lru::LruCache<(String, String), StoredEntry>>,
}

impl Default for InMemoryIdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryIdempotencyCache {
    /// Build an empty cache with the default entry cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Build an empty cache with an explicit entry cap (>= 1).
    pub fn with_capacity(max_entries: usize) -> Self {
        let cap =
            std::num::NonZeroUsize::new(max_entries.max(1)).expect("max_entries.max(1) is nonzero");
        Self {
            inner: parking_lot::Mutex::new(lru::LruCache::new(cap)),
        }
    }
}

impl IdempotencyCache for InMemoryIdempotencyCache {
    fn peek(&self, workspace_id: &str, key: &str) -> EntryState {
        let now = now_unix();
        let key_pair = (workspace_id.to_string(), key.to_string());
        let mut guard = self.inner.lock();
        // Read-side eviction: drop dead rows on access so a slow
        // sweeper does not let a stale response replay or a lapsed
        // claim keep answering 409. `get` also marks the entry
        // most-recently-used so the LRU cap evicts cold keys.
        match guard.get(&key_pair) {
            Some(entry) if entry.is_live(now) => entry.state(now),
            Some(_) => {
                guard.pop(&key_pair);
                EntryState::Absent
            }
            None => EntryState::Absent,
        }
    }

    fn try_claim(&self, workspace_id: &str, key: &str, lease_secs: u64) -> TryClaim {
        let now = now_unix();
        let key_pair = (workspace_id.to_string(), key.to_string());
        let mut guard = self.inner.lock();
        match guard.get(&key_pair) {
            Some(StoredEntry::Completed(response)) if response.expires_at_unix > now => {
                return TryClaim::Completed(Box::new(response.clone()));
            }
            Some(StoredEntry::InFlight {
                lease_expires_at_unix,
                ..
            }) if *lease_expires_at_unix > now => {
                return TryClaim::InFlight {
                    lease_expires_at_unix: *lease_expires_at_unix,
                };
            }
            _ => {}
        }
        // Absent, an expired response, or a claim whose holder never
        // came back. All three are takeable, and the whole read-decide-
        // write sits inside one lock so only one caller takes it.
        let took_over = matches!(guard.peek(&key_pair), Some(StoredEntry::InFlight { .. }));
        let owner = new_owner_token();
        guard.put(
            key_pair,
            StoredEntry::InFlight {
                owner,
                lease_expires_at_unix: now.saturating_add(lease_secs),
            },
        );
        TryClaim::Claimed { owner, took_over }
    }

    fn complete(&self, claim: &IdempotencyClaim, response: CachedResponse) {
        let key_pair = (claim.workspace_id.clone(), claim.key.clone());
        let mut guard = self.inner.lock();
        match guard.peek(&key_pair) {
            Some(StoredEntry::InFlight { owner, .. }) if *owner == claim.owner => {
                guard.put(key_pair, StoredEntry::Completed(response));
            }
            // Superseded: this owner's lease lapsed and another request
            // took the key. Its answer, not ours, is the one waiters are
            // owed.
            _ => {
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "fenced",
                );
            }
        }
    }

    fn release(&self, claim: &IdempotencyClaim) {
        let key_pair = (claim.workspace_id.clone(), claim.key.clone());
        let mut guard = self.inner.lock();
        if matches!(
            guard.peek(&key_pair),
            Some(StoredEntry::InFlight { owner, .. }) if *owner == claim.owner
        ) {
            guard.pop(&key_pair);
        }
    }

    fn backend_label(&self) -> &'static str {
        "memory"
    }
}

// --- KVStore-backed cache (Redis or any other backend) ---

/// [`IdempotencyCache`] backed by any `KVStore` implementation. In OSS
/// deployments this is typically Redis (via `RedisKVStore` from
/// `sbproxy-platform`); in single-instance deployments operators may
/// point this at the embedded redb store.
///
/// Unlike [`InMemoryIdempotencyCache`], which is allocated once per
/// origin, this backend wraps the single cluster-wide `proxy.l2_store`
/// that every origin on every node shares. Isolation therefore has to be
/// in the key: the storage key carries the owning origin's tenant and
/// origin id, supplied at construction, ahead of the workspace id and the
/// caller-supplied `Idempotency-Key`.
///
/// Every segment is length-delimited (`<len>:<bytes>`) rather than merely
/// joined with `:`, because both the operator-supplied ids and the
/// client-supplied key may contain a colon. Without the length prefix,
/// tenant `a:b` with key `c` and tenant `a` with key `b:c` produce the
/// same string, which is a cross-tenant read for anyone who can pick
/// their own `Idempotency-Key`.
///
/// # What this backend cannot do on every store
///
/// Single-flight rests on `put_if_absent_with_ttl`, which is Redis's
/// `SET NX EX`. A `KVStore` that cannot create a key atomically cannot
/// serialize two simultaneous first requests, and there is no way to
/// build that guarantee on top of a non-atomic store. Rather than
/// pretend, this backend notices the first refusal, warns once naming
/// the store, counts every affected request under
/// `result="single_flight_unsupported"`, and falls back to the
/// pre-WOR-2609 behavior: replay still works, overlapping first
/// requests all reach the upstream. The memory and Redis stores both
/// implement it.
pub struct KvIdempotencyCache {
    store: Arc<dyn KVStore>,
    ttl_secs: u64,
    /// Precomputed `sbproxy:idem:<len>:<tenant>:<len>:<origin>` prefix.
    /// Built once so the request path only appends.
    key_prefix: String,
    /// Cleared the first time the store refuses an atomic create.
    single_flight: std::sync::atomic::AtomicBool,
    /// Guards the one-time warning about that refusal.
    warned: std::sync::Once,
}

/// Append one length-delimited segment to a storage key.
///
/// The length prefix is what makes the boundary unambiguous when a
/// segment contains the separator; see [`KvIdempotencyCache`].
fn push_key_segment(out: &mut String, segment: &str) {
    use std::fmt::Write as _;
    // Writing to a String is infallible; the Result exists only to
    // satisfy the trait.
    let _ = write!(out, ":{}:{segment}", segment.len());
}

/// Parse one stored row.
///
/// The fallback is a rolling upgrade: a node still running the previous
/// build writes a bare `CachedResponse`, and a node running this one has
/// to read it as a completed entry rather than as a corrupt row it would
/// then overwrite with a second upstream call.
fn parse_entry(raw: &[u8]) -> Option<StoredEntry> {
    if let Ok(entry) = serde_json::from_slice::<StoredEntry>(raw) {
        return Some(entry);
    }
    serde_json::from_slice::<CachedResponse>(raw)
        .ok()
        .map(StoredEntry::Completed)
}

impl KvIdempotencyCache {
    /// Build a new cache wrapping `store` for one origin.
    ///
    /// `tenant_id` and `origin_id` come from the compiled origin and
    /// namespace every key this instance writes, so two origins sharing
    /// one Redis cannot read or overwrite each other's entries.
    ///
    /// `ttl_secs` is the value a published response is stored under;
    /// a claim is stored under its own, much shorter, lease instead.
    pub fn new(store: Arc<dyn KVStore>, ttl_secs: u64, tenant_id: &str, origin_id: &str) -> Self {
        let ttl = if ttl_secs == 0 {
            DEFAULT_TTL_SECS
        } else {
            ttl_secs
        };
        let mut key_prefix = String::from("sbproxy:idem");
        push_key_segment(&mut key_prefix, tenant_id);
        push_key_segment(&mut key_prefix, origin_id);
        Self {
            store,
            ttl_secs: ttl,
            key_prefix,
            single_flight: std::sync::atomic::AtomicBool::new(true),
            warned: std::sync::Once::new(),
        }
    }

    fn build_key(&self, workspace_id: &str, key: &str) -> String {
        let mut out =
            String::with_capacity(self.key_prefix.len() + workspace_id.len() + key.len() + 16);
        out.push_str(&self.key_prefix);
        push_key_segment(&mut out, workspace_id);
        push_key_segment(&mut out, key);
        out
    }

    fn single_flight_available(&self) -> bool {
        self.single_flight
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record, once, that this store cannot serialize concurrent first
    /// requests, and keep counting every request it affects.
    fn note_no_atomic_create(&self) {
        self.single_flight
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.warned.call_once(|| {
            tracing::warn!(
                prefix = %self.key_prefix,
                "idempotency: this l2_store has no atomic create, so two simultaneous first \
                 requests with one key will both reach the upstream; replay and conflict \
                 detection still work. Use redis for cluster-wide single-flight."
            );
        });
        sbproxy_observe::metrics::record_idempotency_cache_result(
            self.backend_label(),
            "single_flight_unsupported",
        );
    }

    /// The claim a degraded store can still hand out: unfenced, and
    /// counted so an operator can see it happening.
    fn unfenced_claim(&self) -> TryClaim {
        TryClaim::Claimed {
            owner: new_owner_token(),
            took_over: false,
        }
    }
}

impl IdempotencyCache for KvIdempotencyCache {
    fn peek(&self, workspace_id: &str, key: &str) -> EntryState {
        let storage_key = self.build_key(workspace_id, key);
        let raw = match self.store.get(storage_key.as_bytes()) {
            Ok(Some(raw)) => raw,
            Ok(None) => return EntryState::Absent,
            Err(_) => {
                // A store-side failure degrades to "nothing here" so the
                // request still flows, but it is counted separately:
                // folded into `miss` it was indistinguishable from
                // normal cold traffic, and an unreachable Redis meant
                // every request silently re-executed against the
                // upstream.
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "error",
                );
                return EntryState::Absent;
            }
        };
        let Some(entry) = parse_entry(&raw) else {
            return EntryState::Absent;
        };
        let now = now_unix();
        if !entry.is_live(now) {
            // Best-effort eviction: ignore errors because the
            // sweeper / TTL expiry will catch it eventually.
            let _ = self.store.delete(storage_key.as_bytes());
            return EntryState::Absent;
        }
        entry.state(now)
    }

    fn try_claim(&self, workspace_id: &str, key: &str, lease_secs: u64) -> TryClaim {
        let storage_key = self.build_key(workspace_id, key);
        // Bounded retries. Each turn either answers or loses one race,
        // and losing three in a row means another request is making
        // progress on this key, which is the answer a follower wants.
        for _ in 0..3 {
            let now = now_unix();
            let current = match self.store.get(storage_key.as_bytes()) {
                Ok(current) => current,
                Err(_) => {
                    sbproxy_observe::metrics::record_idempotency_cache_result(
                        self.backend_label(),
                        "error",
                    );
                    return self.unfenced_claim();
                }
            };
            match current.as_deref().and_then(parse_entry) {
                Some(StoredEntry::Completed(response)) if response.expires_at_unix > now => {
                    return TryClaim::Completed(Box::new(response));
                }
                Some(StoredEntry::InFlight {
                    lease_expires_at_unix,
                    ..
                }) if lease_expires_at_unix > now => {
                    return TryClaim::InFlight {
                        lease_expires_at_unix,
                    };
                }
                _ => {}
            }

            let owner = new_owner_token();
            let mine = StoredEntry::InFlight {
                owner,
                lease_expires_at_unix: now.saturating_add(lease_secs),
            };
            let Ok(payload) = serde_json::to_vec(&mine) else {
                return self.unfenced_claim();
            };
            let took_over = current.is_some();
            let taken = match &current {
                // Something dead is there. Swap it out under the exact
                // bytes that were read, so two nodes racing a lapsed
                // lease produce exactly one winner.
                Some(raw) => self.store.compare_and_swap_with_ttl(
                    storage_key.as_bytes(),
                    raw,
                    &payload,
                    lease_secs,
                ),
                None => {
                    self.store
                        .put_if_absent_with_ttl(storage_key.as_bytes(), &payload, lease_secs)
                }
            };
            match taken {
                Ok(true) => return TryClaim::Claimed { owner, took_over },
                // Lost the race. Re-read: the winner may already have
                // published, in which case this caller replays instead
                // of waiting.
                Ok(false) => continue,
                Err(_) => {
                    // Either the store has no atomic create, or it
                    // failed. Both mean this claim is unfenced.
                    self.note_no_atomic_create();
                    return self.unfenced_claim();
                }
            }
        }
        TryClaim::InFlight {
            lease_expires_at_unix: now_unix().saturating_add(lease_secs),
        }
    }

    fn complete(&self, claim: &IdempotencyClaim, response: CachedResponse) {
        let storage_key = self.build_key(&claim.workspace_id, &claim.key);
        let Ok(payload) = serde_json::to_vec(&StoredEntry::Completed(response)) else {
            return;
        };
        if !self.single_flight_available() {
            // Degraded store: there was no fence to hold, so an
            // unconditional write is the honest publish rather than a
            // compare-and-swap that can only ever fail.
            if self
                .store
                .put_with_ttl(storage_key.as_bytes(), &payload, self.ttl_secs)
                .is_err()
                && self.store.put(storage_key.as_bytes(), &payload).is_err()
            {
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "error",
                );
            }
            return;
        }
        let current = match self.store.get(storage_key.as_bytes()) {
            Ok(current) => current,
            Err(_) => {
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "error",
                );
                return;
            }
        };
        let still_ours = matches!(
            current.as_deref().and_then(parse_entry),
            Some(StoredEntry::InFlight { owner, .. }) if owner == claim.owner
        );
        if !still_ours {
            // This owner stalled past its lease and somebody else took
            // the key. Publishing now would overwrite the successor's
            // answer with one nobody is waiting for.
            sbproxy_observe::metrics::record_idempotency_cache_result(
                self.backend_label(),
                "fenced",
            );
            return;
        }
        let Some(raw) = current else {
            return;
        };
        match self.store.compare_and_swap_with_ttl(
            storage_key.as_bytes(),
            &raw,
            &payload,
            self.ttl_secs,
        ) {
            Ok(true) => {}
            // Lost between the read and the swap: the same fence, one
            // instant later.
            Ok(false) => {
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "fenced",
                );
            }
            Err(_) => {
                sbproxy_observe::metrics::record_idempotency_cache_result(
                    self.backend_label(),
                    "error",
                );
            }
        }
    }

    fn release(&self, claim: &IdempotencyClaim) {
        let storage_key = self.build_key(&claim.workspace_id, &claim.key);
        let Ok(Some(raw)) = self.store.get(storage_key.as_bytes()) else {
            return;
        };
        let still_ours = matches!(
            parse_entry(&raw),
            Some(StoredEntry::InFlight { owner, .. }) if owner == claim.owner
        );
        if !still_ours {
            return;
        }
        // Swap to an already-lapsed claim rather than deleting, because
        // a delete is unconditional: between reading the row and
        // deleting it, another node can take the key over, and a bare
        // delete would then throw away a live claim. The compare-and-
        // swap can only replace the exact bytes that were read, and the
        // row it leaves is immediately takeable by anyone.
        let lapsed = StoredEntry::InFlight {
            owner: claim.owner,
            lease_expires_at_unix: 0,
        };
        let Ok(payload) = serde_json::to_vec(&lapsed) else {
            return;
        };
        let _ = self.store.compare_and_swap_with_ttl(
            storage_key.as_bytes(),
            &raw,
            &payload,
            self.ttl_secs,
        );
    }

    fn backend_label(&self) -> &'static str {
        "kv"
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn h(headers: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in headers {
            m.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    fn memory() -> Arc<dyn IdempotencyCache> {
        Arc::new(InMemoryIdempotencyCache::new())
    }

    const LEASE: u64 = 60;
    fn wait() -> Duration {
        Duration::from_secs(5)
    }

    /// Claim, then publish, in one step. The shape a handler has when it
    /// already knows the response.
    fn claim_and_publish(
        cache: &Arc<dyn IdempotencyCache>,
        workspace: &str,
        key: &str,
        body: &[u8],
        response: &[u8],
        status: u16,
        ttl_secs: u64,
    ) {
        let ClaimState::Claimed(held) = claim(cache, workspace, key, LEASE) else {
            panic!("expected to take {key}");
        };
        record_response(
            held,
            RecordedResponse {
                status,
                headers: vec![],
                body: response.to_vec(),
                body_hash: hash_body(body),
                ttl_secs,
            },
        );
    }

    #[tokio::test]
    async fn idempotency_cache_miss_persists_response() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "abc-123")]);
        let body = b"{\"hello\":\"world\"}";

        let outcome = check_request(&cache, "ws_a", &headers, body, LEASE, wait()).await;
        let (claim_held, body_hash) = match outcome {
            IdempotencyOutcome::Miss { claim, body_hash } => (claim, body_hash),
            other => panic!("expected Miss, got {other:?}"),
        };

        record_response(
            claim_held,
            RecordedResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: b"{\"ok\":true}".to_vec(),
                body_hash,
                ttl_secs: DEFAULT_TTL_SECS,
            },
        );

        // Retry: same key, same body => cache hit.
        match check_request(&cache, "ws_a", &headers, body, LEASE, wait()).await {
            IdempotencyOutcome::CacheHit(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body, b"{\"ok\":true}");
            }
            other => panic!("expected CacheHit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn idempotency_cache_hit_returns_cached_response_no_rate_limit_consumption() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "k1")]);
        let body = b"payload";
        claim_and_publish(&cache, "ws_a", "k1", body, b"created", 201, 60);

        // The outcome must be a CacheHit so the rate-limit middleware
        // reads `is_cache_hit() == true` and skips token bucket
        // consumption per A3.4 / A2.5.
        let outcome = check_request(&cache, "ws_a", &headers, body, LEASE, wait()).await;
        assert!(
            outcome.is_cache_hit(),
            "cache hit must signal rate-limit-skip"
        );
        assert!(!outcome.is_conflict());
    }

    #[tokio::test]
    async fn idempotency_cache_hit_with_different_body_returns_409_does_consume_rate_limit() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "k2")]);
        claim_and_publish(&cache, "ws_a", "k2", b"body-A", b"", 200, 60);

        // Retry with body B: same key, different body => Conflict.
        let outcome = check_request(&cache, "ws_a", &headers, b"body-B", LEASE, wait()).await;
        assert!(
            outcome.is_conflict(),
            "differing body must surface as Conflict so rate-limit consumes a slot"
        );
        assert!(!outcome.is_cache_hit());

        let (status, ct, body) = conflict_response();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "ledger.idempotency_conflict");
    }

    #[tokio::test]
    async fn idempotency_ttl_expiry_treats_as_cache_miss() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "expiring-key")]);

        // A row whose response expired an epoch ago.
        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"old".to_vec(),
            request_body_hash: hash_body(b"x"),
            expires_at_unix: 1, // 1970-01-01
        };
        let ClaimState::Claimed(held) = claim(&cache, "ws_a", "expiring-key", LEASE) else {
            panic!("expected to take the key");
        };
        cache.complete(&held, stale);
        std::mem::forget(held);

        match check_request(&cache, "ws_a", &headers, b"x", LEASE, wait()).await {
            IdempotencyOutcome::Miss { .. } => {}
            other => panic!("expired row must read as Miss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn idempotency_no_header_passes_through() {
        let cache = memory();
        let headers = HeaderMap::new();
        let outcome = check_request(&cache, "ws_a", &headers, b"x", LEASE, wait()).await;
        assert!(matches!(outcome, IdempotencyOutcome::NotApplicable));
        assert!(!outcome.is_cache_hit());
        assert!(!outcome.is_conflict());
    }

    #[tokio::test]
    async fn idempotency_workspaces_isolated() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "shared")]);
        claim_and_publish(&cache, "ws_a", "shared", b"a", b"", 200, 60);

        // Same key under a different workspace must miss, and must not
        // wait on ws_a's claim either.
        match check_request(&cache, "ws_b", &headers, b"a", LEASE, wait()).await {
            IdempotencyOutcome::Miss { .. } => {}
            other => panic!("ws_b must miss; cache must isolate per workspace, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn idempotency_empty_header_value_is_passthrough() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "")]);
        let outcome = check_request(&cache, "ws_a", &headers, b"x", LEASE, wait()).await;
        // Empty string is not a usable key; treat as NotApplicable.
        assert!(matches!(outcome, IdempotencyOutcome::NotApplicable));
    }

    #[test]
    fn cached_response_round_trips_serde() {
        let resp = CachedResponse {
            status: 201,
            headers: vec![("x-custom".to_string(), "v".to_string())],
            body: b"payload".to_vec(),
            request_body_hash: hash_body(b"req"),
            expires_at_unix: 99_999_999,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: CachedResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(resp, back);
    }

    // --- WOR-2609: single flight ---

    /// The defect this ticket exists for. Fifty overlapping retries of
    /// one payment POST all used to miss, all reach the upstream, and
    /// all charge the card, because the lookup and the store were
    /// independent and nothing said "somebody is already doing this".
    ///
    /// One upstream call, forty-nine identical replies, and no client
    /// gets an error. Without the claim this asserts 50 == 1 and fails
    /// on the first line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fifty_concurrent_first_requests_make_one_upstream_call() {
        let cache = memory();
        let upstream_calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(tokio::sync::Barrier::new(50));
        let mut tasks = Vec::new();

        for _ in 0..50 {
            let cache = Arc::clone(&cache);
            let upstream_calls = Arc::clone(&upstream_calls);
            let start = Arc::clone(&start);
            tasks.push(tokio::spawn(async move {
                let headers = h(&[("Idempotency-Key", "order-1234")]);
                let body = b"{\"amount\":4200}";
                start.wait().await;
                match check_request(&cache, "ws", &headers, body, LEASE, wait()).await {
                    IdempotencyOutcome::Miss { claim, body_hash } => {
                        upstream_calls.fetch_add(1, Ordering::SeqCst);
                        // Stand in for the upstream round trip, so the
                        // followers really do have to wait rather than
                        // racing past an instant publish.
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        record_response(
                            claim,
                            RecordedResponse {
                                status: 201,
                                headers: vec![],
                                body: b"charged".to_vec(),
                                body_hash,
                                ttl_secs: 60,
                            },
                        );
                        "owner"
                    }
                    IdempotencyOutcome::CacheHit(response) => {
                        assert_eq!(response.body, b"charged");
                        assert_eq!(response.status, 201);
                        "replay"
                    }
                    IdempotencyOutcome::Conflict => "conflict",
                    IdempotencyOutcome::InFlight => "in_flight",
                    IdempotencyOutcome::NotApplicable => "not_applicable",
                }
            }));
        }

        let mut owners = 0;
        let mut replays = 0;
        let mut other = Vec::new();
        for task in tasks {
            match task.await.expect("task joins") {
                "owner" => owners += 1,
                "replay" => replays += 1,
                label => other.push(label),
            }
        }

        assert_eq!(
            upstream_calls.load(Ordering::SeqCst),
            1,
            "fifty overlapping retries reached the upstream more than once"
        );
        assert_eq!(owners, 1);
        assert_eq!(
            replays, 49,
            "every follower must get the owner's response, not an error: {other:?}"
        );
    }

    /// The same, over the single cluster-wide store two nodes share.
    /// The memory backend is atomic because one mutex covers it; this
    /// one has to get there through the store's atomic create, which is
    /// the half that governs a real Redis deployment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_requests_on_a_shared_store_make_one_upstream_call() {
        let store = shared_store();
        let cache: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "tenant-a", "a.example"));
        let upstream_calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let upstream_calls = Arc::clone(&upstream_calls);
            let start = Arc::clone(&start);
            tasks.push(tokio::spawn(async move {
                let headers = h(&[("Idempotency-Key", "order-1234")]);
                let body = b"{\"amount\":4200}";
                start.wait().await;
                match check_request(&cache, "", &headers, body, LEASE, wait()).await {
                    IdempotencyOutcome::Miss { claim, body_hash } => {
                        upstream_calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        record_response(
                            claim,
                            RecordedResponse {
                                status: 201,
                                headers: vec![],
                                body: b"charged".to_vec(),
                                body_hash,
                                ttl_secs: 60,
                            },
                        );
                        "owner"
                    }
                    IdempotencyOutcome::CacheHit(response) => {
                        assert_eq!(response.body, b"charged");
                        "replay"
                    }
                    other => panic!("unexpected outcome {other:?}"),
                }
            }));
        }

        let mut owners = 0;
        for task in tasks {
            if task.await.expect("task joins") == "owner" {
                owners += 1;
            }
        }
        assert_eq!(owners, 1);
        assert_eq!(
            upstream_calls.load(Ordering::SeqCst),
            1,
            "the shared store let more than one request through"
        );
    }

    /// A crashed owner must not wedge its key forever, and a live one
    /// must not be evictable early. Both are the same field read against
    /// the wall clock, so both are asserted here rather than by sleeping
    /// out a real lease.
    #[tokio::test]
    async fn a_crashed_claim_expires_and_the_next_request_takes_it_over() {
        let cache = memory();

        // A live lease is not takeable, and it says when it runs out.
        let ClaimState::Claimed(live) = claim(&cache, "ws", "live", 60) else {
            panic!("expected to take `live`");
        };
        match claim(&cache, "ws", "live", 60) {
            ClaimState::InFlight {
                lease_expires_at_unix,
            } => {
                let now = now_unix();
                assert!(
                    lease_expires_at_unix > now && lease_expires_at_unix <= now + 60,
                    "lease deadline {lease_expires_at_unix} is not now+60 (now {now})"
                );
            }
            other => panic!("a live claim must refuse a second taker, got {other:?}"),
        }
        drop(live);

        // A claim whose holder never came back: the row is still there,
        // its lease has run out. `mem::forget` is the point, not an
        // oversight: a process that died never ran `Drop`.
        let TryClaim::Claimed { owner, .. } = cache.try_claim("ws", "crashed", 0) else {
            panic!("expected to take `crashed`");
        };
        std::mem::forget(IdempotencyClaim {
            cache: Arc::clone(&cache),
            workspace_id: "ws".to_string(),
            key: "crashed".to_string(),
            owner,
            published: false,
        });

        assert_eq!(
            cache.peek("ws", "crashed"),
            EntryState::Absent,
            "a lapsed claim must not keep answering in-flight"
        );
        match claim(&cache, "ws", "crashed", 60) {
            ClaimState::Claimed(_) => {}
            other => panic!("a lapsed claim must be takeable, got {other:?}"),
        }
    }

    /// Dropping a claim without publishing releases the key on the spot.
    /// Without this, a request that 502s or is cancelled answers 409 to
    /// every retry until its lease runs out, which is a minute of
    /// refusals caused by one failure.
    #[tokio::test]
    async fn a_dropped_claim_releases_the_key_immediately() {
        let cache = memory();
        let ClaimState::Claimed(held) = claim(&cache, "ws", "abandoned", 60) else {
            panic!("expected to take the key");
        };
        assert!(matches!(
            cache.peek("ws", "abandoned"),
            EntryState::InFlight { .. }
        ));
        drop(held);
        assert_eq!(cache.peek("ws", "abandoned"), EntryState::Absent);
        assert!(matches!(
            claim(&cache, "ws", "abandoned", 60),
            ClaimState::Claimed(_)
        ));
    }

    /// An owner that stalls past its lease, wakes up, and publishes must
    /// not overwrite the answer its successor already gave. Nobody is
    /// waiting for the stale one.
    #[tokio::test]
    async fn a_superseded_owner_cannot_overwrite_the_new_response() {
        let cache = memory();
        let TryClaim::Claimed { owner, .. } = cache.try_claim("ws", "k", 0) else {
            panic!("expected to take the key");
        };
        let stale = IdempotencyClaim {
            cache: Arc::clone(&cache),
            workspace_id: "ws".to_string(),
            key: "k".to_string(),
            owner,
            published: false,
        };

        let ClaimState::Claimed(fresh) = claim(&cache, "ws", "k", 60) else {
            panic!("the successor must be able to take the lapsed key");
        };
        record_response(
            fresh,
            RecordedResponse {
                status: 201,
                headers: vec![],
                body: b"fresh".to_vec(),
                body_hash: hash_body(b"body"),
                ttl_secs: 60,
            },
        );

        record_response(
            stale,
            RecordedResponse {
                status: 500,
                headers: vec![],
                body: b"stale".to_vec(),
                body_hash: hash_body(b"body"),
                ttl_secs: 60,
            },
        );

        match cache.peek("ws", "k") {
            EntryState::Completed(response) => {
                assert_eq!(
                    response.body, b"fresh",
                    "the superseded owner overwrote the live response"
                );
            }
            other => panic!("expected the successor's response, got {other:?}"),
        }
    }

    /// A follower whose body differs from the owner's gets the 409 the
    /// RFC describes, not the owner's response, and never reaches an
    /// upstream of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_follower_with_a_different_body_gets_a_conflict() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "k")]);

        let IdempotencyOutcome::Miss { claim, body_hash } =
            check_request(&cache, "ws", &headers, b"body-A", LEASE, wait()).await
        else {
            panic!("expected the first request to take the key");
        };

        let follower = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                let headers = h(&[("Idempotency-Key", "k")]);
                check_request(&cache, "ws", &headers, b"body-B", LEASE, wait())
                    .await
                    .is_conflict()
            })
        };

        tokio::time::sleep(Duration::from_millis(30)).await;
        record_response(
            claim,
            RecordedResponse {
                status: 201,
                headers: vec![],
                body: b"A-was-here".to_vec(),
                body_hash,
                ttl_secs: 60,
            },
        );

        assert!(
            follower.await.expect("follower joins"),
            "a different body must conflict rather than replay somebody else's response"
        );
    }

    /// A follower that waits out its budget gets 409 rather than a
    /// second upstream call. The budget is a millisecond here because
    /// the assertion is about which answer, not about how long.
    #[tokio::test]
    async fn a_wait_that_runs_out_answers_in_flight_not_a_second_call() {
        let cache = memory();
        let headers = h(&[("Idempotency-Key", "slow")]);
        let ClaimState::Claimed(held) = claim(&cache, "ws", "slow", 60) else {
            panic!("expected to take the key");
        };

        let outcome = check_request(
            &cache,
            "ws",
            &headers,
            b"body",
            LEASE,
            Duration::from_millis(1),
        )
        .await;
        assert!(
            matches!(outcome, IdempotencyOutcome::InFlight),
            "expected InFlight, got {outcome:?}; a follower must never fall through to the upstream"
        );

        let (status, ct, body) = in_flight_response();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(ct, "application/json");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["error"], "ledger.idempotency_in_flight");
        drop(held);
    }

    /// One store standing in for the single cluster-wide
    /// `proxy.l2_store` that every redis-backed origin shares. The point
    /// of the tests below is which key each origin writes into it, so an
    /// in-process map is enough.
    fn shared_store() -> Arc<sbproxy_platform::storage::MemoryKVStore> {
        Arc::new(sbproxy_platform::storage::MemoryKVStore::new(0))
    }

    fn kv_cache(
        store: &Arc<sbproxy_platform::storage::MemoryKVStore>,
        tenant: &str,
        origin: &str,
    ) -> KvIdempotencyCache {
        KvIdempotencyCache::new(
            Arc::clone(store) as Arc<dyn KVStore>,
            DEFAULT_TTL_SECS,
            tenant,
            origin,
        )
    }

    #[tokio::test]
    async fn kv_backend_isolates_two_origins_sharing_one_store() {
        // The shape the redis backend actually ships in: both origins
        // wrap the single cluster `proxy.l2_store`. Tenant A POSTs with
        // `Idempotency-Key: order-1234`; tenant B then sends the same key
        // and the same bytes to a different origin and must reach its own
        // upstream rather than replay A's response.
        let store = shared_store();
        let tenant_a: Arc<dyn IdempotencyCache> =
            Arc::new(kv_cache(&store, "tenant-a", "a.example.com"));
        let tenant_b: Arc<dyn IdempotencyCache> =
            Arc::new(kv_cache(&store, "tenant-b", "b.example.com"));
        let headers = h(&[("Idempotency-Key", "order-1234")]);
        let body = b"{\"amt\":10}";

        let IdempotencyOutcome::Miss { claim, body_hash } =
            check_request(&tenant_a, "", &headers, body, LEASE, wait()).await
        else {
            panic!("expected Miss for tenant A");
        };
        record_response(
            claim,
            RecordedResponse {
                status: 200,
                headers: vec![],
                body: b"tenant-a-order".to_vec(),
                body_hash,
                ttl_secs: 60,
            },
        );

        // Same key, same bytes, different origin: a miss, not a replay.
        match check_request(&tenant_b, "", &headers, body, LEASE, wait()).await {
            IdempotencyOutcome::Miss { claim, .. } => drop(claim),
            other => panic!("tenant B must not read tenant A's entry, got {other:?}"),
        }

        // And a differing body is tenant B's own miss, not a 409 for a
        // key it never used.
        match check_request(&tenant_b, "", &headers, b"{\"amt\":99}", LEASE, wait()).await {
            IdempotencyOutcome::Miss { claim, .. } => drop(claim),
            other => panic!("tenant B must not inherit tenant A's conflict, got {other:?}"),
        }

        // Tenant A still replays its own entry, so the namespacing did
        // not simply break the cache.
        assert!(check_request(&tenant_a, "", &headers, body, LEASE, wait())
            .await
            .is_cache_hit());
    }

    /// WOR-2608 held under WOR-2609's claim: a claim is namespaced the
    /// same way a response is, so an in-flight request on one origin
    /// never makes another origin's request wait, and never coalesces
    /// two origins onto one upstream call.
    #[tokio::test]
    async fn two_origins_never_coalesce_onto_one_claim() {
        let store = shared_store();
        let origin_a: Arc<dyn IdempotencyCache> =
            Arc::new(kv_cache(&store, "tenant-a", "a.example.com"));
        let origin_b: Arc<dyn IdempotencyCache> =
            Arc::new(kv_cache(&store, "tenant-b", "b.example.com"));

        let ClaimState::Claimed(held_a) = claim(&origin_a, "", "shared-key", 60) else {
            panic!("origin A must take its own key");
        };
        match claim(&origin_b, "", "shared-key", 60) {
            ClaimState::Claimed(held_b) => drop(held_b),
            other => panic!("origin B must not wait on origin A's claim, got {other:?}"),
        }
        assert!(matches!(
            origin_a.peek("", "shared-key"),
            EntryState::InFlight { .. }
        ));
        drop(held_a);
    }

    #[tokio::test]
    async fn kv_key_segments_cannot_straddle_the_separator() {
        // Length-delimited segments: without them, tenant `a:b` origin
        // `c` and tenant `a` origin `b:c` build the same prefix, and a
        // caller who picks their own `Idempotency-Key` can walk into
        // another namespace by embedding a colon.
        let store = shared_store();
        let straddling: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "a:b", "c"));
        let honest: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "a", "b:c"));
        let headers = h(&[("Idempotency-Key", "k")]);

        let IdempotencyOutcome::Miss { claim, body_hash } =
            check_request(&straddling, "", &headers, b"x", LEASE, wait()).await
        else {
            panic!("expected Miss");
        };
        record_response(
            claim,
            RecordedResponse {
                status: 200,
                headers: vec![],
                body: b"secret".to_vec(),
                body_hash,
                ttl_secs: 60,
            },
        );

        match check_request(&honest, "", &headers, b"x", LEASE, wait()).await {
            IdempotencyOutcome::Miss { claim, .. } => drop(claim),
            other => panic!("colon-shifted ids must not collide, got {other:?}"),
        }
    }

    /// A row written by the previous build is a bare `CachedResponse`
    /// with no `state` tag. During a rolling upgrade an upgraded node
    /// has to replay it, not read it as garbage and call the upstream
    /// again, which would be this ticket's own defect reintroduced by
    /// its fix.
    #[test]
    fn a_row_from_the_previous_build_still_reads_as_completed() {
        let store = shared_store();
        let cache = kv_cache(&store, "tenant-a", "a.example.com");
        let legacy = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"written-by-the-old-build".to_vec(),
            request_body_hash: hash_body(b"x"),
            expires_at_unix: now_unix() + 600,
        };
        let key = cache.build_key("", "legacy");
        store
            .put(key.as_bytes(), &serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        match cache.peek("", "legacy") {
            EntryState::Completed(response) => {
                assert_eq!(response.body, b"written-by-the-old-build");
            }
            other => panic!("a pre-upgrade row must replay, got {other:?}"),
        }
        match cache.try_claim("", "legacy", 60) {
            TryClaim::Completed(response) => {
                assert_eq!(response.body, b"written-by-the-old-build");
            }
            other => panic!("a pre-upgrade row must not be claimable, got {other:?}"),
        }
    }

    #[test]
    fn backend_label_names_the_real_backend() {
        // The `backend` metric label was the literal "default" at every
        // recording site, so the two backends rendered as one series.
        let store = shared_store();
        assert_eq!(InMemoryIdempotencyCache::new().backend_label(), "memory");
        assert_eq!(kv_cache(&store, "t", "o").backend_label(), "kv");
    }

    #[tokio::test]
    async fn check_request_records_under_the_caches_own_backend_label() {
        // The seam, not the recorder: `backend_label` existing proves
        // nothing until `check_request` is the thing that passes it. It
        // used to pass the literal "default" at all five sites, so a
        // deployment running one origin on memory and another on redis
        // rendered both as one series and an unreachable store looked
        // like normal cold traffic.
        //
        // Presence assertions only. The registry is process-global and
        // these counters never decrease, so this holds under a parallel
        // runner where an exact value would not.
        let store = shared_store();
        let kv: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "t", "o"));
        let headers = h(&[("Idempotency-Key", "seam-check")]);
        if let IdempotencyOutcome::Miss { claim, .. } =
            check_request(&memory(), "", &headers, b"{}", LEASE, wait()).await
        {
            drop(claim);
        }
        if let IdempotencyOutcome::Miss { claim, .. } =
            check_request(&kv, "", &headers, b"{}", LEASE, wait()).await
        {
            drop(claim);
        }

        // Scanned line by line rather than with one `contains` over the
        // whole scrape, because the encoder's label order is not this
        // test's business and the `backend` label is on two families.
        let scrape = sbproxy_observe::metrics::metrics().render();
        let rows: Vec<&str> = scrape
            .lines()
            .filter(|line| line.starts_with("sbproxy_idempotency_cache_results_total{"))
            .collect();
        for backend in ["memory", "kv"] {
            let needle = format!("backend=\"{backend}\"");
            assert!(
                rows.iter().any(|row| row.contains(&needle)),
                "check_request did not record under backend={backend}: {rows:?}"
            );
        }
        assert!(
            !rows.iter().any(|row| row.contains("backend=\"default\"")),
            "the constant label is back: {rows:?}"
        );
    }

    #[test]
    fn in_memory_cache_is_bounded_under_unique_keys() {
        // WOR-1693: inserting far past the cap must not grow the cache
        // without bound. Each key is unique (as real idempotency keys
        // are), so before the LRU bound the map grew forever.
        let cap = 8;
        let concrete = Arc::new(InMemoryIdempotencyCache::with_capacity(cap));
        let cache: Arc<dyn IdempotencyCache> = Arc::clone(&concrete) as Arc<dyn IdempotencyCache>;
        let future = now_unix() + 3600;
        for i in 0..1000 {
            let key = format!("key-{i}");
            let TryClaim::Claimed { owner, .. } = cache.try_claim("ws", &key, 60) else {
                panic!("expected to take {key}");
            };
            let held = IdempotencyClaim {
                cache: Arc::clone(&cache),
                workspace_id: "ws".to_string(),
                key: key.clone(),
                owner,
                published: false,
            };
            cache.complete(
                &held,
                CachedResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                    request_body_hash: hash_body(format!("req-{i}").as_bytes()),
                    expires_at_unix: future,
                },
            );
            std::mem::forget(held);
        }
        assert_eq!(concrete.inner.lock().len(), cap);
        // The most-recent key survived; an early evicted key is gone.
        assert!(matches!(
            cache.peek("ws", "key-999"),
            EntryState::Completed(_)
        ));
        assert_eq!(cache.peek("ws", "key-0"), EntryState::Absent);
    }
}
