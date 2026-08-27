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
///
/// # Why this and [`TryClaim`] and [`EntryState`] all exist
///
/// Three enums over what looks like the same three states is the kind
/// of duplicated vocabulary worth arguing about, so here is the
/// argument. They differ in exactly one variant, and that variant's
/// payload is what each type is for:
///
/// * [`EntryState`] answers a read. Its free case is `Absent`, because
///   a reader that finds nothing has found nothing.
/// * [`TryClaim`] answers a backend's take. Its free case carries the
///   fencing token and whether the key was taken over, because those
///   are the two facts only the backend knows and only it can produce.
/// * `ClaimState` answers the caller's take. Its free case carries the
///   RAII handle, which needs an owning `Arc` of the cache that `&self`
///   inside a backend cannot produce.
///
/// Collapsing any pair means one of them carries a variant it can
/// never return: a `peek` that could answer `Claimed`, or a
/// `try_claim` that could answer `Absent`. A nonsense state in the
/// type is worse than three small enums, and a generic `Claim<T>` with
/// two aliases trades two named types for four less-named ones. The
/// duplication is deliberate and this is the note saying so.
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
    /// Release the key, without blocking a proxy worker on a network
    /// round trip to do it.
    ///
    /// A destructor cannot await, so the usual answer here (wrap it in
    /// `spawn_blocking` and await the handle) is not available. What is
    /// available is to *detach* the release: hand it to the blocking
    /// pool and return immediately. The release is a
    /// compare-and-swap-to-lapsed that nothing in this request is
    /// waiting on, so nothing is lost by it landing a scheduler hop
    /// later, and the alternative is a worker parked for up to the
    /// store's acquire plus command timeout inside a destructor while
    /// every other connection assigned to it stops being served.
    ///
    /// A backend that answers `false` to
    /// [`IdempotencyCache::blocks_on_io`] releases inline. Detaching an
    /// in-process mutex acquisition would buy nothing and would make a
    /// dropped claim readable as still held for a scheduler hop
    /// afterwards, which is a race in every caller that drops and then
    /// looks.
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let owner = self.owner;
        if self.cache.blocks_on_io() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let cache = Arc::clone(&self.cache);
                let workspace_id = std::mem::take(&mut self.workspace_id);
                let key = std::mem::take(&mut self.key);
                handle.spawn_blocking(move || cache.release(&workspace_id, &key, owner));
                return;
            }
        }
        self.cache.release(&self.workspace_id, &self.key, owner);
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

    /// Publish `response` under a claim this caller took, and stop
    /// holding the key.
    ///
    /// Takes the claim's three identifying fields rather than the RAII
    /// handle so the call can be moved onto a blocking thread; see
    /// [`record_response_detached`].
    ///
    /// The claim's lease and the response's retention are two different
    /// lifetimes. A response is written under the cache TTL, which
    /// outlives the lease by hours, and it is written *whether or not
    /// the claim row is still there*: an upstream slower than the lease
    /// is the ordinary case this cache exists for, and refusing to
    /// publish would make every one of that client's retries a fresh
    /// upstream call forever.
    ///
    /// An implementation must therefore refuse in exactly two
    /// situations, both of which mean somebody else's answer is the one
    /// waiters are owed:
    ///
    /// 1. A **live** claim under a different fencing token is stored.
    ///    That request took the key over and is producing the answer.
    /// 2. An unexpired completed response is already stored.
    ///
    /// Everything else publishes, including an absent row, an expired
    /// response, and a lapsed claim under any token. Refusals are
    /// counted under `result="fenced"` rather than logged.
    fn complete(&self, workspace_id: &str, key: &str, owner: u128, response: CachedResponse);

    /// Release a claim this caller holds without publishing anything,
    /// so the next request can take the key immediately.
    ///
    /// A no-op when the claim was already superseded: the row belongs
    /// to the successor, and a release that did not check the fencing
    /// token would hand a live claim away.
    fn release(&self, workspace_id: &str, key: &str, owner: u128);

    /// Whether this backend's calls can block on network I/O.
    ///
    /// A proxy worker that blocks on a Redis round trip stops serving
    /// every other connection assigned to it, so the request path moves
    /// a backend that answers `true` onto the blocking pool: the wait
    /// loop and [`claim_async`] and [`record_response_detached`] already
    /// do, and [`IdempotencyClaim`]'s destructor, which cannot await,
    /// detaches the release onto it instead.
    ///
    /// The default is `false`, which is right for any backend answering
    /// out of process memory: detaching a mutex acquisition onto
    /// another thread costs more than it saves and makes the release
    /// observable only after a scheduler hop.
    fn blocks_on_io(&self) -> bool {
        false
    }

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
    let lease = effective_lease(lease_secs);
    let taken = cache.try_claim(workspace_id, key, lease);
    finish_claim(cache, workspace_id, key, taken)
}

/// [`claim`], with the backend's read and write moved off the caller's
/// thread.
///
/// The request path uses this one. A shared backend's claim is up to
/// six network round trips (three read-decide-write turns), and a
/// Pingora worker that blocks on one stops serving every other
/// connection assigned to it. A backend that answers `false` to
/// [`IdempotencyCache::blocks_on_io`] runs inline, because a scheduler
/// hop costs more than the mutex it would be hopping around.
pub async fn claim_async(
    cache: &Arc<dyn IdempotencyCache>,
    workspace_id: &str,
    key: &str,
    lease_secs: u64,
) -> ClaimState {
    let lease = effective_lease(lease_secs);
    if !cache.blocks_on_io() {
        return finish_claim(
            cache,
            workspace_id,
            key,
            cache.try_claim(workspace_id, key, lease),
        );
    }
    let taken = {
        let cache = Arc::clone(cache);
        let workspace_id = workspace_id.to_string();
        let key = key.to_string();
        match tokio::task::spawn_blocking(move || cache.try_claim(&workspace_id, &key, lease)).await
        {
            Ok(taken) => taken,
            // The blocking pool is gone or the task panicked. Report
            // the key as held rather than handing out a claim nothing
            // wrote: an unowned claim would publish over whatever the
            // real owner produces.
            Err(_) => TryClaim::InFlight {
                lease_expires_at_unix: now_unix().saturating_add(lease),
            },
        }
    };
    finish_claim(cache, workspace_id, key, taken)
}

/// Zero means "the caller did not choose", not "expire immediately".
fn effective_lease(lease_secs: u64) -> u64 {
    if lease_secs == 0 {
        DEFAULT_CLAIM_LEASE_SECS
    } else {
        lease_secs
    }
}

/// Attach the RAII handle and record the outcome.
///
/// Only the arm that ends the request here records a `result`. The
/// other two are answered further down (a replay, a wait, a 409) and
/// recording at both places is what made the counter sum to two or
/// three per request instead of one.
fn finish_claim(
    cache: &Arc<dyn IdempotencyCache>,
    workspace_id: &str,
    key: &str,
    taken: TryClaim,
) -> ClaimState {
    let backend = cache.backend_label();
    match taken {
        TryClaim::Claimed { owner, took_over } => {
            sbproxy_observe::metrics::record_idempotency_cache_result(
                backend,
                if took_over { "takeover" } else { "miss" },
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
        } => ClaimState::InFlight {
            lease_expires_at_unix,
        },
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
            // The caller records the outcome: a coalesced replay and a
            // coalesced conflict are different answers and only the
            // caller has the body hash that tells them apart.
            EntryState::Completed(response) => return Some(*response),
            // The holder released without publishing, or its lease
            // lapsed. Either way there is no response coming and this
            // request cannot produce one. Counted apart from
            // `wait_timeout`: a budget that ran out means overlapping
            // retries are outliving the wait, and a holder that vanished
            // means requests are dying mid-flight. Same 409, opposite
            // things to go look at.
            EntryState::Absent => {
                sbproxy_observe::metrics::record_idempotency_cache_result(backend, "abandoned");
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
    let claimed = claim_async(cache, workspace_id, &key, lease_secs).await;
    let elapsed = start.elapsed().as_secs_f64();
    sbproxy_observe::metrics::record_idempotency_cache_duration(backend, elapsed);

    // `miss` and `takeover` are recorded by the claim itself. Every
    // other arm records exactly one value here, so the `result` label
    // sums to one per request rather than to two or three.
    let (stored, coalesced) = match claimed {
        ClaimState::Claimed(claim) => {
            return IdempotencyOutcome::Miss { body_hash, claim };
        }
        ClaimState::Completed(stored) => (*stored, false),
        ClaimState::InFlight { .. } => {
            match await_completion(cache, workspace_id, &key, wait).await {
                Some(stored) => (stored, true),
                None => return IdempotencyOutcome::InFlight,
            }
        }
    };

    if stored.request_body_hash == body_hash {
        sbproxy_observe::metrics::record_idempotency_cache_result(
            backend,
            if coalesced { "coalesced" } else { "hit" },
        );
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

impl RecordedResponse {
    /// Stamp the absolute expiry and hand back the row a backend
    /// stores. The TTL here is the response's retention, hours long and
    /// unrelated to the claim's lease.
    fn into_cached(self) -> CachedResponse {
        let ttl = if self.ttl_secs == 0 {
            DEFAULT_TTL_SECS
        } else {
            self.ttl_secs
        };
        CachedResponse {
            status: self.status,
            headers: self.headers,
            body: self.body,
            request_body_hash: self.body_hash,
            expires_at_unix: now_unix().saturating_add(ttl),
        }
    }
}

/// Publish the response captured after the handler chain finishes
/// processing a claimed request, and release the claim.
///
/// Consumes the claim: publishing is the one way out of a claim that
/// does not release the key, and taking it by value is what makes that
/// a compile-time fact rather than a convention.
pub fn record_response(mut claim: IdempotencyClaim, recorded: RecordedResponse) {
    let resp = recorded.into_cached();
    claim
        .cache
        .complete(&claim.workspace_id, &claim.key, claim.owner, resp);
    // Set after the publish, not before: `complete` may refuse a
    // superseded claim, and a claim that was refused is not this
    // caller's to release either. The successor owns the key now.
    claim.published = true;
}

/// [`record_response`], with the backend's write kept off the caller's
/// thread.
///
/// The request path uses this one, for the same reason [`claim_async`]
/// exists: publishing to a shared backend is a read plus a conditional
/// write, and the two places that publish are `response_body_filter`
/// and the AI relay, both on a proxy worker that is serving other
/// connections.
///
/// It detaches rather than awaiting because `response_body_filter` is
/// one of Pingora's synchronous trait methods and has no await point to
/// offer. What that costs is that a follower polling the key can see it
/// as still held for a scheduler hop after the owner's response has
/// gone out; the follower is already in a poll loop with seconds of
/// budget, so it picks the answer up on its next turn.
///
/// A backend that answers `false` to [`IdempotencyCache::blocks_on_io`]
/// publishes inline. There is nothing to detach from an in-process
/// mutex, and running it inline is what keeps a caller that publishes
/// and then looks from racing itself.
pub fn record_response_detached(mut claim: IdempotencyClaim, recorded: RecordedResponse) {
    let resp = recorded.into_cached();
    if claim.cache.blocks_on_io() {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let cache = Arc::clone(&claim.cache);
            let workspace_id = claim.workspace_id.clone();
            let key = claim.key.clone();
            let owner = claim.owner;
            handle.spawn_blocking(move || cache.complete(&workspace_id, &key, owner, resp));
            // Set here rather than after the write lands: the publish
            // is this claim's one way out, and re-releasing it from the
            // destructor would hand the key away underneath the write
            // that is about to happen.
            claim.published = true;
            return;
        }
    }
    claim
        .cache
        .complete(&claim.workspace_id, &claim.key, claim.owner, resp);
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
/// The answer to a retry that arrived while the original request held
/// the key and no response was stored inside the wait budget.
/// `draft-ietf-httpapi-idempotency-key-header` names 409 for this case;
/// the distinct error code is so a client can tell "retry this in a
/// moment" from "you reused a key with a different body", which are the
/// same status and opposite instructions.
///
/// The message covers both populations that land here, because the
/// instruction is the same for both and a message that named only the
/// first would be false for the second: the holder may still be
/// working, or it may have ended without storing anything, in which
/// case the retry is what takes the key over.
pub fn in_flight_response() -> (StatusCode, &'static str, Vec<u8>) {
    let body = serde_json::json!({
        "error": "ledger.idempotency_in_flight",
        "message": "A request with this Idempotency-Key is still in progress, or ended without storing a response. Retry with the same key.",
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
mod backends;

pub use backends::{InMemoryIdempotencyCache, KvIdempotencyCache, DEFAULT_MAX_ENTRIES};

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use sbproxy_platform::storage::KVStore;
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
        cache.complete("ws_a", "expiring-key", held.owner(), stale);
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
        // The shared backend detaches its release onto the blocking
        // pool rather than parking a proxy worker inside a destructor,
        // so the key comes free a scheduler hop later. The next
        // assertion is about namespacing, not about that hop.
        settle_release(&tenant_b, "", "order-1234").await;

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
            cache.complete(
                "ws",
                &key,
                owner,
                CachedResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                    request_body_hash: hash_body(format!("req-{i}").as_bytes()),
                    expires_at_unix: future,
                },
            );
        }
        assert_eq!(concrete.inner.lock().len(), cap);
        // The most-recent key survived; an early evicted key is gone.
        assert!(matches!(
            cache.peek("ws", "key-999"),
            EntryState::Completed(_)
        ));
        assert_eq!(cache.peek("ws", "key-0"), EntryState::Absent);
    }

    // --- WOR-2606 fix round: the claim / response lifetimes ---

    /// A store that fails the first `n` atomic creates and is healthy
    /// afterwards. A command timeout, a dropped connection, and a
    /// Redis failover blip all arrive at the caller exactly like this.
    struct FlakyCreateStore {
        inner: sbproxy_platform::storage::MemoryKVStore,
        failures_left: std::sync::atomic::AtomicUsize,
    }

    impl FlakyCreateStore {
        fn new(failures: usize) -> Self {
            Self {
                inner: sbproxy_platform::storage::MemoryKVStore::new(0),
                failures_left: std::sync::atomic::AtomicUsize::new(failures),
            }
        }
    }

    impl KVStore for FlakyCreateStore {
        fn get(&self, key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
            self.inner.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
            self.inner.delete(key)
        }
        fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            self.inner.scan_prefix(prefix)
        }
        fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl: u64) -> anyhow::Result<()> {
            self.inner.put_with_ttl(key, value, ttl)
        }
        fn compare_and_swap_with_ttl(
            &self,
            key: &[u8],
            expected: &[u8],
            value: &[u8],
            ttl: u64,
        ) -> anyhow::Result<bool> {
            self.inner
                .compare_and_swap_with_ttl(key, expected, value, ttl)
        }
        fn put_if_absent_with_ttl(
            &self,
            key: &[u8],
            value: &[u8],
            ttl: u64,
        ) -> anyhow::Result<bool> {
            if self
                .failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                anyhow::bail!("transient: command timed out");
            }
            self.inner.put_if_absent_with_ttl(key, value, ttl)
        }
        fn supports_atomic_create(&self) -> bool {
            true
        }
    }

    fn response(body: &[u8], status: u16) -> CachedResponse {
        CachedResponse {
            status,
            headers: vec![],
            body: body.to_vec(),
            request_body_hash: hash_body(b"req"),
            expires_at_unix: now_unix() + 600,
        }
    }

    /// Poll until a detached release has landed. The KV backend's
    /// destructor hands the release to the blocking pool rather than
    /// parking a proxy worker on a network round trip, so a test that
    /// drops a claim and immediately looks is racing it.
    async fn settle_release(cache: &Arc<dyn IdempotencyCache>, workspace: &str, key: &str) {
        for _ in 0..200 {
            if cache.peek(workspace, key) == EntryState::Absent {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the release never landed for {key}");
    }

    /// The claim's lease and the response's retention are two different
    /// lifetimes, and on Redis the lease *is* the row's TTL.
    ///
    /// An upstream slower than the lease is the ordinary case this
    /// cache exists for: an AI completion, a payment with a 3DS
    /// step-up. The owner claims at t=0 with `EX 60`, the store evicts
    /// the claim at t=60, and the publish at t=90 used to read an
    /// absent row, call it superseded, and discard the response. The
    /// client's retry then missed and re-executed, and so did the one
    /// after that, forever: strictly worse than the unconditional
    /// write this replaced.
    ///
    /// The lease here is one real second because `MemoryKVStore` has no
    /// clock to inject and one second is the smallest a seconds-valued
    /// TTL can express.
    #[tokio::test]
    async fn a_publish_lands_after_the_claim_row_expired() {
        let store = shared_store();
        let cache: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "t", "o"));

        let ClaimState::Claimed(held) = claim(&cache, "ws", "slow", 1) else {
            panic!("expected to take the key");
        };
        // The upstream outlives the lease. The claim row goes with it.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(
            cache.peek("ws", "slow"),
            EntryState::Absent,
            "the claim row must have expired for this test to mean anything"
        );

        record_response(
            held,
            RecordedResponse {
                status: 201,
                headers: vec![],
                body: b"charged".to_vec(),
                body_hash: hash_body(b"req"),
                ttl_secs: 600,
            },
        );

        match cache.peek("ws", "slow") {
            EntryState::Completed(stored) => assert_eq!(stored.body, b"charged"),
            other => panic!("a slow upstream's response must still cache, got {other:?}"),
        }
    }

    /// The other half of the same rule: publishing into an absent row
    /// is unconditional only until somebody else owns the key. A
    /// successor that already answered must not be clobbered by the
    /// owner it replaced.
    #[tokio::test]
    async fn a_stalled_owner_cannot_clobber_a_successors_published_response() {
        let store = shared_store();
        let cache: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "t", "o"));

        // The stalled owner: its lease is already spent.
        let TryClaim::Claimed { owner: stale, .. } = cache.try_claim("ws", "k", 0) else {
            panic!("expected to take the key");
        };
        // The successor takes it over and answers.
        let TryClaim::Claimed {
            owner: fresh,
            took_over,
        } = cache.try_claim("ws", "k", 60)
        else {
            panic!("the successor must be able to take a lapsed key");
        };
        assert!(took_over, "taking a lapsed row over must be counted as one");
        cache.complete("ws", "k", fresh, response(b"fresh", 201));

        // The stalled owner wakes up and publishes.
        cache.complete("ws", "k", stale, response(b"stale", 500));

        match cache.peek("ws", "k") {
            EntryState::Completed(stored) => assert_eq!(
                stored.body, b"fresh",
                "the stalled owner overwrote the successor's answer"
            ),
            other => panic!("expected the successor's response, got {other:?}"),
        }
    }

    /// `peek` is the waiter's poll path: every follower runs it every
    /// five to fifty milliseconds. It used to delete a dead row
    /// unconditionally, which is the exact hazard `release` documents
    /// and refuses to take.
    ///
    /// The race it opened: follower F reads owner A's lapsed row;
    /// retry R wins the takeover a millisecond later and is now the
    /// live owner; F's delete lands a millisecond after that and
    /// removes R's live claim. The key reads as absent, the next
    /// request claims it and charges the card a second time, and R's
    /// own publish is fenced out by a row that is no longer its own.
    ///
    /// Deterministic form of the same property: a read-only method
    /// leaves the row it read alone, so the successor's
    /// compare-and-swap still has the exact bytes it needs.
    #[tokio::test]
    async fn a_peek_never_deletes_the_row_it_read() {
        let store = shared_store();
        let cache = kv_cache(&store, "t", "o");
        let storage_key = cache.build_key("ws", "k");

        // A claim whose holder never came back.
        let TryClaim::Claimed { .. } = cache.try_claim("ws", "k", 0) else {
            panic!("expected to take the key");
        };

        assert_eq!(
            cache.peek("ws", "k"),
            EntryState::Absent,
            "a lapsed claim must not keep answering in-flight"
        );
        assert!(
            store.get(storage_key.as_bytes()).unwrap().is_some(),
            "a read-only poll deleted the row it read"
        );

        // And the consequence: the successor still takes it over,
        // through the compare-and-swap, rather than racing a delete.
        match cache.try_claim("ws", "k", 60) {
            TryClaim::Claimed { took_over, .. } => assert!(
                took_over,
                "the successor claimed an empty key, so the row was gone"
            ),
            other => panic!("the lapsed key must be takeable, got {other:?}"),
        }
    }

    /// One transient store failure used to latch single-flight off for
    /// the lifetime of the process, and the fence with it.
    ///
    /// After the latch, `complete` reverted to an unconditional write:
    /// an owner that stalled past its lease overwrote the answer its
    /// successor had already sent the client, and every retry for the
    /// next day replayed the wrong one. One dropped packet bought that.
    /// Whether a store can create atomically is a property of the
    /// store, asked once at construction, not something inferred from
    /// a request's luck.
    #[tokio::test]
    async fn a_transient_store_failure_does_not_disarm_the_fence() {
        let store: Arc<dyn KVStore> = Arc::new(FlakyCreateStore::new(1));
        let cache = KvIdempotencyCache::new(Arc::clone(&store), DEFAULT_TTL_SECS, "t", "o");

        // The first atomic create fails. The retry inside `try_claim`
        // is what turns that into a claim rather than a disarmed fence.
        match cache.try_claim("ws", "first", 60) {
            TryClaim::Claimed { .. } => {}
            other => panic!("a transient failure must not lose the claim, got {other:?}"),
        }
        assert!(
            cache.single_flight_available(),
            "one transient failure disarmed single-flight for the process"
        );

        // The fence is still doing its job: a stalled owner cannot
        // overwrite its successor's published answer.
        let TryClaim::Claimed { owner: stale, .. } = cache.try_claim("ws", "k", 0) else {
            panic!("expected to take the key");
        };
        let TryClaim::Claimed { owner: fresh, .. } = cache.try_claim("ws", "k", 60) else {
            panic!("the successor must take the lapsed key");
        };
        cache.complete("ws", "k", fresh, response(b"fresh", 201));
        cache.complete("ws", "k", stale, response(b"stale", 500));

        match cache.peek("ws", "k") {
            EntryState::Completed(stored) => assert_eq!(
                stored.body, b"fresh",
                "the fence was disarmed by a transient failure"
            ),
            other => panic!("expected the successor's response, got {other:?}"),
        }
    }

    /// A store that genuinely has no atomic create is detected once, at
    /// construction, and every affected request is counted rather than
    /// the detection being re-derived from each failed write.
    #[tokio::test]
    async fn a_store_without_atomic_create_degrades_once_and_says_so() {
        struct NoAtomicCreate(sbproxy_platform::storage::MemoryKVStore);
        impl KVStore for NoAtomicCreate {
            fn get(&self, key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
                self.0.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
                self.0.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
                self.0.delete(key)
            }
            fn scan_prefix(
                &self,
                prefix: &[u8],
            ) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
                self.0.scan_prefix(prefix)
            }
            fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl: u64) -> anyhow::Result<()> {
                self.0.put_with_ttl(key, value, ttl)
            }
        }

        let store: Arc<dyn KVStore> = Arc::new(NoAtomicCreate(
            sbproxy_platform::storage::MemoryKVStore::new(0),
        ));
        let cache: Arc<dyn IdempotencyCache> =
            Arc::new(KvIdempotencyCache::new(store, DEFAULT_TTL_SECS, "t", "o"));

        // Degraded, and honest about it: replay still works, but two
        // simultaneous first requests both get a claim.
        assert!(matches!(
            cache.try_claim("ws", "k", 60),
            TryClaim::Claimed { .. }
        ));
        assert!(matches!(
            cache.try_claim("ws", "k", 60),
            TryClaim::Claimed { .. }
        ));

        let ClaimState::Claimed(held) = claim(&cache, "ws", "k", 60) else {
            panic!("a degraded store still hands out claims");
        };
        record_response(
            held,
            RecordedResponse {
                status: 200,
                headers: vec![],
                body: b"replayable".to_vec(),
                body_hash: hash_body(b"req"),
                ttl_secs: 600,
            },
        );
        match cache.peek("ws", "k") {
            EntryState::Completed(stored) => assert_eq!(stored.body, b"replayable"),
            other => panic!("replay must survive the degradation, got {other:?}"),
        }
    }

    /// The destructor detaches the shared backend's release rather than
    /// parking a proxy worker inside a `Drop` on a network round trip.
    /// The key still comes free; it comes free a scheduler hop later.
    #[tokio::test]
    async fn a_dropped_kv_claim_still_releases_the_key() {
        let store = shared_store();
        let cache: Arc<dyn IdempotencyCache> = Arc::new(kv_cache(&store, "t", "o"));
        assert!(
            cache.blocks_on_io(),
            "the shared backend must declare that it blocks"
        );

        let ClaimState::Claimed(held) = claim(&cache, "ws", "abandoned", 60) else {
            panic!("expected to take the key");
        };
        assert!(matches!(
            cache.peek("ws", "abandoned"),
            EntryState::InFlight { .. }
        ));
        drop(held);
        settle_release(&cache, "ws", "abandoned").await;
        assert!(matches!(
            claim(&cache, "ws", "abandoned", 60),
            ClaimState::Claimed(_)
        ));
    }
}
