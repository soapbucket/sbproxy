//! The two [`IdempotencyCache`](super::IdempotencyCache) backends, and
//! the row format they share.
//!
//! Split out of the parent module rather than left inline because the
//! protocol and its implementations are two different things to read.
//! The parent owns the vocabulary a caller needs ([`EntryState`],
//! [`TryClaim`], [`IdempotencyClaim`], the trait) and the free
//! functions the request path calls; this file owns the two places
//! that satisfy it and the on-the-wire row they agree on.
//!
//! Everything private to the parent is reachable here, because a child
//! module can see its ancestors' private items. That is what lets
//! [`StoredEntry`] hold a `CachedResponse` and the backends read
//! `now_unix` without either being widened for the sake of the split.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_platform::storage::KVStore;
use serde::{Deserialize, Serialize};

use super::{now_unix, CachedResponse, EntryState, IdempotencyCache, TryClaim, DEFAULT_TTL_SECS};

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
pub(super) enum StoredEntry {
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

// --- In-memory backend ---

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
    pub(super) inner: parking_lot::Mutex<lru::LruCache<(String, String), StoredEntry>>,
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

    fn complete(&self, workspace_id: &str, key: &str, owner: u128, response: CachedResponse) {
        let now = now_unix();
        let key_pair = (workspace_id.to_string(), key.to_string());
        let mut guard = self.inner.lock();
        let superseded = match guard.peek(&key_pair) {
            // Somebody else holds a *live* claim: they took the key
            // over and their answer is the one waiters are owed.
            Some(StoredEntry::InFlight {
                owner: stored,
                lease_expires_at_unix,
            }) => *stored != owner && *lease_expires_at_unix > now,
            // A completed response is already stored. Never overwrite
            // one, whoever wrote it.
            Some(StoredEntry::Completed(stored)) => stored.expires_at_unix > now,
            // Absent, an evicted row, a lapsed claim under any token:
            // none of those is a successor, and the response in hand is
            // the only answer this key has. An upstream slower than the
            // lease lands here and must still cache, or every retry
            // from this client is a fresh upstream call forever.
            None => false,
        };
        if superseded {
            sbproxy_observe::metrics::record_idempotency_cache_result(
                self.backend_label(),
                "fenced",
            );
            return;
        }
        guard.put(key_pair, StoredEntry::Completed(response));
    }

    fn release(&self, workspace_id: &str, key: &str, owner: u128) {
        let key_pair = (workspace_id.to_string(), key.to_string());
        let mut guard = self.inner.lock();
        if matches!(
            guard.peek(&key_pair),
            Some(StoredEntry::InFlight { owner: stored, .. }) if *stored == owner
        ) {
            guard.pop(&key_pair);
        }
    }

    fn backend_label(&self) -> &'static str {
        "memory"
    }
}

// --- KVStore-backed backend (Redis or any other store) ---

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
    /// Whether the wrapped store implements an atomic create.
    ///
    /// Asked once, at construction, and never again. It used to be an
    /// `AtomicBool` cleared by the error arm of the claim write, which
    /// made a single command timeout indistinguishable from a store
    /// that does not have the primitive: one dropped connection
    /// disarmed the fence for the lifetime of the process, after which
    /// a stalled owner could overwrite its successor's response and
    /// every retry for the next day replayed the wrong one. Whether a
    /// backend can create a key atomically is a property of the
    /// backend, not of one request's luck.
    single_flight: bool,
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
        let single_flight = store.supports_atomic_create();
        if !single_flight {
            tracing::warn!(
                prefix = %key_prefix,
                "idempotency: this l2_store has no atomic create, so two simultaneous first \
                 requests with one key will both reach the upstream; replay and conflict \
                 detection still work. Use redis for cluster-wide single-flight."
            );
        }
        Self {
            store,
            ttl_secs: ttl,
            key_prefix,
            single_flight,
        }
    }

    pub(super) fn build_key(&self, workspace_id: &str, key: &str) -> String {
        let mut out =
            String::with_capacity(self.key_prefix.len() + workspace_id.len() + key.len() + 16);
        out.push_str(&self.key_prefix);
        push_key_segment(&mut out, workspace_id);
        push_key_segment(&mut out, key);
        out
    }

    pub(super) fn single_flight_available(&self) -> bool {
        self.single_flight
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
        // Deliberately no eviction here. `peek` is the waiter's poll
        // path, so it runs every five to fifty milliseconds per
        // follower, and a bare `delete` is unconditional: between
        // reading a lapsed row and deleting it, a retry can win the
        // takeover and become the live owner, and the delete then
        // throws that live claim away. The key reads as absent, the
        // next request claims it and reaches the upstream a second
        // time, and the successor's publish is fenced out by a row that
        // is no longer its own. `release` documents exactly this hazard
        // and answers it with a compare-and-swap; a read-only method
        // has no business deleting anything at all. Dead rows are
        // cleaned up by the release path and by the store's own TTL.
        entry.state(now_unix())
    }

    fn try_claim(&self, workspace_id: &str, key: &str, lease_secs: u64) -> TryClaim {
        if !self.single_flight_available() {
            // A store with no atomic create cannot serialize two
            // simultaneous first requests, and no amount of retrying
            // builds that guarantee on top of one. Counted per affected
            // request; the warning naming the store was emitted once at
            // construction.
            sbproxy_observe::metrics::record_idempotency_cache_result(
                self.backend_label(),
                "single_flight_unsupported",
            );
            return self.unfenced_claim();
        }
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
                // A transient store failure: a command timeout, a
                // dropped connection, a failover blip. It is NOT
                // evidence that the store cannot create atomically,
                // and treating it as such used to latch single-flight
                // off for the lifetime of the process on one bad
                // packet, which disarmed the fence for every later
                // request. Whether the store has the primitive at all
                // is a static property of the backend, asked once at
                // construction. Count the failure and take another
                // turn.
                Err(_) => {
                    sbproxy_observe::metrics::record_idempotency_cache_result(
                        self.backend_label(),
                        "error",
                    );
                    continue;
                }
            }
        }
        TryClaim::InFlight {
            lease_expires_at_unix: now_unix().saturating_add(lease_secs),
        }
    }

    fn complete(&self, workspace_id: &str, key: &str, owner: u128, response: CachedResponse) {
        let storage_key = self.build_key(workspace_id, key);
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
        let now = now_unix();
        let Some(raw) = current else {
            // The claim row is gone. On Redis it is gone at
            // `lease_secs`, because the lease is the `SET NX EX` TTL,
            // and an upstream slower than the lease is the ordinary
            // case this cache exists for: an AI completion, a payment
            // with a 3DS step-up. Absent is not superseded, so publish.
            //
            // Conditionally, though. A successor may claim the key
            // between this read and this write, and `put_if_absent`
            // is what makes that a lost race rather than a clobbered
            // claim. Losing it means somebody else owns the key and
            // this response is no longer the one waiters are owed.
            match self
                .store
                .put_if_absent_with_ttl(storage_key.as_bytes(), &payload, self.ttl_secs)
            {
                Ok(true) => {}
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
            return;
        };
        let superseded = match parse_entry(&raw) {
            // A different request holds a *live* claim: it took the key
            // over and its answer is the one waiters are owed. A lapsed
            // claim under any token is not a successor, and neither is
            // this owner's own row.
            Some(StoredEntry::InFlight {
                owner: stored,
                lease_expires_at_unix,
            }) => stored != owner && lease_expires_at_unix > now,
            // A completed response is already stored. Never overwrite
            // one, whoever wrote it: the client has already been told
            // that answer.
            Some(StoredEntry::Completed(stored)) => stored.expires_at_unix > now,
            // An unparseable row is not a successor either.
            None => false,
        };
        if superseded {
            sbproxy_observe::metrics::record_idempotency_cache_result(
                self.backend_label(),
                "fenced",
            );
            return;
        }
        match self.store.compare_and_swap_with_ttl(
            storage_key.as_bytes(),
            &raw,
            &payload,
            self.ttl_secs,
        ) {
            Ok(true) => {}
            // Lost between the read and the swap: somebody wrote the
            // key one instant later, so the same fence applies.
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

    fn release(&self, workspace_id: &str, key: &str, owner: u128) {
        let storage_key = self.build_key(workspace_id, key);
        let Ok(Some(raw)) = self.store.get(storage_key.as_bytes()) else {
            return;
        };
        let still_ours = matches!(
            parse_entry(&raw),
            Some(StoredEntry::InFlight { owner: stored, .. }) if stored == owner
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
            owner,
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

    fn blocks_on_io(&self) -> bool {
        // Every call here is a round trip to the shared store.
        true
    }
}
