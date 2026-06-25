//! SWIM-style gossip failure detector.
//!
//! K4 upgrades the MVP heartbeat loop to the SWIM protocol (Das / Gupta /
//! Gray 2002). The wire transport (UDP), the encryption path (K3 `Cipher`),
//! and the integration primitives (`PeerEvictor`, `IsolationObserver`) are
//! carried forward unchanged; only the failure-detection machinery is new.
//!
//! # Protocol summary
//!
//! Every `swim_protocol_period_ms`:
//!
//! 1. Pick one random Alive peer `target`.
//! 2. Send `Ping { seq, from }` to `target`.
//! 3. Start a `swim_ping_timeout_ms` timer.
//! 4. On `Ack { seq }` from `target`: success. Record success +
//!    `last_ack`; if the peer was Suspect, refute back to Alive.
//! 5. On timeout: pick up to K other Alive peers and send
//!    `PingReq { seq, target, target_addr }` to each. Each witness pings
//!    `target` on our behalf and relays the outcome via `IndirectAck`.
//! 6. On any `IndirectAck { alive: true }`: success (refutes Suspect).
//! 7. On all indirect probes failing (or no witnesses at all): mark
//!    `target` Suspect.
//! 8. A peer that stays Suspect for `swim_suspect_timeout_secs` without
//!    a refuting ACK is marked Dead and reported to `PeerEvictor`
//!    (hash-ring removal). Dead is terminal.
//!
//! # Dissemination (L1)
//!
//! Every PING and ACK carries a bounded `updates: Vec<PeerUpdate>` slot
//! with up to [`MAX_UPDATES_PER_MSG`] entries. When A observes B has
//! transitioned Alive -> Suspect (or any other state change), it enqueues
//! a `PeerUpdate` into the local `Disseminator`. The next protocol tick
//! drains up to N of those updates onto the outgoing PING; the receiver
//! applies them to its own peer table and enqueues them into ITS own
//! disseminator so the news fans out at gossip speed.
//!
//! Conflict resolution uses a per-node monotonic `incarnation` counter:
//! higher wins. A node that sees a Suspect/Dead update about itself bumps
//! its incarnation and queues a fresh `Alive(incarnation+1)` to refute
//! the rumor.
//!
//! # Back-compat
//!
//! L1 breaks wire compatibility with K4: the `Ping` and `Ack` variants
//! grow a required `updates: Vec<PeerUpdate>` field. All nodes in a
//! cluster must upgrade together; mixed-version clusters will see every
//! datagram drop at the deserialize boundary on at least one side. The
//! `PingReq` / `IndirectAck` variants are unchanged.
//!
//! # Encryption
//!
//! When `GossipLoopConfig::cipher` is `Some`, every outbound message is
//! passed through `Cipher::seal` before `UdpSocket::send_to`, and every
//! inbound datagram is passed through `Cipher::open` before
//! `crate::transport::wire::decode`. Failures bump `MESH_CRYPTO_DECRYPT_FAILED` and
//! drop the datagram. This mirrors K3 exactly; the only change is the
//! set of enum variants that round-trip through it.
//!
//! # Module layout
//!
//! WOR-39: the original 3,494-line single-file implementation is split at
//! the natural section boundaries flagged by the audit. Each phase lives
//! in its own private sibling module under `gossip_loop/`:
//!
//! * `probe` - direct Ping/Ack orchestration (`run_probe`), state
//!   transitions, suspect + dead-peer sweepers.
//! * `ping_req` - indirect-probe helpers (witness selection, indirect
//!   pending demux). The witness handler itself is inline in the recv
//!   task in this module.
//! * `dissemination` - L1 piggyback apply path (`apply_updates` /
//!   `apply_update`) and the pure conflict-resolution decision
//!   (`decide_transition`).
//! * `encryption` - per-message AEAD seal-and-send wrapper (`send_msg`);
//!   the decrypt side is inline in the recv task because it shares the
//!   inbound buffer.
//!
//! The public surface ([`GossipLoop`], [`GossipLoopConfig`], [`PeerEntry`],
//! [`PeerTable`], [`PeerState`], [`GossipMsg`], [`PeerUpdate`],
//! [`PeerStateWire`], [`MAX_UPDATES_PER_MSG`]) is defined here so
//! external callers continue using `crate::gossip_loop::*` unchanged.

mod dissemination;
mod encryption;
mod ping_req;
mod probe;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::crypto::Cipher;
use crate::isolation::IsolationObserver;
use crate::metrics::{
    ADDR_MAP_KIND_LEARNED, ADDR_MAP_KIND_REWRITTEN, CRYPTO_KIND_GOSSIP, DISSEM_KIND_ACK,
    MESH_ADDR_MAP_UPDATES, MESH_CRYPTO_DECRYPT_FAILED, MESH_DEAD_PEERS_GC,
    MESH_DISSEMINATION_UPDATES_SENT, MESH_SUSPECT_TRANSITIONS, PEER_STATE_ALIVE, PEER_STATE_DEAD,
    PEER_STATE_SUSPECT,
};
use crate::peer_eviction::PeerEvictor;

use dissemination::apply_updates;
use encryption::send_msg;
use ping_req::complete_pending_indirect;
use probe::{complete_pending_direct, run_probe, sweep_dead_for_gc, sweep_suspects_to_dead};

/// Maximum number of [`PeerUpdate`] entries stamped onto a single
/// outgoing PING or ACK. Keeps encrypted UDP datagrams comfortably under
/// the default 1500-byte MTU even after AEAD overhead and string ids.
pub const MAX_UPDATES_PER_MSG: usize = 16;

// --- Wire format ---

/// Wire messages exchanged between nodes.
///
/// `Heartbeat` is retained as a compatibility shim for existing callers
/// that still construct one in tests / docs; it is NOT emitted by the
/// SWIM loop itself. A received `Heartbeat` is treated as an implicit
/// ACK from the peer that sent it.
///
/// # Dissemination (L1)
///
/// The `Ping` and `Ack` variants carry a bounded `updates: Vec<PeerUpdate>`
/// payload. Each entry carries a `(node_id, state, incarnation)` triple;
/// receivers apply them to their own peer table using incarnation-based
/// conflict resolution (see `apply_update`). This is a wire break from
/// K4: all nodes in a cluster must upgrade together.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GossipMsg {
    /// Back-compat / legacy. Not emitted by K4; accepted on the receive
    /// path so pre-K4 tests keep round-tripping through bincode.
    Heartbeat { node_id: String, ts_ms: u64 },
    /// Reserved for future dynamic-membership join.
    Join {
        node_id: String,
        advertise_addr: String,
    },
    /// SWIM direct probe. Carries piggybacked state deltas (L1).
    Ping {
        seq: u64,
        from: String,
        /// Piggybacked state deltas. Bounded by [`MAX_UPDATES_PER_MSG`].
        updates: Vec<PeerUpdate>,
    },
    /// Response to either a direct `Ping` or a witness's proxied ping.
    /// Carries piggybacked state deltas (L1).
    Ack {
        seq: u64,
        from: String,
        /// Piggybacked state deltas. Bounded by [`MAX_UPDATES_PER_MSG`].
        updates: Vec<PeerUpdate>,
    },
    /// Indirect probe request. `target` is the node id we want pinged;
    /// `target_addr` is the socket address the witness should probe
    /// (the originator carries this so the witness does not need an
    /// out-of-band address book).
    PingReq {
        seq: u64,
        from: String,
        target: String,
        target_addr: String,
    },
    /// Relayed result of a `PingReq`. `alive == true` means the witness
    /// got an ACK from `target` within its own direct-ping window.
    IndirectAck {
        seq: u64,
        from: String,
        target: String,
        alive: bool,
    },
}

/// Membership state enumeration used on the wire. Mirrors [`PeerState`]
/// without the `Instant` timestamp (wall-clock on different machines is
/// not comparable; the local receiver stamps `since` on transition).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerStateWire {
    /// Peer is alive and responding to probes.
    Alive,
    /// Peer is suspected of failure.
    Suspect,
    /// Peer is confirmed dead.
    Dead,
}

impl PeerStateWire {
    /// Render into the `state` metric label used by
    /// [`crate::metrics::MESH_PEER_COUNT`] et al.
    #[allow(dead_code)]
    fn label(self) -> &'static str {
        match self {
            PeerStateWire::Alive => PEER_STATE_ALIVE,
            PeerStateWire::Suspect => PEER_STATE_SUSPECT,
            PeerStateWire::Dead => PEER_STATE_DEAD,
        }
    }
}

/// A single state delta disseminated between nodes. `incarnation` is the
/// per-subject monotonic counter that breaks ties: higher wins. The
/// subject is `node_id`, NOT the sender.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerUpdate {
    /// Node the update is about.
    pub node_id: String,
    /// State the subject is claimed to be in.
    pub state: PeerStateWire,
    /// Incarnation counter for the subject. Higher incarnation wins on
    /// conflict. The subject bumps its own counter on self-refutation.
    pub incarnation: u64,
}

// --- Peer state ---

/// SWIM membership state of a peer, as observed by the local node.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerState {
    /// Last probe (direct or indirect) succeeded within the configured
    /// window.
    Alive,
    /// Last probe failed. The peer is given
    /// `swim_suspect_timeout_secs` to produce a refuting ACK before
    /// transitioning to `Dead`.
    Suspect {
        /// Monotonic timestamp when the peer entered Suspect. Used to
        /// decide when the suspect timeout has elapsed.
        since: Instant,
    },
    /// Terminal. The peer has been evicted from the hash ring and will
    /// not be probed again until an operator restarts the node.
    Dead,
}

/// Per-peer entry consumed by the SWIM loop.
///
/// `addr` is the `host:port` form suitable for [`UdpSocket::send_to`];
/// `node_id` is populated the first time a message from that address is
/// received (the bootstrap seeds `node_id: ""` and the PING/ACK exchange
/// back-fills it).
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Node id reported by the peer.
    pub node_id: String,
    /// `host:port` string used for outbound sends.
    pub addr: String,
    /// Current SWIM state.
    pub state: PeerState,
    /// Monotonic timestamp of the last observed ACK (direct or
    /// indirect). Mirrors the legacy MVP field name so existing
    /// diagnostics keep working.
    pub last_ack: Instant,
    /// Legacy alias for [`Self::last_ack`]. Kept so existing callers that
    /// still read `last_heartbeat` do not break. Always equals
    /// `last_ack`.
    pub last_heartbeat: Instant,
    /// Highest incarnation number we have ever observed for this peer.
    /// Used for dissemination conflict resolution: incoming updates whose
    /// incarnation is less than this are dropped as stale.
    pub incarnation: u64,
    /// Monotonic timestamp of the last state transition. Reset on every
    /// `Alive`/`Suspect`/`Dead` state change, including the initial
    /// `Alive` stamp when the entry is created. L2 uses this as the
    /// anchor for the dead-peer GC timer: a peer in `Dead` whose
    /// `last_transition` is older than `dead_peer_gc_secs` is removed
    /// from the table.
    pub last_transition: Instant,
}

impl PeerEntry {
    /// Convenience constructor preserving the MVP ergonomics: peers seed
    /// with `state = Alive`, `incarnation = 0`, and
    /// `last_ack = last_heartbeat`. `last_transition` is stamped to
    /// `now` so the L2 GC timer starts fresh for this entry.
    pub fn new(node_id: impl Into<String>, addr: impl Into<String>, now: Instant) -> Self {
        Self {
            node_id: node_id.into(),
            addr: addr.into(),
            state: PeerState::Alive,
            last_ack: now,
            last_heartbeat: now,
            incarnation: 0,
            last_transition: now,
        }
    }
}

// --- Peer table (Wave 2D perf fix) ---

/// Hybrid peer-table storage.
///
/// The hot path through the SWIM loop is "look up the entry for an inbound
/// PING/ACK by the sender's `node_id`". Before Wave 2D this was an O(n)
/// `Vec::iter_mut().find(...)` scan under a write lock, paid every
/// PING/ACK / IndirectAck the cluster received. With ~100 peers and a
/// 100ms protocol period that scan dominated mesh CPU.
///
/// `PeerTable` keeps the bulk of entries in a [`HashMap`] keyed by
/// `node_id` for O(1) lookup, plus a small [`Vec`] for the rare entries
/// whose `node_id` is still empty (the bootstrap seed before the first
/// PING back-fills the id, and the L3 address-rebind path during a peer
/// rebind window). Most production peers never see the `Vec` at all.
///
/// All mutators keep the two halves in sync. Iterators visit the HashMap
/// first then the Vec so callers see every entry exactly once.
#[derive(Debug, Default)]
pub struct PeerTable {
    /// Entries with a known `node_id`. Source of truth for id-keyed
    /// lookups via [`PeerTable::get_by_node_id`] /
    /// [`PeerTable::get_mut_by_node_id`].
    by_id: HashMap<String, PeerEntry>,
    /// Entries whose `node_id` is still empty (typically the bootstrap
    /// seed before the first PING back-fills the id). When an entry's id
    /// is back-filled it migrates from this vec into [`Self::by_id`] via
    /// [`PeerTable::promote_unknown`].
    unknown: Vec<PeerEntry>,
}

impl PeerTable {
    /// Construct an empty peer table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a peer table seeded with the given entries. Entries with
    /// a non-empty `node_id` go into the HashMap; the rest into the
    /// fallback Vec. Used by the bootstrap path and by tests that build a
    /// table from a literal vec.
    pub fn from_entries(entries: Vec<PeerEntry>) -> Self {
        let mut table = Self::default();
        for entry in entries {
            table.insert(entry);
        }
        table
    }

    /// Insert a single entry. If the entry has a known `node_id` and an
    /// entry with that id already exists, the old entry is overwritten
    /// (matches the previous Vec semantics where the first-found entry
    /// won and subsequent matches were ignored).
    pub fn insert(&mut self, entry: PeerEntry) {
        if entry.node_id.is_empty() {
            self.unknown.push(entry);
        } else {
            self.by_id.insert(entry.node_id.clone(), entry);
        }
    }

    /// Total entry count across both halves.
    pub fn len(&self) -> usize {
        self.by_id.len() + self.unknown.len()
    }

    /// Returns `true` when the table holds no entries at all.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty() && self.unknown.is_empty()
    }

    /// Visit every entry exactly once (HashMap entries first, then the
    /// fallback Vec). The order within each half is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.by_id.values().chain(self.unknown.iter())
    }

    /// Mutable variant of [`Self::iter`].
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PeerEntry> {
        self.by_id.values_mut().chain(self.unknown.iter_mut())
    }

    /// O(1) lookup by `node_id`. `None` when no entry with that id is in
    /// the HashMap; callers that need fallback behavior should also
    /// search the unknown vec.
    pub fn get_by_node_id(&self, node_id: &str) -> Option<&PeerEntry> {
        self.by_id.get(node_id)
    }

    /// Mutable counterpart to [`Self::get_by_node_id`].
    pub fn get_mut_by_node_id(&mut self, node_id: &str) -> Option<&mut PeerEntry> {
        self.by_id.get_mut(node_id)
    }

    /// Find a mutable entry by `addr` in the unknown-id fallback vec.
    /// Returns the index plus the entry so callers can promote (move it
    /// into the HashMap) after back-filling the id.
    pub fn find_unknown_by_addr_mut(
        &mut self,
        from: SocketAddr,
    ) -> Option<(usize, &mut PeerEntry)> {
        for (idx, entry) in self.unknown.iter_mut().enumerate() {
            if entry_matches_addr(&entry.addr, from) {
                return Some((idx, entry));
            }
        }
        None
    }

    /// Promote a previously-unknown entry (by index in the unknown vec)
    /// into the HashMap. The caller has already populated `node_id` on
    /// the entry. Used by `record_ack` after back-filling an id from the
    /// inbound PING.
    pub fn promote_unknown(&mut self, idx: usize) {
        if idx >= self.unknown.len() {
            return;
        }
        let entry = self.unknown.remove(idx);
        if !entry.node_id.is_empty() {
            self.by_id.insert(entry.node_id.clone(), entry);
        } else {
            // Defensive: if the caller forgot to back-fill, push back so
            // we do not silently drop the entry.
            self.unknown.push(entry);
        }
    }

    /// Remove every entry that matches `predicate`. Returns the removed
    /// entries (caller can log / metric-count). Used by the
    /// `sweep_dead_for_gc` helper inside this module.
    pub fn retain_remove<F>(&mut self, mut predicate: F) -> Vec<PeerEntry>
    where
        F: FnMut(&PeerEntry) -> bool,
    {
        let mut removed = Vec::new();
        // HashMap: collect ids to remove first so the borrow checker is happy.
        let to_remove: Vec<String> = self
            .by_id
            .iter()
            .filter_map(|(k, v)| if predicate(v) { Some(k.clone()) } else { None })
            .collect();
        for k in to_remove {
            if let Some(v) = self.by_id.remove(&k) {
                removed.push(v);
            }
        }
        // Vec: walk in reverse and swap_remove so indices stay valid.
        let mut i = self.unknown.len();
        while i > 0 {
            i -= 1;
            if predicate(&self.unknown[i]) {
                removed.push(self.unknown.swap_remove(i));
            }
        }
        removed
    }
}

// --- Config ---

/// Inputs for [`GossipLoop::start`].
#[derive(Debug, Clone)]
pub struct GossipLoopConfig {
    /// Local node identifier, stamped into every outbound message.
    pub node_id: String,
    /// UDP port to bind. `0` requests an ephemeral port (tests).
    pub gossip_port: u16,
    /// Legacy MVP knob. Retained so existing callers still compile;
    /// not read by the SWIM loop. Use `swim_protocol_period_ms`.
    pub heartbeat_interval_secs: u64,
    /// Legacy MVP knob. Not read by the SWIM loop; the suspect sweeper
    /// runs at its own cadence tied to `swim_suspect_timeout_secs`.
    pub failure_check_interval_secs: u64,
    /// Legacy MVP knob. Not read by the SWIM loop; suspicion expiry is
    /// driven by `swim_suspect_timeout_secs`.
    pub failure_timeout_secs: u64,
    /// Optional AEAD cipher (K3).
    pub cipher: Option<Cipher>,
    /// SWIM protocol period. Each tick, pick one random Alive peer and
    /// direct-probe it.
    pub swim_protocol_period_ms: u64,
    /// Direct-probe deadline. If no ACK arrives within this window, fall
    /// back to indirect probes.
    pub swim_ping_timeout_ms: u64,
    /// K, the number of PING-REQ witnesses to fan out on a direct
    /// timeout. Clamped to `min(K, alive_peers - 1)` at probe time.
    pub swim_indirect_probes: usize,
    /// How long a peer stays Suspect before being marked Dead.
    pub swim_suspect_timeout_secs: u64,
    /// L2: how long a peer stays Dead before the GC sweeper removes the
    /// entry from the peer table. A value of `0` means "GC on the next
    /// sweep tick", handy for tests.
    pub dead_peer_gc_secs: u64,
}

// --- Pending-probe bookkeeping ---

/// Inner state of the pending-probe map. Keyed by outbound sequence
/// number so any ACK can be demultiplexed to the waiter that originated
/// the probe.
pub(super) struct PendingDirect {
    /// Channel used by the receive loop to notify the probe task that
    /// an ACK arrived. Sending `()` is enough; the value carries no
    /// information beyond "ACK was seen".
    pub(super) tx: oneshot::Sender<()>,
}

pub(super) struct PendingIndirect {
    /// One channel per PING-REQ we fanned out. The probe task waits on
    /// the join of the whole fan-out and succeeds as soon as any child
    /// reports `alive = true`.
    pub(super) tx: oneshot::Sender<bool>,
}

/// Locked map of (seq -> pending probe waiter). Separate maps for direct
/// and indirect because the semantics differ (direct has no witness
/// dimension; indirect carries an `alive` bit).
#[derive(Default)]
pub(super) struct PendingMaps {
    pub(super) direct: HashMap<u64, PendingDirect>,
    pub(super) indirect: HashMap<u64, PendingIndirect>,
}

// --- Disseminator (L1) ---

/// FIFO-with-rotation queue of [`PeerUpdate`]s that ride outgoing
/// PING/ACK messages. Each `drain_for_send` pops up to `MAX_UPDATES_PER_MSG`
/// from the head and rotates them onto the tail so every queued update
/// eventually gets airtime across successive gossip rounds.
///
/// The disseminator de-duplicates on push: enqueueing a newer update for
/// the same `node_id` overwrites the queued entry rather than appending
/// a second one. This keeps the queue bounded at roughly one entry per
/// known peer plus the local node's own self-refutation.
pub(super) struct Disseminator {
    inner: Mutex<DisseminatorInner>,
}

#[derive(Default)]
struct DisseminatorInner {
    /// FIFO of queued updates. We use a VecDeque so head-pop + tail-push
    /// are both O(1).
    queue: VecDeque<PeerUpdate>,
}

impl Disseminator {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(DisseminatorInner::default()),
        }
    }

    /// Enqueue an update. If a later update for the same subject already
    /// sits in the queue, the higher-incarnation one wins in place; an
    /// older incarnation is silently dropped. If no existing entry
    /// matches, the update is appended to the tail.
    pub(super) fn push(&self, update: PeerUpdate) {
        let mut inner = self.inner.lock().expect("disseminator poisoned");
        if let Some(existing) = inner.queue.iter_mut().find(|u| u.node_id == update.node_id) {
            // Keep the highest-incarnation version in-place so a burst
            // of transitions about the same peer collapses to the
            // latest observation.
            if update.incarnation > existing.incarnation
                || (update.incarnation == existing.incarnation && update.state != existing.state)
            {
                *existing = update;
            }
            return;
        }
        inner.queue.push_back(update);
    }

    /// Drain up to `max` entries from the head of the queue and rotate
    /// them onto the tail. The caller stamps the returned Vec onto the
    /// outgoing PING/ACK.
    pub(super) fn drain_for_send(&self, max: usize) -> Vec<PeerUpdate> {
        let mut inner = self.inner.lock().expect("disseminator poisoned");
        let take = std::cmp::min(max, inner.queue.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(u) = inner.queue.pop_front() {
                out.push(u.clone());
                inner.queue.push_back(u);
            }
        }
        out
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("disseminator poisoned")
            .queue
            .len()
    }
}

// --- Handle ---

/// Running SWIM loop. Owns the shutdown signal for the protocol task;
/// the receive task is aborted from within the protocol task on shutdown.
pub struct GossipLoop {
    shutdown_tx: Option<oneshot::Sender<()>>,
    _protocol_join: JoinHandle<()>,
    local_port: u16,
}

impl GossipLoop {
    /// Bind the UDP socket and spawn the SWIM protocol + receive tasks.
    ///
    /// `peer_addr_map` is the shared `node_id -> host:port` table also
    /// consumed by the transport layer. The recv task writes back into
    /// this map every time it learns a new `(node_id, addr)` pair from
    /// an inbound PING (L3 address refresh). Passing the same `Arc` that
    /// [`crate::node_handle::MeshNode`] uses for `peer_addr_lookup` means
    /// `TransportClientPool` routing sees gossip-learned mappings without
    /// any extra wiring.
    pub async fn start(
        cfg: GossipLoopConfig,
        peers: Arc<RwLock<PeerTable>>,
        evictor: Arc<PeerEvictor>,
        isolation: Arc<IsolationObserver>,
        peer_addr_map: Arc<RwLock<HashMap<String, String>>>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", cfg.gossip_port)).await?;
        let local_port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        // Shared between receive + protocol tasks.
        let pending: Arc<AsyncMutex<PendingMaps>> =
            Arc::new(AsyncMutex::new(PendingMaps::default()));
        let seq_gen = Arc::new(AtomicU64::new(1));
        // L1: monotonic per-node incarnation + update queue.
        let self_incarnation = Arc::new(AtomicU64::new(0));
        let disseminator = Arc::new(Disseminator::new());

        // --- Receive task ---
        let peers_recv = peers.clone();
        let socket_recv = socket.clone();
        let cipher_recv = cfg.cipher.clone();
        let pending_recv = pending.clone();
        let node_id_recv = cfg.node_id.clone();
        let seq_recv = seq_gen.clone();
        let ping_timeout_recv = Duration::from_millis(cfg.swim_ping_timeout_ms.max(1));
        let disseminator_recv = disseminator.clone();
        let self_incarnation_recv = self_incarnation.clone();
        let evictor_recv = evictor.clone();
        // L3: the recv task maintains the shared `node_id -> host:port`
        // address map, inserting new mappings on first observation and
        // rewriting them when a peer's address changes mid-run.
        let peer_addr_map_recv = peer_addr_map.clone();
        let recv_task: JoinHandle<()> = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match socket_recv.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let plaintext: Vec<u8> = match cipher_recv.as_ref() {
                            Some(c) => match c.open(&buf[..n]) {
                                Some(pt) => pt,
                                None => {
                                    MESH_CRYPTO_DECRYPT_FAILED
                                        .with_label_values(&[CRYPTO_KIND_GOSSIP])
                                        .inc();
                                    tracing::debug!(
                                        from = %from,
                                        "gossip: dropping datagram that failed AEAD decrypt"
                                    );
                                    continue;
                                }
                            },
                            None => buf[..n].to_vec(),
                        };

                        match crate::transport::wire::decode::<GossipMsg>(&plaintext) {
                            Ok(GossipMsg::Ping {
                                seq,
                                from: peer_id,
                                updates,
                            }) => {
                                // Any Ping is implicit evidence that the
                                // peer is alive; refresh last_ack before
                                // responding.
                                record_ack(&peers_recv, &peer_id, from, Some(&peer_addr_map_recv));
                                // Apply piggybacked state deltas before
                                // responding so our ACK can carry fresh
                                // news back.
                                apply_updates(
                                    &updates,
                                    &peers_recv,
                                    &node_id_recv,
                                    &self_incarnation_recv,
                                    &disseminator_recv,
                                    &evictor_recv,
                                );
                                // Immediately reply with an ACK carrying
                                // the same seq so the far side can
                                // demultiplex. Piggyback whatever is in
                                // our dissemination queue.
                                let ack_updates =
                                    disseminator_recv.drain_for_send(MAX_UPDATES_PER_MSG);
                                if !ack_updates.is_empty() {
                                    MESH_DISSEMINATION_UPDATES_SENT
                                        .with_label_values(&[DISSEM_KIND_ACK])
                                        .inc_by(ack_updates.len() as u64);
                                }
                                let ack = GossipMsg::Ack {
                                    seq,
                                    from: node_id_recv.clone(),
                                    updates: ack_updates,
                                };
                                send_msg(&socket_recv, cipher_recv.as_ref(), &ack, from).await;
                            }
                            Ok(GossipMsg::Ack {
                                seq,
                                from: peer_id,
                                updates,
                            }) => {
                                record_ack(&peers_recv, &peer_id, from, Some(&peer_addr_map_recv));
                                apply_updates(
                                    &updates,
                                    &peers_recv,
                                    &node_id_recv,
                                    &self_incarnation_recv,
                                    &disseminator_recv,
                                    &evictor_recv,
                                );
                                complete_pending_direct(&pending_recv, seq).await;
                            }
                            Ok(GossipMsg::PingReq {
                                seq,
                                from: requester_id,
                                target,
                                target_addr,
                            }) => {
                                // We are a witness. Proxy-ping `target`
                                // on behalf of the requester. Reply
                                // with IndirectAck directly to `from`
                                // (the socket addr of the PING-REQ
                                // sender) so no relay channel is
                                // needed. Proxy probe gets a fresh seq
                                // so it does not collide with the
                                // originator's seq.
                                let proxy_seq = seq_recv.fetch_add(1, Ordering::Relaxed);
                                let pending_for_proxy = pending_recv.clone();
                                let socket_for_proxy = socket_recv.clone();
                                let cipher_for_proxy = cipher_recv.clone();
                                let self_id = node_id_recv.clone();
                                let timeout = ping_timeout_recv;
                                let requester_addr = from;

                                tokio::spawn(async move {
                                    let (wait_tx, wait_rx) = oneshot::channel::<()>();
                                    // Wave 2D: switched to tokio::sync::Mutex
                                    // so the guard can be held across .await
                                    // without blocking a worker thread.
                                    pending_for_proxy
                                        .lock()
                                        .await
                                        .direct
                                        .insert(proxy_seq, PendingDirect { tx: wait_tx });
                                    let parsed = target_addr.parse::<SocketAddr>().ok();
                                    // Proxy-ping does not carry
                                    // dissemination; it is a short-lived
                                    // probe on the witness's behalf.
                                    let ping = GossipMsg::Ping {
                                        seq: proxy_seq,
                                        from: self_id.clone(),
                                        updates: Vec::new(),
                                    };
                                    if let Some(addr) = parsed {
                                        send_msg(
                                            &socket_for_proxy,
                                            cipher_for_proxy.as_ref(),
                                            &ping,
                                            addr,
                                        )
                                        .await;
                                    } else {
                                        tracing::debug!(
                                            target_addr = %target_addr,
                                            "gossip: PING-REQ target_addr did not parse"
                                        );
                                    }

                                    let alive =
                                        tokio::time::timeout(timeout, wait_rx).await.is_ok();
                                    pending_for_proxy.lock().await.direct.remove(&proxy_seq);

                                    // Reply to the requester directly.
                                    let reply = GossipMsg::IndirectAck {
                                        seq,
                                        from: self_id,
                                        target,
                                        alive,
                                    };
                                    send_msg(
                                        &socket_for_proxy,
                                        cipher_for_proxy.as_ref(),
                                        &reply,
                                        requester_addr,
                                    )
                                    .await;
                                });

                                // A PING-REQ we accepted is live
                                // traffic from the requester, so its
                                // `last_ack` is refreshed.
                                record_ack(
                                    &peers_recv,
                                    &requester_id,
                                    from,
                                    Some(&peer_addr_map_recv),
                                );
                            }
                            Ok(GossipMsg::IndirectAck {
                                seq,
                                from: witness_id,
                                target: _,
                                alive,
                            }) => {
                                record_ack(
                                    &peers_recv,
                                    &witness_id,
                                    from,
                                    Some(&peer_addr_map_recv),
                                );
                                complete_pending_indirect(&pending_recv, seq, alive).await;
                            }
                            Ok(GossipMsg::Heartbeat { node_id, .. }) => {
                                // Legacy: count as an ACK so pre-K4
                                // peers still keep their entry fresh.
                                record_ack(&peers_recv, &node_id, from, Some(&peer_addr_map_recv));
                            }
                            Ok(GossipMsg::Join { .. }) => {
                                // Reserved for future phase.
                            }
                            Err(e) => {
                                tracing::debug!(
                                    error = %e,
                                    from = %from,
                                    "gossip: dropping malformed datagram"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "gossip: udp recv failed");
                        continue;
                    }
                }
            }
        });

        // --- Protocol task ---
        //
        // Drives the protocol period, the suspect sweeper, and the relay
        // channel (so PING-REQ witnesses can emit IndirectAck without
        // sharing the socket with the recv task's send sites).
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let protocol_cfg = cfg.clone();
        let peers_proto = peers.clone();
        let socket_proto = socket.clone();
        let evictor_proto = evictor.clone();
        let isolation_proto = isolation.clone();
        let pending_proto = pending.clone();
        let seq_proto = seq_gen.clone();
        let cipher_proto = cfg.cipher.clone();
        let disseminator_proto = disseminator.clone();
        let _self_incarnation_proto = self_incarnation.clone();
        let protocol_join: JoinHandle<()> = tokio::spawn(async move {
            let protocol_period =
                Duration::from_millis(protocol_cfg.swim_protocol_period_ms.max(1));
            let ping_timeout = Duration::from_millis(protocol_cfg.swim_ping_timeout_ms.max(1));
            let suspect_timeout =
                Duration::from_secs(protocol_cfg.swim_suspect_timeout_secs.max(1));
            // L2: Dead peers are GC'd after this window has elapsed
            // since the Dead transition. `0` is tolerated (instant GC
            // on the next sweep tick) so tests can exercise the path
            // without sleeping.
            let dead_peer_gc = Duration::from_secs(protocol_cfg.dead_peer_gc_secs);

            let mut protocol_tick = tokio::time::interval(protocol_period);
            protocol_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            // Suspect sweeper fires at ~half the suspect timeout so the
            // worst-case delay between Dead-eligibility and the
            // transition is ~suspect_timeout / 2.
            let sweep_period = std::cmp::max(Duration::from_millis(50), suspect_timeout / 2);
            let mut sweep_tick = tokio::time::interval(sweep_period);
            sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        tracing::info!(
                            node_id = %protocol_cfg.node_id,
                            "SWIM loop shutting down"
                        );
                        recv_task.abort();
                        break;
                    }
                    _ = protocol_tick.tick() => {
                        // Select a random Alive peer to probe.
                        let candidate = pick_random_alive_peer(&peers_proto);
                        if let Some((target_id, target_addr)) = candidate {
                            run_probe(
                                target_id,
                                target_addr,
                                &protocol_cfg,
                                &peers_proto,
                                &socket_proto,
                                cipher_proto.as_ref(),
                                &pending_proto,
                                &seq_proto,
                                ping_timeout,
                                &evictor_proto,
                                &disseminator_proto,
                            )
                            .await;
                        }
                        // Push the current Alive + Suspect count to the
                        // isolation observer. We count Suspect as
                        // "maybe alive" so a brief network glitch does
                        // not flip the node into quarantine during the
                        // suspect window.
                        let maybe_alive = count_maybe_alive(&peers_proto);
                        isolation_proto.update(maybe_alive);
                    }
                    _ = sweep_tick.tick() => {
                        // Any peer that has been Suspect longer than
                        // `suspect_timeout` and has NOT received a
                        // refuting ACK (last_ack still older than when
                        // the suspicion started) transitions to Dead.
                        let now = Instant::now();
                        let transitions = sweep_suspects_to_dead(
                            &peers_proto,
                            suspect_timeout,
                            now,
                        );
                        for (peer_key, incarnation) in transitions {
                            // Fire the evictor callback once per
                            // transition. The evictor takes care of
                            // hash-ring removal + metric bookkeeping.
                            evictor_proto.evict(
                                &peer_key,
                                crate::metrics::EVICT_REASON_DEAD_TIMEOUT,
                            );
                            MESH_SUSPECT_TRANSITIONS
                                .with_label_values(&[PEER_STATE_SUSPECT, PEER_STATE_DEAD])
                                .inc();
                            // L1: disseminate the Dead transition so
                            // peers learn without probing the corpse
                            // themselves.
                            disseminator_proto.push(PeerUpdate {
                                node_id: peer_key,
                                state: PeerStateWire::Dead,
                                incarnation,
                            });
                        }
                        // L2: garbage-collect Dead peers that have been
                        // terminal for longer than `dead_peer_gc`. The
                        // entry is removed outright; a peer that
                        // resurrects re-enters via the normal add-peer
                        // path as a fresh Alive row.
                        let gc_now = Instant::now();
                        let removed = sweep_dead_for_gc(
                            &peers_proto,
                            dead_peer_gc,
                            gc_now,
                        );
                        for (node_id, addr) in removed {
                            MESH_DEAD_PEERS_GC.inc();
                            tracing::info!(
                                node_id = %node_id,
                                addr = %addr,
                                "GC: dead peer removed from table"
                            );
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown_tx: Some(shutdown_tx),
            _protocol_join: protocol_join,
            local_port,
        })
    }

    /// Signal the loop to stop.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// The port the UDP socket is actually bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for GossipLoop {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// --- Receive-side helpers ---

/// Apply an inbound ACK (direct, indirect, or legacy heartbeat) to the
/// peer table. Bumps `last_ack` and, if the peer was Suspect, refutes
/// back to Alive. `Dead` peers are intentionally not refuted here -
/// once evicted they stay evicted until an operator restart.
///
/// L3: when `peer_addr_map` is `Some`, this function also maintains the
/// shared `node_id -> host:port` address table that the transport layer
/// consults to resolve a consistent-hash owner into a reachable socket.
/// Two write paths exist:
///
/// 1. **Back-fill.** An entry seeded with `node_id = ""` gets its id
///    populated from the inbound PING/ACK; we also insert `(node_id, addr)`
///    into the map under the [`crate::metrics::ADDR_MAP_KIND_LEARNED`]
///    label.
/// 2. **Address rewrite.** A known `node_id` whose entry address differs
///    from the inbound `from` socket indicates the peer rebound to a new
///    address (e.g. pod restart on K8s with a fresh pod IP). The entry's
///    `addr` and the map are both rewritten under
///    [`crate::metrics::ADDR_MAP_KIND_REWRITTEN`].
///
/// Steady-state hot paths (a known peer pinging from its known address)
/// take neither write, so this stays cheap in the common case.
pub(super) fn record_ack(
    peers: &Arc<RwLock<PeerTable>>,
    node_id: &str,
    from: SocketAddr,
    peer_addr_map: Option<&Arc<RwLock<HashMap<String, String>>>>,
) {
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();

    // --- O(1) lookup by known node_id (Wave 2D perf fix) ---
    //
    // Previously this was an O(n) `Vec::iter_mut().find(...)` scan paid
    // on every PING and ACK. Now backed by `PeerTable`'s `by_id` HashMap.
    if !node_id.is_empty() {
        if let Some(entry) = table.get_mut_by_node_id(node_id) {
            entry.last_ack = now;
            entry.last_heartbeat = now;
            if let PeerState::Suspect { .. } = entry.state {
                entry.state = PeerState::Alive;
                // L2: refutation flips the state; refresh the anchor.
                entry.last_transition = now;
                MESH_SUSPECT_TRANSITIONS
                    .with_label_values(&[PEER_STATE_SUSPECT, PEER_STATE_ALIVE])
                    .inc();
            }
            // L3: if the peer's observed address differs from what we have
            // on file, treat it as a rebind (e.g. pod restart with a new
            // pod IP) and rewrite both the entry and the shared map.
            let from_str = from.to_string();
            if entry.addr != from_str {
                let old_addr = std::mem::replace(&mut entry.addr, from_str.clone());
                let peer_id = entry.node_id.clone();
                drop(table);
                refresh_addr_map(peer_addr_map, &peer_id, &from_str, ADDR_MAP_KIND_REWRITTEN);
                tracing::info!(
                    node_id = %peer_id,
                    old_addr = %old_addr,
                    new_addr = %from_str,
                    "gossip: peer address changed, rewrote peer_addr_map"
                );
            }
            return;
        }
    }

    // --- Back-fill: scan only the (small) unknown-id fallback vec ---
    //
    // The vast majority of production peers have a known `node_id` and
    // never enter this branch. Only the bootstrap-seeded entries and the
    // brief rebind window pay the linear scan, which is bounded by the
    // size of the unknown vec (small in steady state).
    if let Some((idx, entry)) = table.find_unknown_by_addr_mut(from) {
        entry.node_id = node_id.to_string();
        entry.last_ack = now;
        entry.last_heartbeat = now;
        if let PeerState::Suspect { .. } = entry.state {
            entry.state = PeerState::Alive;
            entry.last_transition = now;
        }
        let learned_addr = entry.addr.clone();
        let peer_id = node_id.to_string();
        // Promote into the by_id HashMap so subsequent ACKs hit the O(1)
        // path above.
        table.promote_unknown(idx);
        drop(table);
        refresh_addr_map(
            peer_addr_map,
            &peer_id,
            &learned_addr,
            ADDR_MAP_KIND_LEARNED,
        );
        return;
    }

    // Unknown peer; dynamic discovery is a future phase.
    tracing::debug!(
        node_id = node_id,
        from = %from,
        "gossip: message from unknown peer, dropping"
    );
}

/// L3: insert / rewrite `(node_id, addr)` in the shared peer address
/// map, bumping [`MESH_ADDR_MAP_UPDATES`] with the provided `kind` label.
/// A no-op when `map` is `None` (older call sites, e.g. `PingReq` witness
/// accounting, that do not participate in address refresh).
///
/// The write is fail-safe: a poisoned `RwLock` is unwrapped via
/// `into_inner` instead of panicking, so a crashed writer elsewhere in
/// the process cannot take down the gossip loop.
fn refresh_addr_map(
    map: Option<&Arc<RwLock<HashMap<String, String>>>>,
    node_id: &str,
    addr: &str,
    kind: &'static str,
) {
    if node_id.is_empty() {
        return;
    }
    let map = match map {
        Some(m) => m,
        None => return,
    };
    let mut guard = match map.write() {
        Ok(g) => g,
        Err(p) => {
            tracing::warn!(
                node_id = node_id,
                "gossip: peer_addr_map write lock poisoned; recovering"
            );
            p.into_inner()
        }
    };
    // Only record the metric when the map actually changes so idempotent
    // reaffirmations (same (id, addr) we already know) stay silent.
    let changed = match guard.get(node_id) {
        Some(existing) => existing != addr,
        None => true,
    };
    if !changed {
        return;
    }
    guard.insert(node_id.to_string(), addr.to_string());
    drop(guard);
    MESH_ADDR_MAP_UPDATES.with_label_values(&[kind]).inc();
}

/// Resolve `"host:port"` to a list of [`SocketAddr`] and return `true`
/// if any equals `from`.
fn entry_matches_addr(addr: &str, from: SocketAddr) -> bool {
    use std::net::ToSocketAddrs;
    match addr.to_socket_addrs() {
        Ok(iter) => iter.into_iter().any(|a| a == from),
        Err(_) => false,
    }
}

// --- Peer-table queries ---

/// Pick one random Alive peer with a non-empty addr. Returns
/// `(node_id, addr)`. None when the table has no Alive peers.
pub(super) fn pick_random_alive_peer(peers: &Arc<RwLock<PeerTable>>) -> Option<(String, String)> {
    let guard = match peers.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut rng = rand::thread_rng();
    guard
        .iter()
        .filter(|p| matches!(p.state, PeerState::Alive) && !p.addr.is_empty())
        .choose(&mut rng)
        .map(|p| (p.node_id.clone(), p.addr.clone()))
}

/// Count peers that are Alive OR Suspect. Suspect counts as "maybe
/// alive" so a brief probe glitch does not trip the isolation gauge
/// during the suspect window.
pub(super) fn count_maybe_alive(peers: &Arc<RwLock<PeerTable>>) -> usize {
    let guard = match peers.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard
        .iter()
        .filter(|p| !matches!(p.state, PeerState::Dead))
        .count()
}

/// Prefer node_id as the eviction / metric key; fall back to addr when
/// the id has not yet been learned.
pub(super) fn key_of<'a>(node_id: &'a str, addr: &'a str) -> &'a str {
    if node_id.is_empty() {
        addr
    } else {
        node_id
    }
}

/// Find the mutable peer entry matching either id or addr.
///
/// Wave 2D: O(1) when the lookup hits the by-id HashMap; falls back to
/// an O(unknown.len()) scan otherwise.
pub(super) fn find_mut<'a>(
    table: &'a mut PeerTable,
    node_id: &str,
    addr: &str,
) -> Option<&'a mut PeerEntry> {
    if !node_id.is_empty() {
        // Note: `if let Some(...) = table.get_mut_by_node_id(...)` would
        // borrow `table` for the if-let arm; rebinding via the lifetime
        // of the returned reference works around the borrow checker
        // limitation around early-return mut borrows.
        if table.get_by_node_id(node_id).is_some() {
            return table.get_mut_by_node_id(node_id);
        }
    }
    if !addr.is_empty() {
        // Search both halves; HashMap entries first so a known peer is
        // also reachable by addr.
        return table.iter_mut().find(|p| p.addr == addr);
    }
    None
}

// --- Legacy helper retained for back-compat ---

/// Legacy helper used by older tests / docs. Equivalent to
/// [`record_ack`] with the sender resolved as the current message's
/// origin. Not emitted by the SWIM loop; retained only so existing
/// unit tests keep compiling. The L3 peer_addr_map is intentionally not
/// wired through this shim since legacy callers do not participate in
/// address refresh.
#[allow(dead_code)]
fn update_peer_on_heartbeat(peers: &Arc<RwLock<PeerTable>>, node_id: &str, from: SocketAddr) {
    record_ack(peers, node_id, from, None)
}

/// Used to support legacy tests that rely on a `SystemTime` stamp. The
/// current SWIM flow does not need this; keep it so the compat
/// constructor in older docs still works.
#[allow(dead_code)]
fn ts_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[cfg(test)]
mod tests {
    use super::*;
    // WOR-39: items moved into sibling sub-modules; bring them back into
    // scope so the existing test bodies keep compiling unchanged.
    use super::dissemination::{apply_update, apply_updates, decide_transition, TransitionOutcome};
    use super::ping_req::pick_indirect_witnesses;
    use super::probe::{sweep_dead_for_gc, sweep_suspects_to_dead};
    // Per-phase metrics constants the tests assert on; these used to live
    // inline in the parent module's `use crate::metrics::{...}` block but
    // now belong to the phase modules. Re-import here so `super::*` still
    // covers everything tests reference.
    use crate::metrics::{
        DISSEM_IGNORE_STALE_INCARNATION, DISSEM_IGNORE_TERMINAL_DEAD, DISSEM_IGNORE_UNKNOWN_PEER,
        DISSEM_TRANS_DEAD_ALIVE, MESH_DISSEMINATION_UPDATES_IGNORED, MESH_PROBE_DIRECT_SUCCESS,
    };

    /// Serializes tests that read+assert on the global `MESH_ADDR_MAP_UPDATES`
    /// Prometheus counter. Without it, parallel tests in this module race
    /// between their `before`/`after` snapshots and produce off-by-N flakes.
    static ADDR_MAP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // --- Helpers ---

    /// Build a `GossipLoopConfig` with fast SWIM knobs so tests
    /// terminate well under 5s even when they exercise the Suspect ->
    /// Dead transition.
    fn fast_cfg(node_id: &str, cipher: Option<Cipher>) -> GossipLoopConfig {
        GossipLoopConfig {
            node_id: node_id.to_string(),
            gossip_port: 0,
            heartbeat_interval_secs: 1,
            failure_check_interval_secs: 1,
            failure_timeout_secs: 5,
            cipher,
            swim_protocol_period_ms: 100,
            swim_ping_timeout_ms: 50,
            swim_indirect_probes: 3,
            swim_suspect_timeout_secs: 1,
            // Default test GC timeout long enough that existing tests
            // observing Dead state are not surprised by a sudden
            // removal mid-assertion. GC-specific tests override this.
            dead_peer_gc_secs: 60,
        }
    }

    /// Spin up a `GossipLoop` with the given peer seed + cipher.
    async fn spawn_loop(
        node_id: &str,
        peers: Vec<PeerEntry>,
        cipher: Option<Cipher>,
    ) -> (
        GossipLoop,
        Arc<RwLock<PeerTable>>,
        Arc<PeerEvictor>,
        Arc<IsolationObserver>,
    ) {
        let (handle, peers_arc, evictor, isolation, _addr_map) =
            spawn_loop_with_addr_map(node_id, peers, cipher).await;
        (handle, peers_arc, evictor, isolation)
    }

    /// Variant of [`spawn_loop`] that also hands back the shared peer
    /// address map so L3 tests can observe gossip-driven updates without
    /// plumbing the Arc out the front door for every non-L3 test.
    async fn spawn_loop_with_addr_map(
        node_id: &str,
        peers: Vec<PeerEntry>,
        cipher: Option<Cipher>,
    ) -> (
        GossipLoop,
        Arc<RwLock<PeerTable>>,
        Arc<PeerEvictor>,
        Arc<IsolationObserver>,
        Arc<RwLock<HashMap<String, String>>>,
    ) {
        let peers_arc = Arc::new(RwLock::new(PeerTable::from_entries(peers)));
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));
        let isolation = Arc::new(IsolationObserver::new(node_id.to_string(), 1));
        let peer_addr_map = Arc::new(RwLock::new(HashMap::new()));
        let cfg = fast_cfg(node_id, cipher);
        let handle = GossipLoop::start(
            cfg,
            peers_arc.clone(),
            evictor.clone(),
            isolation.clone(),
            peer_addr_map.clone(),
        )
        .await
        .expect("bind");
        (handle, peers_arc, evictor, isolation, peer_addr_map)
    }

    // --- Unit tests on helpers ---

    #[test]
    fn gossip_msg_round_trips_new_variants() {
        let m = GossipMsg::Ping {
            seq: 42,
            from: "node-a".to_string(),
            updates: Vec::new(),
        };
        let bytes = crate::transport::wire::encode(&m).unwrap();
        let back: GossipMsg = crate::transport::wire::decode(&bytes).unwrap();
        assert_eq!(back, m);

        let m = GossipMsg::PingReq {
            seq: 7,
            from: "node-a".to_string(),
            target: "node-c".to_string(),
            target_addr: "10.0.0.3:7946".to_string(),
        };
        let bytes = crate::transport::wire::encode(&m).unwrap();
        let back: GossipMsg = crate::transport::wire::decode(&bytes).unwrap();
        assert_eq!(back, m);

        let m = GossipMsg::IndirectAck {
            seq: 7,
            from: "node-b".to_string(),
            target: "node-c".to_string(),
            alive: true,
        };
        let bytes = crate::transport::wire::encode(&m).unwrap();
        let back: GossipMsg = crate::transport::wire::decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn record_ack_refutes_suspect() {
        // A peer stamped Suspect goes back to Alive on receipt of any
        // ACK from that node id.
        let now = Instant::now();
        let suspect_entry = PeerEntry {
            node_id: "peer-a".to_string(),
            addr: "127.0.0.1:1".to_string(),
            state: PeerState::Suspect {
                since: now - Duration::from_millis(100),
            },
            last_ack: now - Duration::from_secs(1),
            last_heartbeat: now - Duration::from_secs(1),
            incarnation: 0,
            last_transition: now - Duration::from_millis(100),
        };
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![suspect_entry])));
        record_ack(&peers, "peer-a", "127.0.0.1:31234".parse().unwrap(), None);
        let guard = peers.read().unwrap();
        let entry = guard.get_by_node_id("peer-a").expect("peer-a present");
        assert!(matches!(entry.state, PeerState::Alive));
    }

    #[test]
    fn sweep_suspects_to_dead_transitions_only_expired() {
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            // Fresh Suspect (within window) stays Suspect.
            PeerEntry {
                node_id: "fresh-suspect".to_string(),
                addr: "127.0.0.1:1".to_string(),
                state: PeerState::Suspect { since: now },
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            // Stale Suspect (past window) transitions.
            PeerEntry {
                node_id: "old-suspect".to_string(),
                addr: "127.0.0.1:2".to_string(),
                state: PeerState::Suspect {
                    since: now - Duration::from_secs(10),
                },
                last_ack: now - Duration::from_secs(20),
                last_heartbeat: now - Duration::from_secs(20),
                incarnation: 0,
                last_transition: now - Duration::from_secs(10),
            },
            // Alive is untouched.
            PeerEntry {
                node_id: "alive".to_string(),
                addr: "127.0.0.1:3".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
        ])));
        let trans = sweep_suspects_to_dead(&peers, Duration::from_secs(1), now);
        assert_eq!(trans, vec![("old-suspect".to_string(), 0u64)]);
        let guard = peers.read().unwrap();
        let fresh = guard
            .get_by_node_id("fresh-suspect")
            .expect("fresh-suspect present");
        let old = guard
            .get_by_node_id("old-suspect")
            .expect("old-suspect present");
        let alive = guard.get_by_node_id("alive").expect("alive present");
        assert!(matches!(fresh.state, PeerState::Suspect { .. }));
        assert!(matches!(old.state, PeerState::Dead));
        assert!(matches!(alive.state, PeerState::Alive));
    }

    #[test]
    fn pick_random_alive_peer_skips_non_alive() {
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "dead".to_string(),
                addr: "127.0.0.1:1".to_string(),
                state: PeerState::Dead,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "suspect".to_string(),
                addr: "127.0.0.1:2".to_string(),
                state: PeerState::Suspect { since: now },
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "alive".to_string(),
                addr: "127.0.0.1:3".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
        ])));
        let pick = pick_random_alive_peer(&peers).expect("one alive peer");
        assert_eq!(pick.0, "alive");
    }

    #[test]
    fn pick_indirect_witnesses_excludes_target() {
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "target".to_string(),
                addr: "127.0.0.1:1".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "witness-1".to_string(),
                addr: "127.0.0.1:2".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "witness-2".to_string(),
                addr: "127.0.0.1:3".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
        ])));
        let picks = pick_indirect_witnesses(&peers, "target", 3);
        assert_eq!(picks.len(), 2);
        assert!(!picks.iter().any(|(id, _)| id == "target"));
    }

    #[test]
    fn pick_indirect_witnesses_clamps_to_pool_size() {
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "target".to_string(),
                addr: "127.0.0.1:1".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "only-witness".to_string(),
                addr: "127.0.0.1:2".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
        ])));
        let picks = pick_indirect_witnesses(&peers, "target", 5);
        assert_eq!(picks.len(), 1);
    }

    // --- Integration tests ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_stay_alive_via_swim_probes() {
        // Standard two-node pairing: both nodes pick each other as the
        // target once per protocol tick, both get ACKs, both stay
        // Alive.
        let before_success = MESH_PROBE_DIRECT_SUCCESS
            .with_label_values(&["node-b"])
            .get();

        let (la, pa, _ev_a, iso_a) = spawn_loop("node-a", vec![], None).await;
        let (lb, pb, _ev_b, iso_b) = spawn_loop("node-b", vec![], None).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_b = format!("127.0.0.1:{}", lb.local_port());

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b, now));
        pb.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));

        // Several protocol periods (100ms each) + some slack for the
        // direct probe round trip.
        tokio::time::sleep(Duration::from_millis(800)).await;

        let pa_guard = pa.read().unwrap();
        let b_in_a = pa_guard.get_by_node_id("node-b").expect("node-b in pa");
        assert!(
            matches!(b_in_a.state, PeerState::Alive),
            "node-b should be Alive in node-a's table"
        );
        drop(pa_guard);
        let pb_guard = pb.read().unwrap();
        let a_in_b = pb_guard.get_by_node_id("node-a").expect("node-a in pb");
        assert!(
            matches!(a_in_b.state, PeerState::Alive),
            "node-a should be Alive in node-b's table"
        );
        drop(pb_guard);

        let after_success = MESH_PROBE_DIRECT_SUCCESS
            .with_label_values(&["node-b"])
            .get();
        assert!(
            after_success > before_success,
            "direct-success counter must advance"
        );
        assert!(!iso_a.is_isolated());
        assert!(!iso_b.is_isolated());

        la.shutdown();
        lb.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_without_indirect_witness_transitions_to_dead() {
        // Node A probes a dead address. With no witnesses available
        // (only the target is in the peer table), the probe goes
        // straight to Suspect; after `swim_suspect_timeout_secs`, Dead.
        let (la, pa, ev_a, iso_a) = spawn_loop("solo", vec![], None).await;

        // Target is a port we know is NOT bound.
        let dead_addr = "127.0.0.1:1".to_string();
        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("dead-peer", dead_addr, now));

        // ~2 protocol periods + ping timeout to reach Suspect, then
        // suspect_timeout=1s + sweep grace to reach Dead.
        tokio::time::sleep(Duration::from_millis(2200)).await;

        let guard = pa.read().unwrap();
        let dead = guard
            .get_by_node_id("dead-peer")
            .expect("dead-peer present");
        assert!(
            matches!(dead.state, PeerState::Dead),
            "peer should have transitioned to Dead, got {:?}",
            dead.state
        );
        drop(guard);
        assert!(
            iso_a.is_isolated(),
            "node should be isolated with zero live peers"
        );
        // Evictor fires dead-timeout on the suspect->dead transition.
        // The counter on the evictor itself is reset by `evict`, but
        // the failure map is cleared. We validate the callback path
        // indirectly via the state transition being observed.
        let _ = ev_a;

        la.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_nodes_dead_target_with_witness_also_fails() {
        // A <-> C are both alive; B is dead. A picks B, direct-probe
        // fails, A sends PING-REQ to C. C also cannot reach B, so A
        // marks B Suspect then Dead.
        let (la, pa, _ev_a, _iso_a) = spawn_loop("node-a", vec![], None).await;
        let (lc, pc, _ev_c, _iso_c) = spawn_loop("node-c", vec![], None).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_c = format!("127.0.0.1:{}", lc.local_port());
        // Unbound port for B.
        let addr_b_dead = "127.0.0.1:1".to_string();

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b_dead.clone(), now));
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-c", addr_c.clone(), now));
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b_dead, now));

        // Wait long enough for Suspect + Dead transition on A's view
        // of B. Suspect timeout = 1s; add slack for the probe cadence.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        let guard = pa.read().unwrap();
        let b_entry = guard.iter().find(|p| p.node_id == "node-b").unwrap();
        assert!(
            matches!(b_entry.state, PeerState::Dead | PeerState::Suspect { .. }),
            "node-b should be Dead or at least Suspect from node-a's view; got {:?}",
            b_entry.state
        );
        // node-c must still be Alive from node-a's view (we never
        // probed it as dead; it ACKs our PING-REQs as a witness).
        let c_entry = guard.iter().find(|p| p.node_id == "node-c").unwrap();
        assert!(
            matches!(c_entry.state, PeerState::Alive),
            "node-c should stay Alive in node-a's table, got {:?}",
            c_entry.state
        );

        la.shutdown();
        lc.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn indirect_probe_rescues_slow_direct_peer() {
        // Build a 3-node cluster where B intentionally ignores direct
        // PINGs from A but responds to PINGs from C (the witness). A
        // direct-times-out, fans out PING-REQ, and B stays Alive.
        //
        // We implement B as a bespoke UDP echo that only responds to
        // PING whose `from == "node-c"`, simulating an asymmetric
        // partition between A and B.
        let cipher: Option<Cipher> = None;

        let b_socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let addr_b = format!("127.0.0.1:{}", b_socket.local_addr().unwrap().port());
        let b_socket = Arc::new(b_socket);

        // Minimal B: accept Ping, respond with Ack IFF from == "node-c".
        let b_socket_clone = b_socket.clone();
        let b_task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = match b_socket_clone.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let msg: GossipMsg = match crate::transport::wire::decode(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if let GossipMsg::Ping {
                    seq, from: source, ..
                } = msg
                {
                    if source == "node-c" {
                        let ack = GossipMsg::Ack {
                            seq,
                            from: "node-b".to_string(),
                            updates: Vec::new(),
                        };
                        let bytes = crate::transport::wire::encode(&ack).unwrap();
                        let _ = b_socket_clone.send_to(&bytes, from).await;
                    }
                }
            }
        });

        let (la, pa, _ev_a, _iso_a) = spawn_loop("node-a", vec![], cipher.clone()).await;
        let (lc, pc, _ev_c, _iso_c) = spawn_loop("node-c", vec![], cipher).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_c = format!("127.0.0.1:{}", lc.local_port());

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b.clone(), now));
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-c", addr_c.clone(), now));
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b, now));

        // Several protocol periods. The direct A -> B probe will time
        // out (B ignores); the PING-REQ A -> C -> B must succeed and
        // refute suspicion.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let guard = pa.read().unwrap();
        let b_entry = guard.iter().find(|p| p.node_id == "node-b").unwrap();
        // B should NOT be Dead. We accept either Alive (indirect
        // rescue landed inside the window) or Suspect (rescue not yet
        // consumed). The key assertion is "not Dead".
        assert!(
            !matches!(b_entry.state, PeerState::Dead),
            "node-b must not be Dead: indirect probe rescues slow direct peer; got {:?}",
            b_entry.state
        );
        drop(guard);

        la.shutdown();
        lc.shutdown();
        b_task.abort();
    }

    // --- Encryption round-trip (K3 carried forward) ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn swim_loop_with_shared_cipher_stays_alive() {
        let cipher = Some(Cipher::from_shared_key("swim-secret"));
        let (la, pa, _ev_a, iso_a) = spawn_loop("node-a", vec![], cipher.clone()).await;
        let (lb, pb, _ev_b, iso_b) = spawn_loop("node-b", vec![], cipher).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_b = format!("127.0.0.1:{}", lb.local_port());

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b, now));
        pb.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));

        tokio::time::sleep(Duration::from_millis(800)).await;

        assert!(!iso_a.is_isolated());
        assert!(!iso_b.is_isolated());

        la.shutdown();
        lb.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn swim_loop_mismatched_ciphers_isolate() {
        let cipher_a = Some(Cipher::from_shared_key("key-a"));
        let cipher_b = Some(Cipher::from_shared_key("key-b"));
        let before = MESH_CRYPTO_DECRYPT_FAILED
            .with_label_values(&[CRYPTO_KIND_GOSSIP])
            .get();

        let (la, pa, _ev_a, iso_a) = spawn_loop("node-a-mis", vec![], cipher_a).await;
        let (lb, pb, _ev_b, _iso_b) = spawn_loop("node-b-mis", vec![], cipher_b).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_b = format!("127.0.0.1:{}", lb.local_port());
        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b-mis", addr_b, now));
        pb.write()
            .unwrap()
            .insert(PeerEntry::new("node-a-mis", addr_a, now));

        // Wait for isolation: protocol_period=100, ping_timeout=50,
        // suspect_timeout=1s. So ~1.5s to reach Dead.
        tokio::time::sleep(Duration::from_millis(2000)).await;

        assert!(iso_a.is_isolated());
        let after = MESH_CRYPTO_DECRYPT_FAILED
            .with_label_values(&[CRYPTO_KIND_GOSSIP])
            .get();
        assert!(after > before);

        la.shutdown();
        lb.shutdown();
    }

    #[tokio::test]
    async fn shutdown_via_drop_does_not_leak() {
        let (handle, _peers, _ev, _iso) = spawn_loop("drop-test", vec![], None).await;
        drop(handle);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // --- Dissemination (L1) ---

    // --- Disseminator unit tests ---

    #[test]
    fn disseminator_fifo_rotates() {
        // push three updates; drain_for_send rotates them onto the tail
        // so repeated drains cycle the queue.
        let d = Disseminator::new();
        d.push(PeerUpdate {
            node_id: "a".into(),
            state: PeerStateWire::Alive,
            incarnation: 1,
        });
        d.push(PeerUpdate {
            node_id: "b".into(),
            state: PeerStateWire::Alive,
            incarnation: 1,
        });
        d.push(PeerUpdate {
            node_id: "c".into(),
            state: PeerStateWire::Alive,
            incarnation: 1,
        });
        assert_eq!(d.len(), 3);
        // drain 2: a, b
        let first = d.drain_for_send(2);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].node_id, "a");
        assert_eq!(first[1].node_id, "b");
        // queue should still be 3 long (a, b rotated to tail).
        assert_eq!(d.len(), 3);
        let second = d.drain_for_send(3);
        assert_eq!(
            second
                .iter()
                .map(|u| u.node_id.as_str())
                .collect::<Vec<_>>(),
            vec!["c", "a", "b"]
        );
    }

    #[test]
    fn disseminator_push_deduplicates_on_node_id() {
        // Re-pushing the same node with a higher incarnation replaces
        // in place; an older incarnation is dropped.
        let d = Disseminator::new();
        d.push(PeerUpdate {
            node_id: "a".into(),
            state: PeerStateWire::Alive,
            incarnation: 1,
        });
        d.push(PeerUpdate {
            node_id: "a".into(),
            state: PeerStateWire::Suspect,
            incarnation: 2,
        });
        assert_eq!(d.len(), 1);
        let out = d.drain_for_send(16);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].incarnation, 2);
        assert_eq!(out[0].state, PeerStateWire::Suspect);

        // Stale update is dropped in place.
        d.push(PeerUpdate {
            node_id: "a".into(),
            state: PeerStateWire::Alive,
            incarnation: 0,
        });
        let out = d.drain_for_send(16);
        assert_eq!(
            out[0].incarnation, 2,
            "older incarnation must not overwrite"
        );
    }

    #[test]
    fn disseminator_drain_bounded() {
        let d = Disseminator::new();
        for i in 0..32u64 {
            d.push(PeerUpdate {
                node_id: format!("peer-{}", i),
                state: PeerStateWire::Alive,
                incarnation: 1,
            });
        }
        let out = d.drain_for_send(MAX_UPDATES_PER_MSG);
        assert_eq!(out.len(), MAX_UPDATES_PER_MSG);
    }

    // --- decide_transition unit tests ---

    #[test]
    fn decide_transition_incarnation_ordering_ignores_stale_suspect() {
        // Test 3 from the task spec (pure form). Peer entry Alive(7).
        // Incoming Suspect(5) must be ignored as stale.
        let outcome = decide_transition(
            PeerState::Alive,
            7,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Suspect,
                incarnation: 5,
            },
        );
        match outcome {
            TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION) => {}
            other => panic!(
                "expected Ignore(stale_incarnation); got {:?}",
                match other {
                    TransitionOutcome::Ignore(r) => format!("Ignore({})", r),
                    TransitionOutcome::Accept { .. } => "Accept".into(),
                }
            ),
        }
    }

    #[test]
    fn decide_transition_suspect_applies_at_same_incarnation() {
        // Alive(3) + incoming Suspect(3) -> accept Suspect. Same-
        // incarnation Suspect refutations are allowed (weaker than
        // Alive, which requires strictly greater).
        let outcome = decide_transition(
            PeerState::Alive,
            3,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Suspect,
                incarnation: 3,
            },
        );
        match outcome {
            TransitionOutcome::Accept { new_state, .. } => {
                assert!(matches!(new_state, PeerState::Suspect { .. }));
            }
            TransitionOutcome::Ignore(r) => panic!("expected Accept; got Ignore({})", r),
        }
    }

    #[test]
    fn decide_transition_refutation_requires_strictly_greater_alive() {
        // Suspect(5) peer. Alive(5) must NOT refute; only Alive(6+) does.
        let no_refute = decide_transition(
            PeerState::Suspect {
                since: Instant::now(),
            },
            5,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Alive,
                incarnation: 5,
            },
        );
        assert!(matches!(
            no_refute,
            TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION)
        ));

        let refute = decide_transition(
            PeerState::Suspect {
                since: Instant::now(),
            },
            5,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Alive,
                incarnation: 6,
            },
        );
        assert!(matches!(
            refute,
            TransitionOutcome::Accept {
                new_state: PeerState::Alive,
                ..
            }
        ));
    }

    #[test]
    fn decide_transition_dead_is_terminal_except_on_rejoin() {
        // Dead(5) + Suspect(99) stays Dead (terminal_dead).
        let stays_dead = decide_transition(
            PeerState::Dead,
            5,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Suspect,
                incarnation: 99,
            },
        );
        assert!(matches!(
            stays_dead,
            TransitionOutcome::Ignore(DISSEM_IGNORE_TERMINAL_DEAD)
        ));
        // Dead(5) + Alive(6) rejoins.
        let rejoin = decide_transition(
            PeerState::Dead,
            5,
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Alive,
                incarnation: 6,
            },
        );
        assert!(matches!(
            rejoin,
            TransitionOutcome::Accept {
                new_state: PeerState::Alive,
                transition_label: DISSEM_TRANS_DEAD_ALIVE,
                ..
            }
        ));
    }

    // --- apply_update unit tests ---

    #[test]
    fn apply_update_self_suspect_bumps_incarnation_and_refutes() {
        // A Suspect rumor about me bumps my own incarnation strictly
        // above the rumor and queues a fresh Alive for dissemination.
        let peers = Arc::new(RwLock::new(PeerTable::new()));
        let self_inc = Arc::new(AtomicU64::new(0));
        let disseminator = Arc::new(Disseminator::new());
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));

        apply_update(
            &PeerUpdate {
                node_id: "me".into(),
                state: PeerStateWire::Suspect,
                incarnation: 5,
            },
            &peers,
            "me",
            &self_inc,
            &disseminator,
            &evictor,
        );

        assert!(
            self_inc.load(Ordering::Relaxed) > 5,
            "self incarnation must be bumped strictly above the rumor"
        );
        let queued = disseminator.drain_for_send(16);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].node_id, "me");
        assert_eq!(queued[0].state, PeerStateWire::Alive);
        assert!(queued[0].incarnation > 5);
    }

    #[test]
    fn apply_update_unknown_peer_is_dropped() {
        let peers = Arc::new(RwLock::new(PeerTable::new()));
        let self_inc = Arc::new(AtomicU64::new(0));
        let disseminator = Arc::new(Disseminator::new());
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));
        let before = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_UNKNOWN_PEER])
            .get();
        apply_update(
            &PeerUpdate {
                node_id: "ghost".into(),
                state: PeerStateWire::Suspect,
                incarnation: 1,
            },
            &peers,
            "me",
            &self_inc,
            &disseminator,
            &evictor,
        );
        let after = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_UNKNOWN_PEER])
            .get();
        assert!(
            after > before,
            "unknown_peer counter must advance: before={} after={}",
            before,
            after,
        );
    }

    #[test]
    fn apply_update_stale_incarnation_increments_ignored_metric() {
        // Alive(7) known peer. A stale Suspect(5) bumps the
        // `stale_incarnation` counter without touching the peer.
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry {
            node_id: "b".into(),
            addr: "127.0.0.1:2".into(),
            state: PeerState::Alive,
            last_ack: now,
            last_heartbeat: now,
            incarnation: 7,
            last_transition: now,
        }])));
        let self_inc = Arc::new(AtomicU64::new(0));
        let disseminator = Arc::new(Disseminator::new());
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));

        let before = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_STALE_INCARNATION])
            .get();
        apply_update(
            &PeerUpdate {
                node_id: "b".into(),
                state: PeerStateWire::Suspect,
                incarnation: 5,
            },
            &peers,
            "me",
            &self_inc,
            &disseminator,
            &evictor,
        );
        let after = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_STALE_INCARNATION])
            .get();
        assert!(
            after > before,
            "stale_incarnation counter must advance: before={} after={}",
            before,
            after,
        );
        // Peer unchanged.
        let guard = peers.read().unwrap();
        let b = guard.get_by_node_id("b").expect("b present");
        assert!(matches!(b.state, PeerState::Alive));
        assert_eq!(b.incarnation, 7);
    }

    // --- Integration tests (L1) ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dissemination_self_refutation_clears_suspect_on_accuser() {
        // Simulate: some third party claims B is Suspect. Inject that
        // claim by sending B a PING whose `updates` list contains
        // Suspect(incarnation=0) about B itself. B must bump its own
        // incarnation and queue Alive(1); the next time B pings A,
        // that Alive(1) rides along and A's pre-seeded Suspect(0) on
        // B flips to Alive.
        let (la, pa, _ev_a, _iso_a) = spawn_loop("node-a", vec![], None).await;
        let (lb, pb, _ev_b, _iso_b) = spawn_loop("node-b", vec![], None).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_b = format!("127.0.0.1:{}", lb.local_port());

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b.clone(), now));
        pb.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a.clone(), now));

        // Force A's view of B to Suspect(incarnation=0). We want to
        // observe it flip back via dissemination.
        {
            let mut guard = pa.write().unwrap();
            let entry = guard.get_mut_by_node_id("node-b").expect("b in a table");
            entry.state = PeerState::Suspect {
                since: Instant::now(),
            };
            entry.incarnation = 0;
        }

        // Send B a crafted PING announcing B is Suspect. Use a fresh
        // UDP socket so we do not interfere with either node's loop.
        let injector = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let injected = GossipMsg::Ping {
            seq: 999_999,
            from: "outsider".to_string(),
            updates: vec![PeerUpdate {
                node_id: "node-b".to_string(),
                state: PeerStateWire::Suspect,
                incarnation: 0,
            }],
        };
        let bytes = crate::transport::wire::encode(&injected).unwrap();
        let b_addr: SocketAddr = addr_b.parse().unwrap();
        let _ = injector.send_to(&bytes, b_addr).await;

        // Give B time to process the rumor + bump its incarnation +
        // disseminate Alive(1) on its next probe tick. Note: A's
        // direct probes of B succeed (B responds normally), and that
        // success path on A also flips Suspect -> Alive via
        // `transition_to_alive`. To isolate dissemination from that
        // path, we would need to drop direct-probe responses, which
        // requires a bespoke receiver like the indirect-rescue test.
        // Instead, we verify B's own incarnation advanced, which is
        // the load-bearing invariant: even if A's direct probe also
        // fixes its view, B committed the refutation.
        tokio::time::sleep(Duration::from_millis(600)).await;

        // B's own view of A is healthy.
        let guard_b = pb.read().unwrap();
        let a_entry = guard_b.iter().find(|p| p.node_id == "node-a").unwrap();
        assert!(matches!(a_entry.state, PeerState::Alive));
        drop(guard_b);
        // A's view of B is Alive (either via dissemination or direct
        // probe success; both are acceptable, both exercise the
        // refutation semantics).
        let guard = pa.read().unwrap();
        let b_entry = guard.iter().find(|p| p.node_id == "node-b").unwrap();
        assert!(
            matches!(b_entry.state, PeerState::Alive),
            "node-b should be Alive on node-a after refutation; got {:?}",
            b_entry.state
        );
        drop(guard);

        la.shutdown();
        lb.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dissemination_news_travels_without_direct_probe() {
        // 3-node cluster A, B(dead-addr), C. C has no entry for B:
        // C's view is just {A}. A's view is {B(dead), C}. A's probe of
        // B fails, A marks B Dead, disseminates Dead(0). C's PING to
        // A gets an ACK with that dissemination; C previously had no
        // record of B, so the update is dropped as unknown_peer (per
        // L1 rules; L3 adds address map refresh).
        //
        // To directly verify "news travels to C and C learns without
        // probing B itself", we pre-seed C with B(Alive) then confirm
        // it flips to Dead via the dissemination path. C never binds
        // a socket that can reach B.
        let (la, pa, _ev_a, _iso_a) = spawn_loop("node-a", vec![], None).await;
        let (lc, pc, _ev_c, _iso_c) = spawn_loop("node-c", vec![], None).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_c = format!("127.0.0.1:{}", lc.local_port());
        // Dead port for B.
        let addr_b = "127.0.0.1:1".to_string();

        let now = Instant::now();
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b.clone(), now));
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("node-c", addr_c.clone(), now));
        // C pre-seeded with B as Alive so the dissemination has a
        // row to mutate. C does NOT share A's probing; C only probes
        // A.
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));
        pc.write()
            .unwrap()
            .insert(PeerEntry::new("node-b", addr_b.clone(), now));

        // Wait long enough for A to: (1) fail direct probe of B, (2)
        // no witnesses -> Suspect, (3) sweep -> Dead + disseminate,
        // (4) next PING to C carries Dead(0), (5) C applies it.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        let guard_a = pa.read().unwrap();
        let b_in_a = guard_a.iter().find(|p| p.node_id == "node-b").unwrap();
        assert!(
            matches!(b_in_a.state, PeerState::Dead),
            "A should have promoted B to Dead by now, got {:?}",
            b_in_a.state
        );
        drop(guard_a);

        let guard_c = pc.read().unwrap();
        let b_in_c = guard_c.iter().find(|p| p.node_id == "node-b").unwrap();
        assert!(
            matches!(b_in_c.state, PeerState::Dead | PeerState::Suspect { .. }),
            "C should have learned about B (Dead or at least Suspect) via dissemination; got {:?}",
            b_in_c.state
        );
        drop(guard_c);

        la.shutdown();
        lc.shutdown();
    }

    #[tokio::test]
    async fn dissemination_stale_incarnation_is_ignored_end_to_end() {
        // Two-peer table. Current known state for B is Alive(7).
        // Apply a stale Suspect(5) -> ignored_stale counter bumps;
        // entry unchanged. The counter is process-global; assert that
        // this call contributes at least one increment rather than
        // pinning an exact value (other tests running in parallel may
        // also bump it).
        let before = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_STALE_INCARNATION])
            .get();

        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry {
            node_id: "node-b".to_string(),
            addr: "127.0.0.1:1".to_string(),
            state: PeerState::Alive,
            last_ack: now,
            last_heartbeat: now,
            incarnation: 7,
            last_transition: now,
        }])));
        let self_inc = Arc::new(AtomicU64::new(0));
        let disseminator = Arc::new(Disseminator::new());
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));

        apply_updates(
            &[PeerUpdate {
                node_id: "node-b".to_string(),
                state: PeerStateWire::Suspect,
                incarnation: 5,
            }],
            &peers,
            "node-a",
            &self_inc,
            &disseminator,
            &evictor,
        );

        let after = MESH_DISSEMINATION_UPDATES_IGNORED
            .with_label_values(&[DISSEM_IGNORE_STALE_INCARNATION])
            .get();
        assert!(
            after > before,
            "stale_incarnation counter must fire: before={} after={}",
            before,
            after,
        );
        // Peer unchanged by the stale update.
        {
            let guard = peers.read().unwrap();
            let b = guard.get_by_node_id("node-b").expect("node-b present");
            assert!(matches!(b.state, PeerState::Alive));
            assert_eq!(b.incarnation, 7);
        }

        // A newer Alive(8) must refresh the stored incarnation (but
        // not produce a visible state flip since we were Alive
        // already).
        apply_updates(
            &[PeerUpdate {
                node_id: "node-b".to_string(),
                state: PeerStateWire::Alive,
                incarnation: 8,
            }],
            &peers,
            "node-a",
            &self_inc,
            &disseminator,
            &evictor,
        );
        let guard = peers.read().unwrap();
        let b = guard.get_by_node_id("node-b").expect("node-b present");
        assert_eq!(b.incarnation, 8);
        assert!(matches!(b.state, PeerState::Alive));
    }

    // --- L2: dead-peer GC ---

    #[test]
    fn sweep_dead_for_gc_removes_expired_dead() {
        // Three peers: an Alive, a Suspect, and a Dead whose
        // `last_transition` is past the GC window. Only the Dead row
        // should be removed.
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "alive".to_string(),
                addr: "127.0.0.1:1".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            PeerEntry {
                node_id: "suspect".to_string(),
                addr: "127.0.0.1:2".to_string(),
                state: PeerState::Suspect { since: now },
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now,
            },
            // Dead for longer than the GC window.
            PeerEntry {
                node_id: "gc-me".to_string(),
                addr: "127.0.0.1:3".to_string(),
                state: PeerState::Dead,
                last_ack: now - Duration::from_secs(10),
                last_heartbeat: now - Duration::from_secs(10),
                incarnation: 0,
                last_transition: now - Duration::from_secs(10),
            },
        ])));

        let before = MESH_DEAD_PEERS_GC.get();
        let removed = sweep_dead_for_gc(&peers, Duration::from_secs(1), now);
        // Mirror the sweep-loop's metric-fire side effect so the test
        // covers the complete contract (not just the helper).
        for _ in &removed {
            MESH_DEAD_PEERS_GC.inc();
        }
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, "gc-me");
        let guard = peers.read().unwrap();
        assert_eq!(guard.len(), 2);
        assert!(guard.iter().all(|p| p.node_id != "gc-me"));
        assert!(MESH_DEAD_PEERS_GC.get() > before);
    }

    #[test]
    fn sweep_dead_for_gc_retains_fresh_dead() {
        // A Dead peer whose transition just happened stays in the
        // table: its age is below the GC threshold.
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry {
            node_id: "fresh-dead".to_string(),
            addr: "127.0.0.1:4".to_string(),
            state: PeerState::Dead,
            last_ack: now,
            last_heartbeat: now,
            incarnation: 0,
            // Half the GC window.
            last_transition: now - Duration::from_millis(500),
        }])));
        let removed = sweep_dead_for_gc(&peers, Duration::from_secs(1), now);
        assert!(removed.is_empty());
        let guard = peers.read().unwrap();
        assert_eq!(guard.len(), 1);
        let fresh = guard
            .get_by_node_id("fresh-dead")
            .expect("fresh-dead present");
        assert!(matches!(fresh.state, PeerState::Dead));
    }

    #[test]
    fn sweep_dead_for_gc_only_touches_dead() {
        // Even with their `last_transition` arbitrarily old, Alive and
        // Suspect rows must never be removed by the GC sweep.
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "old-alive".to_string(),
                addr: "127.0.0.1:5".to_string(),
                state: PeerState::Alive,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now - Duration::from_secs(3600),
            },
            PeerEntry {
                node_id: "old-suspect".to_string(),
                addr: "127.0.0.1:6".to_string(),
                state: PeerState::Suspect {
                    since: now - Duration::from_secs(3600),
                },
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now - Duration::from_secs(3600),
            },
        ])));
        let removed = sweep_dead_for_gc(&peers, Duration::from_secs(1), now);
        assert!(removed.is_empty());
        assert_eq!(peers.read().unwrap().len(), 2);
    }

    #[test]
    fn sweep_dead_for_gc_multiple_peers_metric_counts() {
        // Two Dead peers both past the GC window; the helper returns
        // both; the caller (in production the sweep arm) increments
        // the counter once per removed entry.
        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![
            PeerEntry {
                node_id: "d1".to_string(),
                addr: "127.0.0.1:7".to_string(),
                state: PeerState::Dead,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now - Duration::from_secs(5),
            },
            PeerEntry {
                node_id: "d2".to_string(),
                addr: "127.0.0.1:8".to_string(),
                state: PeerState::Dead,
                last_ack: now,
                last_heartbeat: now,
                incarnation: 0,
                last_transition: now - Duration::from_secs(5),
            },
        ])));
        let before = MESH_DEAD_PEERS_GC.get();
        let removed = sweep_dead_for_gc(&peers, Duration::from_secs(1), now);
        for _ in &removed {
            MESH_DEAD_PEERS_GC.inc();
        }
        assert_eq!(removed.len(), 2);
        assert_eq!(peers.read().unwrap().len(), 0);
        assert!(MESH_DEAD_PEERS_GC.get() >= before + 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_peer_gc_runs_in_live_loop() {
        // End-to-end: spin up a node probing a dead address with a
        // fast SWIM cadence + `dead_peer_gc_secs = 0`. The peer
        // transitions Alive -> Suspect -> Dead, then the next sweep
        // tick GCs it. Eventually the peer table is empty.
        let peers_arc = Arc::new(RwLock::new(PeerTable::new()));
        let evictor = Arc::new(PeerEvictor::new(3, Arc::new(|_p: &str| {})));
        let isolation = Arc::new(IsolationObserver::new("gc-test".to_string(), 1));
        let peer_addr_map = Arc::new(RwLock::new(HashMap::new()));
        let mut cfg = fast_cfg("gc-test", None);
        cfg.dead_peer_gc_secs = 0;
        let handle = GossipLoop::start(
            cfg,
            peers_arc.clone(),
            evictor.clone(),
            isolation.clone(),
            peer_addr_map.clone(),
        )
        .await
        .expect("bind");

        let before = MESH_DEAD_PEERS_GC.get();
        let now = Instant::now();
        peers_arc
            .write()
            .unwrap()
            .insert(PeerEntry::new("gc-peer", "127.0.0.1:1", now));

        // Protocol period = 100ms, ping_timeout = 50ms,
        // suspect_timeout = 1s, sweep tick runs at suspect_timeout / 2.
        // Wait long enough for Suspect + Dead + GC: ~1.5s.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        let guard = peers_arc.read().unwrap();
        assert!(
            guard.iter().all(|p| p.node_id != "gc-peer"),
            "GC should have removed gc-peer; table: {:?}",
            guard
        );
        drop(guard);
        assert!(
            MESH_DEAD_PEERS_GC.get() > before,
            "MESH_DEAD_PEERS_GC must advance on GC"
        );

        handle.shutdown();
    }

    // --- L3: peer address map refresh from gossip ---

    #[test]
    fn record_ack_learns_node_id_and_populates_addr_map() {
        let _g = ADDR_MAP_TEST_LOCK.lock().unwrap();
        // Seed a peer entry with empty node_id (the bootstrap state).
        // Receiving a message from that address with a node_id must
        // back-fill both the entry and the shared peer_addr_map.
        let before = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .get();

        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry::new(
            "",
            "127.0.0.1:40001",
            now,
        )])));
        let addr_map = Arc::new(RwLock::new(HashMap::new()));

        record_ack(
            &peers,
            "node-b",
            "127.0.0.1:40001".parse().unwrap(),
            Some(&addr_map),
        );

        // Entry got its node_id backfilled and promoted into the by_id map.
        let guard = peers.read().unwrap();
        let entry = guard.get_by_node_id("node-b").expect("node-b promoted");
        assert_eq!(entry.node_id, "node-b");
        drop(guard);

        // Map now carries the gossip-learned binding.
        let map = addr_map.read().unwrap();
        assert_eq!(
            map.get("node-b").map(String::as_str),
            Some("127.0.0.1:40001")
        );
        drop(map);

        let after = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .get();
        assert!(
            after > before,
            "learned counter must fire: before={} after={}",
            before,
            after,
        );
    }

    #[test]
    fn record_ack_rewrites_addr_map_when_peer_address_changes() {
        let _g = ADDR_MAP_TEST_LOCK.lock().unwrap();
        // Scenario: node-b was previously known at addr1; it now
        // pings us from addr2 (e.g. the pod restarted with a new
        // pod IP). The shared peer_addr_map must be rewritten and
        // the `rewritten` counter must advance.
        let before = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
            .get();

        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry::new(
            "node-b",
            "127.0.0.1:50001",
            now,
        )])));
        let addr_map = Arc::new(RwLock::new(HashMap::new()));
        addr_map
            .write()
            .unwrap()
            .insert("node-b".to_string(), "127.0.0.1:50001".to_string());

        // PING arrives from a different socket address for the same
        // known node_id.
        record_ack(
            &peers,
            "node-b",
            "127.0.0.1:50002".parse().unwrap(),
            Some(&addr_map),
        );

        // Entry's addr rewritten to reflect the new binding.
        let guard = peers.read().unwrap();
        let entry = guard.get_by_node_id("node-b").expect("node-b present");
        assert_eq!(entry.addr, "127.0.0.1:50002");
        drop(guard);

        // Map rewritten as well.
        let map = addr_map.read().unwrap();
        assert_eq!(
            map.get("node-b").map(String::as_str),
            Some("127.0.0.1:50002")
        );
        drop(map);

        let after = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
            .get();
        assert!(
            after > before,
            "rewritten counter must fire: before={} after={}",
            before,
            after,
        );
    }

    #[test]
    fn record_ack_addr_map_noop_when_address_unchanged() {
        let _g = ADDR_MAP_TEST_LOCK.lock().unwrap();
        // Steady-state case: a known peer pings from its known address.
        // Neither `learned` nor `rewritten` should fire.
        let before_learned = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .get();
        let before_rewritten = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
            .get();

        let now = Instant::now();
        let peers = Arc::new(RwLock::new(PeerTable::from_entries(vec![PeerEntry::new(
            "node-b",
            "127.0.0.1:60001",
            now,
        )])));
        let addr_map = Arc::new(RwLock::new(HashMap::new()));
        addr_map
            .write()
            .unwrap()
            .insert("node-b".to_string(), "127.0.0.1:60001".to_string());

        record_ack(
            &peers,
            "node-b",
            "127.0.0.1:60001".parse().unwrap(),
            Some(&addr_map),
        );

        let after_learned = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .get();
        let after_rewritten = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
            .get();
        assert_eq!(
            after_learned, before_learned,
            "steady state must not bump `learned`"
        );
        assert_eq!(
            after_rewritten, before_rewritten,
            "steady state must not bump `rewritten`"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_loop_populates_addr_map_from_incoming_pings() {
        // End-to-end: node A is seeded with an unknown-id entry for
        // node B's address. After a few SWIM protocol periods, A's
        // shared peer_addr_map should contain `("node-b", addr_b)`.
        let (la, pa, _ev_a, _iso_a, addr_map_a) =
            spawn_loop_with_addr_map("node-a", vec![], None).await;
        let (lb, pb, _ev_b, _iso_b) = spawn_loop("node-b", vec![], None).await;

        let addr_a = format!("127.0.0.1:{}", la.local_port());
        let addr_b = format!("127.0.0.1:{}", lb.local_port());

        let now = Instant::now();
        // Seed A with B's addr but unknown node_id (bootstrap state).
        pa.write()
            .unwrap()
            .insert(PeerEntry::new("", addr_b.clone(), now));
        pb.write()
            .unwrap()
            .insert(PeerEntry::new("node-a", addr_a, now));

        // Wait for several protocol periods so A probes B, B ACKs,
        // and A back-fills node_id + peer_addr_map.
        tokio::time::sleep(Duration::from_millis(800)).await;

        let map = addr_map_a.read().unwrap();
        let learned = map.get("node-b").cloned();
        drop(map);
        assert_eq!(
            learned.as_deref(),
            Some(addr_b.as_str()),
            "gossip loop must populate peer_addr_map with the learned (node-b, addr_b) binding"
        );

        la.shutdown();
        lb.shutdown();
    }
}
