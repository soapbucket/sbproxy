//! Direct-probe (Ping / Ack) orchestration plus the state-transition
//! helpers that fire from probe outcomes.
//!
//! [`run_probe`] is one SWIM protocol round from the originator's side:
//! direct PING, optional PING-REQ fan-out (delegated to [`super::ping_req`]),
//! and the resulting Alive/Suspect transition. The Dead transition runs
//! out of band via [`sweep_suspects_to_dead`] on the suspect-sweeper tick,
//! and the L2 dead-peer GC sweeper [`sweep_dead_for_gc`] removes terminal
//! Dead entries after their grace window.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::crypto::Cipher;
use crate::metrics::{
    DISSEM_KIND_PING, MESH_DISSEMINATION_UPDATES_SENT, MESH_GOSSIP_LATENCY, MESH_GOSSIP_RETRY,
    MESH_PROBE_DIRECT_SUCCESS, MESH_PROBE_DIRECT_TIMEOUT, MESH_PROBE_INDIRECT_SUCCESS,
    MESH_SUSPECT_TRANSITIONS, PEER_STATE_ALIVE, PEER_STATE_DEAD, PEER_STATE_SUSPECT,
};
use crate::peer_eviction::PeerEvictor;

use super::encryption::send_msg;
use super::ping_req::pick_indirect_witnesses;
use super::{
    key_of, Disseminator, GossipLoopConfig, GossipMsg, PeerState, PeerStateWire, PeerTable,
    PeerUpdate, PendingDirect, PendingIndirect, PendingMaps, MAX_UPDATES_PER_MSG,
};

/// Execute one SWIM protocol round against `target`. Fires direct PING,
/// waits up to `ping_timeout`, optionally fans out PING-REQs, and
/// updates the peer's state accordingly.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_probe(
    target_id: String,
    target_addr: String,
    cfg: &GossipLoopConfig,
    peers: &Arc<RwLock<PeerTable>>,
    socket: &Arc<UdpSocket>,
    cipher: Option<&Cipher>,
    pending: &Arc<AsyncMutex<PendingMaps>>,
    seq_gen: &Arc<AtomicU64>,
    ping_timeout: Duration,
    evictor: &Arc<PeerEvictor>,
    disseminator: &Arc<Disseminator>,
) {
    let parsed_addr = match target_addr.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            // Unroutable; skip this round rather than trip the
            // suspect transition on a misconfigured peer.
            tracing::debug!(
                target = %target_id,
                addr = %target_addr,
                "swim: target addr unparseable, skipping probe"
            );
            return;
        }
    };

    // --- Direct probe ---
    let seq = seq_gen.fetch_add(1, Ordering::Relaxed);
    let (ack_tx, ack_rx) = oneshot::channel::<()>();
    pending
        .lock()
        .await
        .direct
        .insert(seq, PendingDirect { tx: ack_tx });

    // L1: piggyback bounded dissemination payload on every outbound
    // PING. An empty vec is fine; the receiver treats it as a no-op.
    let ping_updates = disseminator.drain_for_send(MAX_UPDATES_PER_MSG);
    if !ping_updates.is_empty() {
        MESH_DISSEMINATION_UPDATES_SENT
            .with_label_values(&[DISSEM_KIND_PING])
            .inc_by(ping_updates.len() as u64);
    }
    let ping = GossipMsg::Ping {
        seq,
        from: cfg.node_id.clone(),
        updates: ping_updates,
    };
    let probe_started = Instant::now();
    send_msg(socket, cipher, &ping, parsed_addr).await;

    let direct_ok = tokio::time::timeout(ping_timeout, ack_rx).await.is_ok();
    // Clean up in either case.
    pending.lock().await.direct.remove(&seq);

    let label = if target_id.is_empty() {
        target_addr.as_str()
    } else {
        target_id.as_str()
    };

    if direct_ok {
        MESH_GOSSIP_LATENCY
            .with_label_values(&[label])
            .observe(probe_started.elapsed().as_secs_f64());
        MESH_PROBE_DIRECT_SUCCESS.with_label_values(&[label]).inc();
        transition_to_alive(peers, &target_id, &target_addr, Some(disseminator));
        evictor.record_success(key_of(&target_id, &target_addr));
        return;
    }
    MESH_PROBE_DIRECT_TIMEOUT.with_label_values(&[label]).inc();

    // --- Indirect probe (PING-REQ fan-out) ---
    let witnesses = pick_indirect_witnesses(peers, &target_id, cfg.swim_indirect_probes);

    // No witnesses available (2-node cluster, or only Alive peer is the
    // target we just probed). Skip straight to Suspect.
    if witnesses.is_empty() {
        transition_to_suspect(peers, &target_id, &target_addr, Some(disseminator));
        return;
    }

    // Fan out PING-REQ. The direct probe timed out and the indirect
    // fallback is actually firing, so this counts as one gossip retry
    // attempt against the target (once per attempt, not per witness).
    MESH_GOSSIP_RETRY.with_label_values(&[label]).inc();
    let indirect_seq = seq_gen.fetch_add(1, Ordering::Relaxed);
    let (ind_tx, ind_rx) = oneshot::channel::<bool>();
    pending
        .lock()
        .await
        .indirect
        .insert(indirect_seq, PendingIndirect { tx: ind_tx });

    for (_wit_id, wit_addr) in &witnesses {
        if let Ok(addr) = wit_addr.parse::<SocketAddr>() {
            // PingReq is not piggybacked; it is a short-lived
            // request/reply with the witness. Dissemination rides
            // the separate PING/ACK pair the witness does on our
            // behalf.
            let req = GossipMsg::PingReq {
                seq: indirect_seq,
                from: cfg.node_id.clone(),
                target: target_id.clone(),
                target_addr: target_addr.clone(),
            };
            send_msg(socket, cipher, &req, addr).await;
        }
    }

    // Wait at most 2x ping_timeout: witness does its own direct probe
    // (up to ping_timeout) + one network leg for the IndirectAck.
    let indirect_window = ping_timeout.saturating_mul(2);
    let indirect_ok = match tokio::time::timeout(indirect_window, ind_rx).await {
        Ok(Ok(alive)) => alive,
        _ => false,
    };
    pending.lock().await.indirect.remove(&indirect_seq);

    if indirect_ok {
        MESH_PROBE_INDIRECT_SUCCESS
            .with_label_values(&[label])
            .inc();
        transition_to_alive(peers, &target_id, &target_addr, Some(disseminator));
        evictor.record_success(key_of(&target_id, &target_addr));
    } else {
        transition_to_suspect(peers, &target_id, &target_addr, Some(disseminator));
    }
}

/// Transition a peer to `Alive`. Logs + metric-counts any refutation
/// (Suspect -> Alive). Does not touch the eviction counter; callers
/// handle that. If `disseminator` is provided, any non-no-op transition
/// also enqueues a [`PeerUpdate`] so peers learn via piggyback.
pub(super) fn transition_to_alive(
    peers: &Arc<RwLock<PeerTable>>,
    target_id: &str,
    target_addr: &str,
    disseminator: Option<&Arc<Disseminator>>,
) {
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(entry) = super::find_mut(&mut table, target_id, target_addr) {
        let prev = entry.state;
        let now = Instant::now();
        entry.state = PeerState::Alive;
        entry.last_ack = now;
        entry.last_heartbeat = now;
        // L2: refresh the state-transition anchor on any observable
        // flip so the dead-peer GC timer is reset when a peer rejoins.
        if !matches!(prev, PeerState::Alive) {
            entry.last_transition = now;
        }
        let peer_node_id = entry.node_id.clone();
        let incarnation = entry.incarnation;
        // Release the write guard before interacting with the
        // disseminator.
        drop(table);
        match prev {
            PeerState::Alive => {}
            PeerState::Suspect { .. } => {
                MESH_SUSPECT_TRANSITIONS
                    .with_label_values(&[PEER_STATE_SUSPECT, PEER_STATE_ALIVE])
                    .inc();
                tracing::info!(
                    peer = target_id,
                    "swim: peer refuted Suspect, back to Alive"
                );
                if let (Some(d), false) = (disseminator, peer_node_id.is_empty()) {
                    d.push(PeerUpdate {
                        node_id: peer_node_id,
                        state: PeerStateWire::Alive,
                        incarnation,
                    });
                }
            }
            PeerState::Dead => {
                // Extremely rare: a Dead peer should not produce an
                // ACK because we stopped probing it. If this happens
                // (e.g. a witness still knows the peer), accept the
                // refutation so the cluster converges without manual
                // intervention.
                MESH_SUSPECT_TRANSITIONS
                    .with_label_values(&[PEER_STATE_DEAD, PEER_STATE_ALIVE])
                    .inc();
                tracing::warn!(
                    peer = target_id,
                    "swim: peer previously marked Dead responded; back to Alive"
                );
                if let (Some(d), false) = (disseminator, peer_node_id.is_empty()) {
                    d.push(PeerUpdate {
                        node_id: peer_node_id,
                        state: PeerStateWire::Alive,
                        incarnation,
                    });
                }
            }
        }
    }
}

/// Transition a peer from `Alive` to `Suspect`. No-op when the peer is
/// already Suspect or Dead. Enqueues a dissemination update on non-no-op
/// transitions.
pub(super) fn transition_to_suspect(
    peers: &Arc<RwLock<PeerTable>>,
    target_id: &str,
    target_addr: &str,
    disseminator: Option<&Arc<Disseminator>>,
) {
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(entry) = super::find_mut(&mut table, target_id, target_addr) {
        if let PeerState::Alive = entry.state {
            let now = Instant::now();
            entry.state = PeerState::Suspect { since: now };
            // L2: stamp the transition so the GC timer anchor stays
            // consistent across all state changes.
            entry.last_transition = now;
            let peer_node_id = entry.node_id.clone();
            let incarnation = entry.incarnation;
            drop(table);
            MESH_SUSPECT_TRANSITIONS
                .with_label_values(&[PEER_STATE_ALIVE, PEER_STATE_SUSPECT])
                .inc();
            tracing::warn!(
                peer = target_id,
                "swim: marking peer Suspect after failed probe"
            );
            if let (Some(d), false) = (disseminator, peer_node_id.is_empty()) {
                d.push(PeerUpdate {
                    node_id: peer_node_id,
                    state: PeerStateWire::Suspect,
                    incarnation,
                });
            }
        }
    }
}

/// Walk the peer table and move any peer that has been Suspect longer
/// than `suspect_timeout` into `Dead`. Returns `(key, incarnation)`
/// pairs for each transitioned peer so the caller can fire eviction
/// callbacks + dissemination updates outside the lock.
pub(super) fn sweep_suspects_to_dead(
    peers: &Arc<RwLock<PeerTable>>,
    suspect_timeout: Duration,
    now: Instant,
) -> Vec<(String, u64)> {
    let mut transitioned = Vec::new();
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for entry in table.iter_mut() {
        if let PeerState::Suspect { since } = entry.state {
            if now.duration_since(since) >= suspect_timeout {
                entry.state = PeerState::Dead;
                // L2: anchor the dead-peer GC timer at the moment of
                // transition, not wall-clock noise in later sweeps.
                entry.last_transition = now;
                let key = if !entry.node_id.is_empty() {
                    entry.node_id.clone()
                } else {
                    entry.addr.clone()
                };
                transitioned.push((key, entry.incarnation));
            }
        }
    }
    transitioned
}

/// L2: walk the peer table and remove any peer that has been in the
/// `Dead` state for longer than `dead_peer_gc` (measured from the
/// entry's `last_transition` stamp). Returns the list of evicted
/// `(node_id, addr)` pairs so the caller can log / metric-count the
/// removals after releasing the write lock.
///
/// This complements `sweep_suspects_to_dead`: the Suspect sweeper makes
/// Dead terminal; the Dead sweeper makes Dead finite. A peer that
/// resurrects (receives a PING from the same address, or is rediscovered
/// by bootstrap) is re-added via the normal add-peer path as a fresh
/// Alive entry.
pub(super) fn sweep_dead_for_gc(
    peers: &Arc<RwLock<PeerTable>>,
    dead_peer_gc: Duration,
    now: Instant,
) -> Vec<(String, String)> {
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // Wave 2D: PeerTable handles HashMap + Vec removal in one pass.
    let removed_entries = table.retain_remove(|entry| {
        matches!(entry.state, PeerState::Dead)
            && now.duration_since(entry.last_transition) >= dead_peer_gc
    });
    removed_entries
        .into_iter()
        .map(|e| (e.node_id, e.addr))
        .collect()
}

/// Complete a pending direct probe. Sends `()` down the waiter channel;
/// a failed send means the waiter already timed out, which is harmless.
///
/// Wave 2D: now async because `pending` is a `tokio::sync::Mutex` (held
/// across `.await` in the witness fan-out path).
pub(super) async fn complete_pending_direct(pending: &Arc<AsyncMutex<PendingMaps>>, seq: u64) {
    let waiter = pending.lock().await.direct.remove(&seq);
    if let Some(p) = waiter {
        let _ = p.tx.send(());
    }
}
