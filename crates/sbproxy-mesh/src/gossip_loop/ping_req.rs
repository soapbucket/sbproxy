//! Indirect probe (PING-REQ) helpers.
//!
//! When a direct PING times out, the originator fans out PING-REQ to up
//! to K witnesses. Each witness performs its own direct ping against the
//! suspected peer and relays the verdict back via `IndirectAck`.
//!
//! The *fan-out* lives in [`super::probe::run_probe`]; the *witness*
//! handler is inlined into the recv task in [`super`] (a short-lived
//! `tokio::spawn` block per inbound `PingReq`). This module owns the
//! peer-table query that selects witnesses and the demux helper that
//! resolves an arriving `IndirectAck` against the originator's pending
//! probe map.

use std::sync::{Arc, RwLock};

use rand::seq::IteratorRandom;
use tokio::sync::Mutex as AsyncMutex;

use super::{PeerEntry, PeerState, PeerTable, PendingMaps};

/// Pick up to K random witnesses for a PING-REQ fan-out. Excludes the
/// target itself and any Dead peer. Returns `(node_id, addr)` pairs.
pub(super) fn pick_indirect_witnesses(
    peers: &Arc<RwLock<PeerTable>>,
    target_id: &str,
    k: usize,
) -> Vec<(String, String)> {
    let guard = match peers.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut rng = rand::thread_rng();
    // `target_id` may be empty for unknown-id peers; when empty, fall
    // back to excluding by addr not being the target addr, but since
    // the caller only passes a known id the simple filter suffices.
    let pool: Vec<&PeerEntry> = guard
        .iter()
        .filter(|p| matches!(p.state, PeerState::Alive))
        .filter(|p| p.node_id != target_id || target_id.is_empty())
        .collect();
    // `IteratorRandom::choose_multiple` does sampling without
    // replacement; clamps gracefully when K > pool size.
    pool.into_iter()
        .choose_multiple(&mut rng, k)
        .into_iter()
        .map(|p| (p.node_id.clone(), p.addr.clone()))
        .collect()
}

/// Complete a pending indirect probe with the `alive` verdict.
pub(super) async fn complete_pending_indirect(
    pending: &Arc<AsyncMutex<PendingMaps>>,
    seq: u64,
    alive: bool,
) {
    let waiter = pending.lock().await.indirect.remove(&seq);
    if let Some(p) = waiter {
        let _ = p.tx.send(alive);
    }
}
