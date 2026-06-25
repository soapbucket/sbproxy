//! Dissemination apply path (L1).
//!
//! Each PING and ACK carries a bounded `updates: Vec<PeerUpdate>` payload.
//! The receive task drains those updates onto the local peer table via
//! [`apply_updates`]; conflict resolution uses a per-subject monotonic
//! `incarnation` counter (higher wins). The pure decision logic lives in
//! [`decide_transition`] so it can be unit-tested without locks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::metrics::{
    DISSEM_IGNORE_NO_CHANGE, DISSEM_IGNORE_STALE_INCARNATION, DISSEM_IGNORE_TERMINAL_DEAD,
    DISSEM_IGNORE_UNKNOWN_PEER, DISSEM_TRANS_ALIVE_DEAD, DISSEM_TRANS_ALIVE_SUSPECT,
    DISSEM_TRANS_DEAD_ALIVE, DISSEM_TRANS_SELF_REFUTATION, DISSEM_TRANS_SUSPECT_ALIVE,
    DISSEM_TRANS_SUSPECT_DEAD, MESH_DISSEMINATION_UPDATES_APPLIED,
    MESH_DISSEMINATION_UPDATES_IGNORED, MESH_SUSPECT_TRANSITIONS, PEER_STATE_ALIVE,
    PEER_STATE_DEAD, PEER_STATE_SUSPECT,
};
use crate::peer_eviction::PeerEvictor;

use super::{Disseminator, PeerState, PeerStateWire, PeerTable, PeerUpdate};

/// Apply a batch of [`PeerUpdate`]s received over the wire to our local
/// peer table. Each update is resolved independently so a malformed entry
/// in the middle of a batch does not poison the rest.
pub(super) fn apply_updates(
    updates: &[PeerUpdate],
    peers: &Arc<RwLock<PeerTable>>,
    local_node_id: &str,
    self_incarnation: &Arc<AtomicU64>,
    disseminator: &Arc<Disseminator>,
    evictor: &Arc<PeerEvictor>,
) {
    for update in updates {
        apply_update(
            update,
            peers,
            local_node_id,
            self_incarnation,
            disseminator,
            evictor,
        );
    }
}

/// Apply a single [`PeerUpdate`]. Implements the incarnation-based
/// conflict-resolution rules:
///
/// - If the subject is the local node:
///   - Suspect/Dead: bump our own incarnation and queue a refutation
///     `Alive(incarnation+1)` for dissemination.
///   - Alive: no-op (we always know our own state).
/// - If the subject is another peer we track:
///   - Follow the per-current-state rules documented in the module
///     preamble (higher incarnation wins, strict-greater for same-state
///     updates, etc.).
/// - If the subject is unknown: silently drop. Address-map refresh is a
///   future phase (L3).
pub(super) fn apply_update(
    update: &PeerUpdate,
    peers: &Arc<RwLock<PeerTable>>,
    local_node_id: &str,
    self_incarnation: &Arc<AtomicU64>,
    disseminator: &Arc<Disseminator>,
    evictor: &Arc<PeerEvictor>,
) {
    // --- Self-refutation ---
    if update.node_id == local_node_id && !local_node_id.is_empty() {
        match update.state {
            PeerStateWire::Suspect | PeerStateWire::Dead => {
                // Bump our own incarnation strictly above what the
                // rumor claims so the refutation wins under the
                // ordering rules below. fetch_max is not available on
                // stable AtomicU64, so do a CAS loop.
                let mut current = self_incarnation.load(Ordering::Relaxed);
                let target = update.incarnation.saturating_add(1);
                let new_inc = loop {
                    let desired = std::cmp::max(current.saturating_add(1), target);
                    match self_incarnation.compare_exchange_weak(
                        current,
                        desired,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break desired,
                        Err(observed) => current = observed,
                    }
                };
                disseminator.push(PeerUpdate {
                    node_id: local_node_id.to_string(),
                    state: PeerStateWire::Alive,
                    incarnation: new_inc,
                });
                MESH_DISSEMINATION_UPDATES_APPLIED
                    .with_label_values(&[DISSEM_TRANS_SELF_REFUTATION])
                    .inc();
                tracing::info!(
                    incarnation = new_inc,
                    rumor = ?update.state,
                    "dissemination: refuting self-suspicion"
                );
            }
            PeerStateWire::Alive => {
                // An Alive rumor about ourselves is redundant; skip.
                MESH_DISSEMINATION_UPDATES_IGNORED
                    .with_label_values(&[DISSEM_IGNORE_NO_CHANGE])
                    .inc();
            }
        }
        return;
    }

    // --- Peer update ---
    let mut table = match peers.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // Wave 2D: O(1) by-id lookup replaces the previous Vec scan.
    let entry = match (!update.node_id.is_empty())
        .then(|| table.get_mut_by_node_id(&update.node_id))
        .flatten()
    {
        Some(e) => e,
        None => {
            // Unknown peer; address map refresh is L3.
            MESH_DISSEMINATION_UPDATES_IGNORED
                .with_label_values(&[DISSEM_IGNORE_UNKNOWN_PEER])
                .inc();
            return;
        }
    };

    let prev_state = entry.state;
    let prev_incarnation = entry.incarnation;

    // Decide whether to accept + what new state to record, based on the
    // conflict rules.
    let outcome = decide_transition(prev_state, prev_incarnation, update);
    match outcome {
        TransitionOutcome::Ignore(reason) => {
            MESH_DISSEMINATION_UPDATES_IGNORED
                .with_label_values(&[reason])
                .inc();
        }
        TransitionOutcome::Accept {
            new_state,
            new_incarnation,
            transition_label,
            rebroadcast,
        } => {
            let observable_flip =
                std::mem::discriminant(&entry.state) != std::mem::discriminant(&new_state);
            entry.state = new_state;
            entry.incarnation = new_incarnation;
            let now = Instant::now();
            if matches!(new_state, PeerState::Alive) {
                entry.last_ack = now;
                entry.last_heartbeat = now;
            }
            // L2: any observable state flip resets the transition anchor
            // so the GC timer restarts for the new state. Same-state
            // incarnation refreshes (e.g. Alive(7) -> Alive(8)) do not
            // bump this.
            if observable_flip {
                entry.last_transition = now;
            }
            let peer_key = if !entry.node_id.is_empty() {
                entry.node_id.clone()
            } else {
                entry.addr.clone()
            };
            let rebroadcast_update = if rebroadcast {
                Some(PeerUpdate {
                    node_id: entry.node_id.clone(),
                    state: update.state,
                    incarnation: new_incarnation,
                })
            } else {
                None
            };
            drop(table);

            MESH_DISSEMINATION_UPDATES_APPLIED
                .with_label_values(&[transition_label])
                .inc();
            // Fire evictor hooks so the hash ring tracks the new
            // state without probing the peer ourselves.
            match new_state {
                PeerState::Alive => {
                    evictor.record_success(&peer_key);
                }
                PeerState::Dead => {
                    evictor.evict(&peer_key, crate::metrics::EVICT_REASON_DEAD_TIMEOUT);
                }
                PeerState::Suspect { .. } => {
                    // Suspect does not touch the eviction counter; the
                    // sweep loop will promote to Dead if refutation
                    // never arrives. We still record it as a "failure"
                    // so consecutive-failure eviction tracks the trend.
                    let _ = evictor.record_failure(&peer_key);
                }
            }
            // Mirror the top-level transition metric so operators see
            // the same counter regardless of whether the transition
            // came from a direct probe or dissemination.
            let (from_label, to_label) = transition_labels(prev_state, new_state);
            MESH_SUSPECT_TRANSITIONS
                .with_label_values(&[from_label, to_label])
                .inc();
            if let Some(u) = rebroadcast_update {
                disseminator.push(u);
            }
        }
    }
}

/// Outcome of evaluating an incoming [`PeerUpdate`] against the current
/// peer entry.
pub(super) enum TransitionOutcome {
    /// Drop the update; the `reason` label names why.
    Ignore(&'static str),
    /// Apply the update: write `new_state` / `new_incarnation` into the
    /// entry and, if `rebroadcast` is true, forward the news onward.
    Accept {
        new_state: PeerState,
        new_incarnation: u64,
        transition_label: &'static str,
        rebroadcast: bool,
    },
}

/// Pure logic for the dissemination conflict rules. No locks, no side
/// effects, no allocations: easy to unit-test.
pub(super) fn decide_transition(
    prev_state: PeerState,
    prev_incarnation: u64,
    update: &PeerUpdate,
) -> TransitionOutcome {
    match (prev_state, update.state) {
        // --- Prev: Alive ---
        (PeerState::Alive, PeerStateWire::Alive) => {
            if update.incarnation > prev_incarnation {
                // Higher-incarnation Alive refresh: no observable
                // state change, but bump the stored incarnation so
                // later updates compare correctly.
                TransitionOutcome::Accept {
                    new_state: PeerState::Alive,
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_SUSPECT_ALIVE,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_NO_CHANGE)
            }
        }
        (PeerState::Alive, PeerStateWire::Suspect) => {
            if update.incarnation >= prev_incarnation {
                TransitionOutcome::Accept {
                    new_state: PeerState::Suspect {
                        since: Instant::now(),
                    },
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_ALIVE_SUSPECT,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION)
            }
        }
        (PeerState::Alive, PeerStateWire::Dead) => {
            if update.incarnation >= prev_incarnation {
                TransitionOutcome::Accept {
                    new_state: PeerState::Dead,
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_ALIVE_DEAD,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION)
            }
        }
        // --- Prev: Suspect ---
        (PeerState::Suspect { .. }, PeerStateWire::Alive) => {
            if update.incarnation > prev_incarnation {
                TransitionOutcome::Accept {
                    new_state: PeerState::Alive,
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_SUSPECT_ALIVE,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION)
            }
        }
        (PeerState::Suspect { .. }, PeerStateWire::Suspect) => {
            if update.incarnation > prev_incarnation {
                // Later Suspect, same state; update the incarnation
                // but do not log a new transition.
                TransitionOutcome::Accept {
                    new_state: PeerState::Suspect {
                        since: Instant::now(),
                    },
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_ALIVE_SUSPECT,
                    rebroadcast: false,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_NO_CHANGE)
            }
        }
        (PeerState::Suspect { .. }, PeerStateWire::Dead) => {
            if update.incarnation >= prev_incarnation {
                TransitionOutcome::Accept {
                    new_state: PeerState::Dead,
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_SUSPECT_DEAD,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_STALE_INCARNATION)
            }
        }
        // --- Prev: Dead ---
        (PeerState::Dead, PeerStateWire::Alive) => {
            if update.incarnation > prev_incarnation {
                TransitionOutcome::Accept {
                    new_state: PeerState::Alive,
                    new_incarnation: update.incarnation,
                    transition_label: DISSEM_TRANS_DEAD_ALIVE,
                    rebroadcast: true,
                }
            } else {
                TransitionOutcome::Ignore(DISSEM_IGNORE_TERMINAL_DEAD)
            }
        }
        (PeerState::Dead, _) => TransitionOutcome::Ignore(DISSEM_IGNORE_TERMINAL_DEAD),
    }
}

/// Render a `(prev, new)` state pair into the `from` / `to` metric
/// labels expected by [`MESH_SUSPECT_TRANSITIONS`].
pub(super) fn transition_labels(prev: PeerState, new: PeerState) -> (&'static str, &'static str) {
    let prev_label = match prev {
        PeerState::Alive => PEER_STATE_ALIVE,
        PeerState::Suspect { .. } => PEER_STATE_SUSPECT,
        PeerState::Dead => PEER_STATE_DEAD,
    };
    let new_label = match new {
        PeerState::Alive => PEER_STATE_ALIVE,
        PeerState::Suspect { .. } => PEER_STATE_SUSPECT,
        PeerState::Dead => PEER_STATE_DEAD,
    };
    (prev_label, new_label)
}
