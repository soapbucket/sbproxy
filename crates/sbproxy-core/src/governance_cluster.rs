// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cross-node dissemination of approximate governance counters (WOR-1835).
//!
//! The approximate governance tier (`InMemoryGovernanceStore`) counts usage
//! that happened on this process only. Without a shared database, a key's
//! spend and rate limits would silently reset per node: a client bouncing
//! across three workers could use three times its budget. This module closes
//! that gap the same way `cluster_metrics` closes it for fleet metrics: each
//! node periodically publishes a compact snapshot of its own counter slots
//! through the process-wide cluster handle, and merges every live peer's
//! snapshot back into the store so admission checks see cluster-wide usage.
//!
//! It mirrors `cluster_metrics::run_loop` structurally (tokio interval,
//! monotonic generation, publish then collect-live-members then
//! `read_state` each tick). The one deliberate difference: this node's own
//! contribution is excluded from the merged peer view. The store already
//! counts local usage directly in its own key state, so re-adding a
//! self-published slot here would double-count against the node's limits.

use std::sync::Arc;
use std::time::Duration;

use sbproxy_ai::governance::InMemoryGovernanceStore;
use sbproxy_ai::governance_crdt::{merge_contributions, GovernanceContribution, MergedCounters};
use sbproxy_mesh::{ClusterHandle, ClusterMemberState, ClusterStateRead};

/// Cluster state namespace for published governance counter contributions.
const GOVERNANCE_STATE_NAMESPACE: &str = "governance-counters";

/// Schema version for [`GovernanceContribution`] as published to the mesh.
const GOVERNANCE_STATE_SCHEMA_VERSION: u32 = 1;

/// Merge every peer contribution except this node's own into a peer view.
/// Excluding self is required: the store counts local usage directly, so a
/// self-slot here would double-count against the node's own limits.
fn merged_peer_view(my_id: &str, contributions: Vec<GovernanceContribution>) -> MergedCounters {
    merge_contributions(contributions.into_iter().filter(|c| c.node_id != my_id))
}

/// Publish this node's governance counter slots and merge every live peer's
/// slots back into the currently installed approximate store, forever, on the
/// given cadence. The resolver is called on every cycle so a key-plane reload
/// cannot leave this process publishing into an obsolete store. A strict or
/// disabled key plane resolves to `None` and is skipped until approximate
/// governance returns. Failures are skipped; the next tick re-publishes.
pub(crate) async fn run_loop<F>(handle: ClusterHandle, resolve_store: F, interval_secs: u64)
where
    F: Fn() -> Option<Arc<InMemoryGovernanceStore>> + Send + Sync + 'static,
{
    let mut generation = generation_seed();
    let mut tick_timer = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        tick_timer.tick().await;
        generation = generation.saturating_add(1);
        tick_current_store(&handle, &resolve_store, generation, interval_secs).await;
    }
}

/// Resolve the active approximate store for one cycle, then publish and merge
/// against that same snapshot. A reload may replace the store between cycles,
/// but cannot split one cycle across two stores.
async fn tick_current_store<F>(
    handle: &ClusterHandle,
    resolve_store: &F,
    generation: u64,
    interval_secs: u64,
) where
    F: Fn() -> Option<Arc<InMemoryGovernanceStore>> + Send + Sync + ?Sized,
{
    let Some(store) = resolve_store() else {
        return;
    };
    tick(handle, store.as_ref(), generation, interval_secs).await;
}

/// One publish-then-collect cycle: publish this node's current counter
/// slots at `generation`, then read every live peer's latest published
/// contribution and install the merged, self-excluded view into `store`.
async fn tick(
    handle: &ClusterHandle,
    store: &InMemoryGovernanceStore,
    generation: u64,
    interval_secs: u64,
) {
    let my_id = handle.identity().node_id.clone();
    let ttl = Duration::from_secs(interval_secs.max(1).saturating_mul(3));
    let contribution = GovernanceContribution {
        node_id: my_id.clone(),
        generation,
        slots: store.local_slots(),
    };
    if let Err(error) = handle
        .publish_state(
            GOVERNANCE_STATE_NAMESPACE,
            &my_id,
            GOVERNANCE_STATE_SCHEMA_VERSION,
            generation,
            ttl,
            &contribution,
        )
        .await
    {
        tracing::debug!(%error, "governance-counters: publish failed (retry next tick)");
    }

    let live: Vec<_> = handle
        .membership()
        .into_iter()
        .filter(|m| m.node_id == my_id || m.state == ClusterMemberState::Alive)
        .collect();
    let mut contributions = Vec::new();
    for member in &live {
        if member.node_id == my_id {
            continue; // local usage is counted by the store directly
        }
        if let ClusterStateRead::Present(record) = handle
            .read_state::<GovernanceContribution>(
                GOVERNANCE_STATE_NAMESPACE,
                &member.node_id,
                GOVERNANCE_STATE_SCHEMA_VERSION,
            )
            .await
        {
            contributions.push(record.payload);
        }
    }
    store.set_peer_counters(merged_peer_view(&my_id, contributions));
}

/// A coarse, monotonic-enough starting generation derived from wall-clock
/// time, so a restarted node's first publish still outranks any stale
/// record a peer might still be holding from before the restart.
fn generation_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_peer_view_excludes_this_node_and_sums_the_rest() {
        use sbproxy_ai::governance::GovernanceUsage;
        use sbproxy_ai::governance_crdt::NodeCounterSlot;
        let slot = |n: u64| NodeCounterSlot {
            key_id: "k1".into(),
            policy_revision: 1,
            window_start_millis: 0,
            usage: GovernanceUsage {
                requests: n,
                tokens: 0,
                micro_usd: 0,
            },
        };
        let contributions = vec![
            GovernanceContribution {
                node_id: "self".into(),
                generation: 1,
                slots: vec![slot(100)],
            }, // must be excluded
            GovernanceContribution {
                node_id: "b".into(),
                generation: 1,
                slots: vec![slot(3)],
            },
            GovernanceContribution {
                node_id: "c".into(),
                generation: 1,
                slots: vec![slot(5)],
            },
        ];
        let merged = merged_peer_view("self", contributions);
        assert_eq!(
            merged.merged_usage("k1", 1, 0).requests,
            8,
            "peers b+c summed, self excluded"
        );
    }

    #[tokio::test]
    async fn tick_publishes_and_installs_peer_counters_without_panicking() {
        use sbproxy_ai::governance::InMemoryGovernanceConfig;
        use sbproxy_mesh::{ClusterIdentity, ClusterNodeRole};
        use std::collections::{BTreeMap, BTreeSet};

        let identity = ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "node-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        };
        let handle = ClusterHandle::local(identity).expect("cluster handle");
        let store = Arc::new(
            InMemoryGovernanceStore::new(InMemoryGovernanceConfig::default())
                .expect("default in-memory governance bounds are valid"),
        );

        tick(&handle, &store, 1, 5).await;
    }

    #[tokio::test]
    async fn resolved_tick_switches_publication_and_peer_updates_to_reloaded_store() {
        use sbproxy_ai::governance::{
            GovernanceError, GovernanceLimits, GovernanceStore, GovernanceUsage,
            InMemoryGovernanceConfig, ReserveRequest, SettleRequest, GOVERNANCE_LIFETIME_WINDOW,
        };
        use sbproxy_ai::governance_crdt::NodeCounterSlot;
        use sbproxy_mesh::{ClusterIdentity, ClusterNodeRole};
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::Mutex;

        let identity = ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "node-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        };
        let handle = ClusterHandle::local(identity).expect("cluster handle");
        let new_store = || {
            Arc::new(
                InMemoryGovernanceStore::new(InMemoryGovernanceConfig::default())
                    .expect("default in-memory governance bounds are valid"),
            )
        };
        let store_a = new_store();
        let store_b = new_store();

        async fn settle_tokens(
            store: &InMemoryGovernanceStore,
            reservation_id: &str,
            key_id: &str,
            tokens: u64,
        ) {
            store
                .reserve(ReserveRequest {
                    reservation_id: reservation_id.to_string(),
                    key_id: key_id.to_string(),
                    policy_revision: 1,
                    limits: GovernanceLimits::default(),
                    token_ceiling: tokens,
                    micro_usd_ceiling: 0,
                })
                .await
                .expect("reserve local usage");
            store
                .settle(SettleRequest {
                    reservation_id: reservation_id.to_string(),
                    key_id: key_id.to_string(),
                    actual_tokens: tokens,
                    actual_micro_usd: 0,
                })
                .await
                .expect("settle local usage");
        }

        settle_tokens(store_a.as_ref(), "local-a", "local-a", 11).await;
        settle_tokens(store_b.as_ref(), "local-b", "local-b", 22).await;

        let current = Arc::new(Mutex::new(Arc::clone(&store_a)));
        let resolver_state = Arc::clone(&current);
        let resolve_store = move || {
            Some(
                resolver_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            )
        };

        tick_current_store(&handle, &resolve_store, 1, 5).await;
        let first = handle
            .read_state::<GovernanceContribution>(
                GOVERNANCE_STATE_NAMESPACE,
                "node-a",
                GOVERNANCE_STATE_SCHEMA_VERSION,
            )
            .await;
        let ClusterStateRead::Present(first) = first else {
            panic!("expected first governance publication, got {first:?}");
        };
        assert!(first.payload.slots.iter().any(|slot| {
            slot.key_id == "local-a"
                && slot.window_start_millis == GOVERNANCE_LIFETIME_WINDOW
                && slot.usage.tokens == 11
        }));

        let peer_view = || {
            merge_contributions([GovernanceContribution {
                node_id: "peer".to_string(),
                generation: 1,
                slots: vec![NodeCounterSlot {
                    key_id: "peer-probe".to_string(),
                    policy_revision: 1,
                    window_start_millis: GOVERNANCE_LIFETIME_WINDOW,
                    usage: GovernanceUsage {
                        requests: 0,
                        tokens: 1,
                        micro_usd: 0,
                    },
                }],
            }])
        };
        store_a.set_peer_counters(peer_view());
        store_b.set_peer_counters(peer_view());
        *current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::clone(&store_b);

        tick_current_store(&handle, &resolve_store, 2, 5).await;
        let second = handle
            .read_state::<GovernanceContribution>(
                GOVERNANCE_STATE_NAMESPACE,
                "node-a",
                GOVERNANCE_STATE_SCHEMA_VERSION,
            )
            .await;
        let ClusterStateRead::Present(second) = second else {
            panic!("expected reloaded governance publication, got {second:?}");
        };
        assert!(second.payload.slots.iter().any(|slot| {
            slot.key_id == "local-b"
                && slot.window_start_millis == GOVERNANCE_LIFETIME_WINDOW
                && slot.usage.tokens == 22
        }));
        assert!(
            second
                .payload
                .slots
                .iter()
                .all(|slot| slot.key_id != "local-a"),
            "the old store must not be published after reload"
        );

        let probe = |reservation_id: &str| ReserveRequest {
            reservation_id: reservation_id.to_string(),
            key_id: "peer-probe".to_string(),
            policy_revision: 1,
            limits: GovernanceLimits {
                total_tokens: Some(1),
                ..GovernanceLimits::default()
            },
            token_ceiling: 1,
            micro_usd_ceiling: 0,
        };
        assert!(matches!(
            store_a.reserve(probe("probe-a")).await,
            Err(GovernanceError::LimitExceeded(_))
        ));
        assert!(
            store_b.reserve(probe("probe-b")).await.is_ok(),
            "the peer view must be refreshed on the reloaded store only"
        );
    }
}
