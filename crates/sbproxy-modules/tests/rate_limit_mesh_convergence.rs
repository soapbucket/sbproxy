// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Multi-node convergence proof for mesh rate limiting.
//!
//! The bug this guards: with no Redis, every node rate limited independently,
//! so 600 rpm configured on three nodes admitted roughly 1800 rpm. These tests
//! drive three independent policies, each with its own tier, and disseminate
//! between them the way the `sbproxy-core` loop does, then assert the cluster
//! admits close to the configured limit rather than three times it.
//!
//! Dissemination is simulated rather than gossiped. The transport itself is
//! covered by the mesh crate's own tests; what needs proving here is the
//! arithmetic, and in particular that one node's decision reads another node's
//! counts. A CRDT nothing merges is the shape deleted in #722, so
//! `a_node_reads_its_peers_counts` is the guardrail test for this whole design.

use std::sync::Arc;

use sbproxy_ai::governance_crdt::{merge_contributions, GovernanceContribution};
use sbproxy_modules::policy::rate_limit_cluster::RateLimitClusterTier;
use sbproxy_modules::RateLimitPolicy;

/// One node: a policy and the tier it reads.
struct Node {
    id: String,
    policy: RateLimitPolicy,
    tier: Arc<RateLimitClusterTier>,
}

fn node(id: &str, rpm: f64) -> Node {
    let tier = Arc::new(RateLimitClusterTier::new(id));
    let policy = RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": rpm }))
        .expect("valid rpm policy")
        .with_cluster(Some(tier.clone()), "origin-1");
    Node {
        id: id.to_string(),
        policy,
        tier,
    }
}

/// One dissemination round: every node publishes its slots, and every node
/// installs the merge of all the others. Mirrors `rate_limit_cluster::tick`,
/// including the self-exclusion that stops a node double-counting itself.
fn disseminate(nodes: &[Node], generation: u64) {
    let contributions: Vec<GovernanceContribution> = nodes
        .iter()
        .map(|n| GovernanceContribution {
            node_id: n.id.clone(),
            generation,
            slots: n.tier.local_slots(),
        })
        .collect();

    for n in nodes {
        let peers = contributions
            .iter()
            .filter(|c| c.node_id != n.id)
            .cloned()
            .collect::<Vec<_>>();
        n.tier.set_peer_counters(merge_contributions(peers));
    }
}

/// Drive `total` requests round-robin across the nodes, disseminating every
/// `batch` requests, and return how many the cluster admitted.
fn drive_round_robin(nodes: &[Node], total: usize, batch: usize) -> usize {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let mut admitted = 0usize;
    let mut generation = 1u64;
    for i in 0..total {
        let n = &nodes[i % nodes.len()];
        if rt
            .block_on(n.policy.allow_with_info_async("client-1"))
            .allowed
        {
            admitted += 1;
        }
        if (i + 1) % batch == 0 {
            generation += 1;
            disseminate(nodes, generation);
        }
    }
    admitted
}

#[test]
fn three_nodes_admit_near_the_limit_not_three_times_it() {
    // 600 rpm across three nodes. Disseminating every 10 requests stands in
    // for the 3 second cadence: what matters is that peers learn before the
    // window fills, not the wall-clock interval.
    let nodes = [node("a", 600.0), node("b", 600.0), node("c", 600.0)];
    let admitted = drive_round_robin(&nodes, 1800, 10);

    assert!(
        admitted < 1800,
        "the cluster admitted every request ({admitted}/1800), which is per-node \
         enforcement: the exact bug this test exists to catch"
    );
    assert!(
        admitted <= 900,
        "admitted {admitted}, past the documented (N-1) * rate * cadence bound"
    );
    assert!(
        admitted >= 600,
        "admitted only {admitted}: convergence must not deny below the configured limit"
    );
}

#[test]
fn a_node_reads_its_peers_counts() {
    // The #722 guardrail. If this fails, the counters are write-only and the
    // whole design is decoration.
    let nodes = [node("a", 600.0), node("b", 600.0)];
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // Only node b serves traffic.
    for _ in 0..5 {
        assert!(
            rt.block_on(nodes[1].policy.allow_with_info_async("client-1"))
                .allowed
        );
    }
    // Before dissemination node a knows nothing about it.
    assert_eq!(
        nodes[0].tier.local_slots().len(),
        0,
        "node a served nothing, so it has no local slots"
    );

    disseminate(&nodes, 2);

    // After dissemination node a's remaining budget reflects b's traffic.
    let info = rt.block_on(nodes[0].policy.allow_with_info_async("client-1"));
    assert!(
        info.remaining < info.limit - 1,
        "node a must account for node b's 5 requests, but remaining was {} of {}",
        info.remaining,
        info.limit
    );
}

#[test]
fn a_single_node_cluster_enforces_exactly_the_configured_limit() {
    // No peers means no approximation, so the limit is exact. This pins that
    // the convergence path does not loosen a single-node deployment.
    let nodes = [node("solo", 5.0)];
    let admitted = drive_round_robin(&nodes, 20, 5);
    assert_eq!(admitted, 5, "a lone node admits exactly its limit");
}

#[test]
fn a_partitioned_node_keeps_serving_at_its_own_limit() {
    // A node that hears from nobody falls back to enforcing on its own count.
    // That over-admits rather than denying, which is the deliberate failure
    // direction: a partition must not turn into an outage.
    let nodes = [node("lonely", 4.0)];
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let mut admitted = 0;
    for _ in 0..10 {
        if rt
            .block_on(nodes[0].policy.allow_with_info_async("client-1"))
            .allowed
        {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 4, "still enforces its own limit while isolated");
}
