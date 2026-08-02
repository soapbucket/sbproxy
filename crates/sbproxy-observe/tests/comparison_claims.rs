// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The public claims guard.
//!
//! `docs/comparison.md` advertised "Clustered without an external Redis: the
//! key plane, budgets, and rate counters stay coherent" for months. The
//! key-plane half was true. The two things the sentence named after it,
//! budgets and rate counters, were written locally and never merged across the
//! fleet. Nothing in the repository connected that sentence to the code, so
//! nothing could tell you it was false.
//!
//! This binds the load-bearing rows of the comparison table to a capability
//! and its support level. A row that claims a plain "Yes" for a capability that
//! is not `Stable` fails the build, and a row whose text stops matching the doc
//! fails too, so the guard cannot rot into describing a table that no longer
//! exists.

use sbproxy_capability::{validate_claims, Claim, ClaimValue, ProductCapability, SupportLevel};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

/// The capabilities a public comparison claim is allowed to cite.
///
/// Support level is the truth about the code as of this commit.
///
/// Cluster budget coherence was `ConfigOnly` for as long as the per-key
/// counters were written and never merged. That is no longer the state of the
/// code: the approximate tier publishes each node's settled counters and
/// merges every live peer's back in on a fixed cadence, and the strict tier
/// runs atomic reserve, settle, and release scripts against a shared Redis
/// backend. Both have executable evidence, so the level is `Stable`.
///
/// The claim below stays [`ClaimValue::Qualified`] on purpose. "Stable" here
/// says the mechanism runs, not that it is exact: the no-backend tier is
/// coherent within a bounded staleness window, and only the shared-backend
/// tier is exact under a concurrent burst. A plain "Yes" would erase that
/// distinction, which is the same erasure WOR-1889 was filed to undo.
const CAPABILITIES: &[ProductCapability] = &[
    ProductCapability {
        id: "cluster.key_plane_coherence",
        support: SupportLevel::Stable,
        summary: "Mint a key on one replica, use it on any, revoke on one and the rest deny.",
        evidence: &["crates/sbproxy-core/src/key_plane.rs", "examples/ai-dynamic-keys-cluster"],
    },
    ProductCapability {
        id: "cluster.no_postgres",
        support: SupportLevel::Stable,
        summary: "The mesh needs no Postgres and no external control plane.",
        evidence: &["crates/sbproxy-mesh/src/lib.rs"],
    },
    ProductCapability {
        id: "cluster.budget_coherence",
        support: SupportLevel::Stable,
        summary: "Per-key spend and rate counters merge across live peers with no shared backend, within a bounded staleness window; exact cluster-wide enforcement under concurrency needs the strict shared backend.",
        evidence: &[
            "crates/sbproxy-core/src/governance_cluster.rs",
            "crates/sbproxy-core/src/rate_limit_cluster.rs",
            "crates/sbproxy-ai/src/governance_redis.rs",
            "e2e/tests/governance_approximate_cluster.rs",
            "e2e/tests/governance_strict.rs",
        ],
    },
];

/// Rows in `docs/comparison.md`, bound to the capability that backs each and to
/// the exact cell text the table is allowed to print.
const CLAIMS: &[Claim] = &[
    Claim {
        row: "Clustering substrate (gossip mesh, no Postgres)",
        capability: "cluster.no_postgres",
        value: ClaimValue::Yes,
    },
    Claim {
        row: "Rate limiting",
        capability: "cluster.budget_coherence",
        value: ClaimValue::Qualified("Built-in (node-local; cluster-wide needs a shared backend)"),
    },
];

#[test]
fn no_comparison_claim_outruns_its_capability() {
    let errors = validate_claims(CLAIMS, CAPABILITIES);
    assert!(
        errors.is_empty(),
        "a public claim outruns the capability behind it:\n{}",
        errors
            .iter()
            .map(|error| format!("  - {error}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_bound_row_appears_verbatim_in_the_comparison_table() {
    // The binding is only meaningful if the row text still matches the doc. If
    // an edit rewords a row, this fails and forces the registry to be updated
    // alongside it, rather than silently guarding a row that no longer exists.
    let comparison = std::fs::read_to_string(repo_root().join("docs/comparison.md"))
        .expect("read docs/comparison.md");

    for claim in CLAIMS {
        assert!(
            comparison.contains(claim.row),
            "comparison.md no longer contains the row '{}'; update the claims registry",
            claim.row
        );
        assert!(
            comparison.contains(claim.value.cell()),
            "comparison.md no longer prints '{}' for row '{}'; the claim and the table \
             have diverged",
            claim.value.cell(),
            claim.row
        );
    }
}

#[test]
fn the_retracted_redis_claim_is_gone() {
    // The specific sentence WOR-1889 was filed to remove. Its absence is part
    // of the contract now, so a future edit cannot quietly reintroduce it.
    let comparison = std::fs::read_to_string(repo_root().join("docs/comparison.md"))
        .expect("read docs/comparison.md");
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README.md");

    for (name, text) in [("comparison.md", &comparison), ("README.md", &readme)] {
        assert!(
            !text.contains("budgets, and rate counters stay coherent"),
            "{name} still claims fleet-coherent budgets and rate counters (WOR-1889)"
        );
    }
}
