//! Building and checking a lockfile baseline from a live catalogue.
//!
//! The gate in [`crate::mcp::federation`] reads a committed lockfile and
//! measures the live catalogue against it. Nothing produced that file.
//! An operator had to read `digest.rs` and reimplement RFC 8785 canonical
//! JSON over an undocumented field projection to write one by hand, so in
//! practice the gate stayed off (WOR-2443).
//!
//! This module is the other half: [`build_lockfile`] turns a discovered
//! catalogue into a baseline, and [`diff_lockfile`] reports how a
//! catalogue has moved away from one. `sbproxy mcp lock` and
//! `sbproxy mcp verify-lock` are thin wrappers over the two.
//!
//! Both resolve every contract through
//! [`digest::baseline_entry_v2`](super::digest::baseline_entry_v2), which
//! the gate's v2 branch also calls. That shared call is the point: two
//! projections is exactly how `CONTRACT_FIELDS` and the gate's live
//! projection drifted apart the first time, and the drift is silent
//! because both sides compile and both produce a digest.

use super::digest::{baseline_entry_v2, is_contract_digest_v2};
use super::lockfile::{Lockfile, ToolLock};
use crate::mcp::federation::FederatedTool;
use std::collections::{BTreeMap, HashMap};

/// The semver a tool is pinned at when the operator has not declared one.
///
/// A first baseline is a statement about the contract, not a claim about
/// the upstream's own versioning, which MCP does not expose. `1.0.0` is
/// the neutral starting point the bump linter grades later changes
/// against; an operator who knows better sets
/// `tool_versioning.declared_versions`.
pub const DEFAULT_PINNED_VERSION: semver::Version = semver::Version::new(1, 0, 0);

/// Current lockfile format version.
///
/// Unchanged by the v2 digest scheme on purpose: the scheme is named
/// inside each `contract_digest` value, so a reader tells the recipes
/// apart per entry and a mixed file stays readable. Bumping this would
/// claim the *shape* changed, and it has not.
pub const LOCKFILE_VERSION: u32 = 1;

/// Build a lockfile baseline pinning every tool in `tools`.
///
/// `declared` supplies operator-declared versions
/// (`tool_versioning.declared_versions`); a tool absent from it is pinned
/// at [`DEFAULT_PINNED_VERSION`].
///
/// Every entry embeds its full contract as well as the digest. The
/// digest alone can only prove that something changed, which grades as a
/// patch; the embedded contract is what lets a later change be graded
/// structurally, so a removed required field can be called major.
pub fn build_lockfile(
    generated_for: String,
    tools: &[FederatedTool],
    declared: &HashMap<String, semver::Version>,
) -> Lockfile {
    let mut locked = BTreeMap::new();
    for tool in tools {
        let (contract, contract_digest) = baseline_entry_v2(tool);
        locked.insert(
            tool.name.clone(),
            ToolLock {
                semver: declared
                    .get(&tool.name)
                    .cloned()
                    .unwrap_or(DEFAULT_PINNED_VERSION),
                contract_digest,
                contract: Some(contract),
            },
        );
    }
    Lockfile {
        version: LOCKFILE_VERSION,
        generated_for,
        tools: locked,
    }
}

/// One way a live catalogue has moved away from its committed baseline.
///
/// Deliberately not graded here. `verify-lock` answers "does the
/// committed baseline still describe what is being served", which is a
/// question about drift; whether a given change is major or minor is the
/// oracle's job and needs the declared-version table the running gate
/// has. Reporting a grade from here would invite two answers to the same
/// question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// A tool is advertised that the baseline does not pin.
    Added {
        /// The advertised tool name.
        tool: String,
    },
    /// The baseline pins a tool that is no longer advertised.
    Removed {
        /// The pinned tool name.
        tool: String,
    },
    /// A pinned tool is still advertised, with a different contract.
    Changed {
        /// The advertised tool name.
        tool: String,
        /// The digest the baseline pinned.
        from: String,
        /// The digest the live contract hashes to.
        to: String,
    },
    /// A pinned tool's digest uses a scheme this build cannot compute.
    ///
    /// Reported rather than treated as drift. A lockfile written by a
    /// newer build must not read as "everything changed" on a rollback,
    /// which is the same fail-open posture the running gate takes.
    UnknownScheme {
        /// The advertised tool name.
        tool: String,
        /// The digest whose scheme was not recognized.
        digest: String,
    },
}

impl Drift {
    /// The tool this drift concerns.
    pub fn tool(&self) -> &str {
        match self {
            Self::Added { tool }
            | Self::Removed { tool }
            | Self::Changed { tool, .. }
            | Self::UnknownScheme { tool, .. } => tool,
        }
    }

    /// Stable kind label, for machine-readable output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Added { .. } => "added",
            Self::Removed { .. } => "removed",
            Self::Changed { .. } => "changed",
            Self::UnknownScheme { .. } => "unknown_digest_scheme",
        }
    }

    /// Whether this drift means the committed baseline is out of date.
    ///
    /// [`Self::UnknownScheme`] is the one that does not: it says this
    /// build cannot evaluate the entry, not that the entry is wrong.
    /// Failing CI on it would make a rollback look like a broken
    /// contract.
    pub fn is_stale(&self) -> bool {
        !matches!(self, Self::UnknownScheme { .. })
    }
}

/// Diff a live catalogue against a committed baseline.
///
/// Returns drift sorted by tool name so the output of two runs over the
/// same catalogue compares cleanly, which matters when this is wired
/// into CI and someone is reading a diff of two failures.
///
/// A tool pinned under the v1 scheme is re-digested under v1 rather than
/// reported as changed. Comparing a v1 baseline against a v2 digest
/// would report drift on every tool in an older lockfile, which is a
/// false alarm about the recipe rather than a finding about the tools.
pub fn diff_lockfile(baseline: &Lockfile, tools: &[FederatedTool]) -> Vec<Drift> {
    let live: BTreeMap<&str, &FederatedTool> = tools.iter().map(|t| (t.name.as_str(), t)).collect();
    let mut drift = Vec::new();

    for (name, lock) in &baseline.tools {
        let Some(tool) = live.get(name.as_str()) else {
            drift.push(Drift::Removed { tool: name.clone() });
            continue;
        };
        let live_digest = if is_contract_digest_v2(&lock.contract_digest) {
            baseline_entry_v2(tool).1
        } else if super::digest::is_contract_digest_v1(&lock.contract_digest) {
            super::digest::contract_digest(&super::digest::contract_of(tool))
        } else {
            drift.push(Drift::UnknownScheme {
                tool: name.clone(),
                digest: lock.contract_digest.clone(),
            });
            continue;
        };
        if live_digest != lock.contract_digest {
            drift.push(Drift::Changed {
                tool: name.clone(),
                from: lock.contract_digest.clone(),
                to: live_digest,
            });
        }
    }

    for name in live.keys() {
        if !baseline.tools.contains_key(*name) {
            drift.push(Drift::Added {
                tool: (*name).to_string(),
            });
        }
    }

    drift.sort_by(|a, b| a.tool().cmp(b.tool()).then(a.kind().cmp(b.kind())));
    drift
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(name: &str, description: &str) -> FederatedTool {
        FederatedTool {
            name: name.to_string(),
            upstream_name: name.to_string(),
            description: description.to_string(),
            input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            server_name: "upstream".to_string(),
            streaming: false,
            meta: None,
            contract: None,
            legacy_document: None,
            modern_contract: None,
            modern_incompatibility: None,
        }
    }

    #[test]
    fn a_generated_baseline_is_what_the_gate_would_compute() {
        // The acceptance criterion, as a test rather than by hand: an
        // entry this writes has to satisfy the same comparison the
        // running gate makes, or the generator ships operators a
        // baseline that is wrong on its first refresh.
        let tools = vec![tool("search", "search public repositories")];
        let lock = build_lockfile("upstream".into(), &tools, &HashMap::new());
        assert_eq!(diff_lockfile(&lock, &tools), Vec::new());
    }

    #[test]
    fn a_generated_digest_carries_the_v2_scheme() {
        let lock = build_lockfile("upstream".into(), &[tool("search", "d")], &HashMap::new());
        let entry = lock.tools.get("search").expect("tool pinned");
        assert!(
            is_contract_digest_v2(&entry.contract_digest),
            "generator must emit v2, got {}",
            entry.contract_digest
        );
        assert!(
            entry.contract.is_some(),
            "the embedded contract is what makes a later change gradable structurally"
        );
    }

    #[test]
    fn declared_versions_win_over_the_default_pin() {
        let mut declared = HashMap::new();
        declared.insert("search".to_string(), semver::Version::new(2, 3, 4));
        let lock = build_lockfile(
            "upstream".into(),
            &[tool("search", "d"), tool("other", "d")],
            &declared,
        );
        assert_eq!(
            lock.tools.get("search").expect("pinned").semver,
            semver::Version::new(2, 3, 4)
        );
        assert_eq!(
            lock.tools.get("other").expect("pinned").semver,
            DEFAULT_PINNED_VERSION
        );
    }

    #[test]
    fn a_changed_description_is_drift() {
        let before = vec![tool("search", "search public repositories")];
        let lock = build_lockfile("upstream".into(), &before, &HashMap::new());
        let after = vec![tool("search", "search every repository, including private")];
        let drift = diff_lockfile(&lock, &after);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert_eq!(drift[0].kind(), "changed");
        assert_eq!(drift[0].tool(), "search");
    }

    #[test]
    fn added_and_removed_tools_are_both_drift() {
        let lock = build_lockfile(
            "upstream".into(),
            &[tool("gone", "d"), tool("stays", "d")],
            &HashMap::new(),
        );
        let drift = diff_lockfile(&lock, &[tool("stays", "d"), tool("new", "d")]);
        let kinds: Vec<_> = drift.iter().map(|d| (d.tool(), d.kind())).collect();
        assert_eq!(kinds, vec![("gone", "removed"), ("new", "added")]);
    }

    #[test]
    fn a_v1_baseline_is_compared_under_v1() {
        // An older lockfile must not read as "every tool changed" just
        // because this build generates v2. The scheme is per entry.
        let tools = vec![tool("search", "d")];
        let mut lock = build_lockfile("upstream".into(), &tools, &HashMap::new());
        let entry = lock.tools.get_mut("search").expect("pinned");
        entry.contract_digest =
            super::super::digest::contract_digest(&super::super::digest::contract_of(&tools[0]));
        assert!(diff_lockfile(&lock, &tools).is_empty());
    }

    #[test]
    fn an_unreadable_scheme_reports_rather_than_failing_the_run() {
        let tools = vec![tool("search", "d")];
        let mut lock = build_lockfile("upstream".into(), &tools, &HashMap::new());
        lock.tools
            .get_mut("search")
            .expect("pinned")
            .contract_digest = "mcp-contract-v9-sha256:beef".to_string();
        let drift = diff_lockfile(&lock, &tools);
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].kind(), "unknown_digest_scheme");
        assert!(
            !drift[0].is_stale(),
            "a scheme this build cannot read is not evidence the baseline is stale; \
             failing CI on it would make a rollback look like a broken contract"
        );
    }
}
