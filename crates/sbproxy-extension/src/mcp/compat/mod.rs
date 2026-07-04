//! MCP tool-versioning compatibility oracle.
//!
//! Gives each MCP tool a canonical contract digest and grades a change against
//! semantic versioning across three dimensions (structural, behavioral, and
//! description-semantics), then a version-bump linter fails when a breaking
//! change ships without a matching bump. Self-contained: the schema diff and
//! response fingerprint live here, and the model-dependent description-semantics
//! dimension is reached through an injected [`semantics::Judge`], so the gateway
//! wires its own model client and nothing here depends on external test tooling.

use serde::{Deserialize, Serialize};

pub mod behavioral;
pub mod digest;
pub mod lint;
pub mod lockfile;
pub mod oracle;
pub mod schema_diff;
pub mod semantics;
pub mod structural;

pub use behavioral::behavioral_findings;
pub use digest::contract_digest;
pub use lint::{lint_bump, BumpVerdict};
pub use lockfile::{Lockfile, ToolLock};
pub use oracle::{evaluate_compatibility, evaluate_compatibility_full, OracleInputs};
pub use semantics::{
    semantics_findings, Judge, SemanticsConfig, SemanticsOutcome, TOOL_SEMANTICS_RUBRIC,
};
pub use structural::structural_findings;

/// A semver-grade delta between two tool versions.
///
/// Ordered so that taking the maximum picks the most significant change:
/// `None < Patch < Minor < Major`. The variant order is the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemverGrade {
    /// No contract change.
    None,
    /// A backward-compatible fix, no interface or behavior change.
    Patch,
    /// A backward-compatible addition.
    Minor,
    /// A breaking change.
    Major,
}

/// Confidence in a description-semantics verdict, derived from inter-judge
/// agreement when a jury is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Judges agreed closely.
    High,
    /// Judges partly agreed.
    Medium,
    /// Judges split; pair with the needs-confirmation flag.
    Low,
}

/// Which lens produced a [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dimension {
    /// Schema shape: input contravariant, output covariant.
    Structural,
    /// Same input, same response shape.
    Behavioral,
    /// The natural-language description and annotations, judged by a model.
    DescriptionSemantics,
}

/// One graded observation about a change between two tool versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// The lens that produced it.
    pub dimension: Dimension,
    /// The semver grade this change implies on its own.
    pub grade: SemverGrade,
    /// Tool field or contract element the change touched.
    pub pointer: String,
    /// Human-readable reason.
    pub reason: String,
    /// True for rug-pull or tool-poisoning-class findings.
    pub security: bool,
    /// Judge confidence, set only for the description-semantics dimension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// The composed verdict for one tool between two versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityVerdict {
    /// Tool name.
    pub tool: String,
    /// Contract digest of the old version.
    pub from_digest: String,
    /// Contract digest of the new version.
    pub to_digest: String,
    /// The most significant grade across all findings.
    pub grade: SemverGrade,
    /// Every graded observation.
    pub findings: Vec<Finding>,
    /// False when the behavioral dimension was skipped (no response samples).
    pub behavioral_evaluated: bool,
    /// True when the description-semantics jury could not agree confidently.
    pub needs_confirmation: bool,
}

/// The most significant grade across a set of findings.
pub(crate) fn max_grade(findings: &[Finding]) -> SemverGrade {
    findings
        .iter()
        .map(|f| f.grade)
        .max()
        .unwrap_or(SemverGrade::None)
}
