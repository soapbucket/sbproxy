//! Deterministic context-compression evaluation support.

mod adapter;
mod evaluator;
mod model;
mod provenance;
mod report;

pub use adapter::{adapt_external_jsonl, ExternalSuite};
pub use evaluator::{
    build_stateless_levers, evaluate_cases, AggregateReport, ArmReport, CaseLeverReport,
    CaseReport, EvalConfig, EvalReport, Recommendation,
};
pub use model::{parse_cases, AcceptanceSpec, EvalCase, EvalPipelineFile, QualitySpec};
pub use provenance::{
    load_provenance, verify_fixture_set, FixtureArtifact, ProvenanceManifest,
    VerifiedProvenanceSummary,
};
pub use report::{render_json, render_markdown};
