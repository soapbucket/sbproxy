//! Offline AI evaluation harness (WOR-2672 port of
//! `sbproxy-enterprise-ai::evaluation`): judges, experiments, datasets,
//! prompt scoring, and custom metrics.
//!
//! This is an offline evaluation toolkit an embedder drives from a script,
//! test, or CI job to compare model versions and prompt templates against
//! recorded datasets, not a request-path feature. It does not touch live
//! traffic.
//!
//! ## Not the same "judge" as `sbproxy_ai::judge`
//!
//! `sbproxy_ai::judge` is the live policy-authoring host function
//! (`judge::semantic`, cached, budget-capped) an operator's CEL or Lua
//! policy calls mid-request to get an LLM's opinion on a decision, per
//! `docs/adr-judge-trait.md`. [`crate::evaluation::judge`] here is a different, offline
//! concern: building a structured judge PROMPT and parsing a judge
//! model's scored JSON response for an evaluation run, with no cache, no
//! budget, and no policy integration. Neither depends on the other; both
//! happen to use the word "judge" for what an LLM-as-judge literally is.
//!
//! ## Modules
//!
//! - [`crate::evaluation::judge`] - LLM-as-Judge prompt building and response parsing.
//! - [`crate::evaluation::experiments`] - Experiment tracking across model and prompt
//!   variants.
//! - [`crate::evaluation::datasets`] - Versioned evaluation dataset management.
//! - [`crate::evaluation::prompt_scoring`] - Per-prompt quality score aggregation and
//!   ranking.
//! - [`crate::evaluation::custom_metrics`] - Composable pass/fail metrics (regex, JSON,
//!   length, keywords).
//!
//! Self-contained: entirely in-memory, no dependency on the classifier
//! sidecar or any other WOR-2661 port. See `docs/ai-evaluation-harness.md`
//! and `examples/ai-evaluation-harness/` for a runnable walkthrough.

pub mod custom_metrics;
pub mod datasets;
pub mod experiments;
pub mod judge;
pub mod prompt_scoring;

pub use custom_metrics::{evaluate_all, evaluate_metric, pass_rate, MetricType};
pub use datasets::{Dataset, DatasetEntry, DatasetError, DatasetStore};
pub use experiments::{Experiment, ExperimentStore};
pub use judge::{
    build_judge_prompt, parse_judge_response, JudgeConfig, JudgeParseError, JudgeResult,
};
pub use prompt_scoring::{PromptScore, PromptScorer};
