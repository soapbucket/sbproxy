use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, Result};
use sbproxy_ai::compression::{
    decode_sbproxy_table_v1, inspect_marked_context, CompactSerializationLever, CompressionLever,
    CompressionLeverConfig, CompressionRequest, CompressionRunner, LeverOutcome,
    PositionReorderLever, RagSelectLever, RequestOutcome, WindowFitLever,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AcceptanceSpec, EvalCase, QualitySpec};

/// Immutable settings shared by every case in one evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalConfig {
    /// Named profile shown in reports.
    pub profile: String,
    /// Ordered production compression levers evaluated by the treatment arm.
    pub levers: Vec<CompressionLeverConfig>,
    /// Include observed wall-clock latency in this non-gated artifact.
    pub measure_latency: bool,
}

/// Build the production stateless levers selected by a deterministic evaluation.
pub fn build_stateless_levers(
    configs: &[CompressionLeverConfig],
) -> Result<Vec<Arc<dyn CompressionLever>>> {
    configs
        .iter()
        .map(|config| match config {
            CompressionLeverConfig::RagSelect(config) => {
                if config.min_tokens == 0 {
                    bail!("rag_select min_tokens must be greater than zero");
                }
                if config.max_chunks == 0 {
                    bail!("rag_select max_chunks must be greater than zero");
                }
                if config.min_relevance_percent > 100 {
                    bail!("rag_select min_relevance_percent must not exceed 100");
                }
                Ok(Arc::new(RagSelectLever::new(config.clone())) as Arc<dyn CompressionLever>)
            }
            CompressionLeverConfig::CompactSerialization(config) => {
                if config.min_tokens == 0 {
                    bail!("compact_serialization min_tokens must be greater than zero");
                }
                if config.tabular.enabled && config.tabular.min_rows < 2 {
                    bail!("compact_serialization tabular min_rows must be at least 2 when enabled");
                }
                Ok(Arc::new(CompactSerializationLever::new(config.clone()))
                    as Arc<dyn CompressionLever>)
            }
            CompressionLeverConfig::PositionReorder(config) => {
                Ok(Arc::new(PositionReorderLever::new(config.clone()))
                    as Arc<dyn CompressionLever>)
            }
            CompressionLeverConfig::WindowFit(config) => {
                if config.input_budget_tokens == Some(0) {
                    bail!("evaluation input budget must be greater than zero");
                }
                Ok(Arc::new(WindowFitLever::new(config.clone())) as Arc<dyn CompressionLever>)
            }
            CompressionLeverConfig::SummaryBuffer(_) => {
                bail!("stateful levers are not supported by the deterministic harness")
            }
        })
        .collect()
}

/// Deterministic build decision for one corpus or complete report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    /// Savings and quality clear the smoke thresholds.
    Build,
    /// Savings exist, but more representative evidence should be borrowed.
    Borrow,
    /// Quality, failures, or savings do not clear the smoke thresholds.
    Defer,
}

/// Token and quality result for one evaluation arm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmReport {
    /// Tokens seen before this arm runs.
    pub input_tokens: u64,
    /// Tokens emitted by this arm.
    pub output_tokens: u64,
    /// Deterministic or imported quality score in the inclusive 0 to 1 range.
    pub quality_score: Option<f64>,
}

/// One ordered production lever result without wall-clock data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLeverReport {
    /// Stable production lever name.
    pub lever: String,
    /// Applied, skipped, or failed outcome.
    pub outcome: String,
    /// Closed skip or failure reason, when present.
    pub reason: Option<String>,
    /// Target-model tokens before this lever.
    pub before_tokens: u64,
    /// Target-model tokens after this lever.
    pub after_tokens: u64,
    /// Committed tokens saved by this lever.
    pub tokens_saved: u64,
}

/// One off/on comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReport {
    /// Stable normalized case identifier.
    pub id: String,
    /// Corpus identifier from the normalized input.
    pub corpus: String,
    /// Target model used for both token counts.
    pub target_model: String,
    /// Quality or accuracy scorer used for this case.
    pub quality_metric: String,
    /// Uncompressed control arm.
    pub off: ArmReport,
    /// Ordered compression treatment arm.
    pub on: ArmReport,
    /// Target-model tokens avoided by the treatment.
    pub tokens_saved: u64,
    /// Saved tokens divided by control output tokens.
    pub savings_ratio: f64,
    /// Treatment quality minus control quality.
    pub quality_delta: Option<f64>,
    /// Ordered accounting for every configured treatment lever.
    pub levers: Vec<CaseLeverReport>,
    /// Declared case-local deterministic acceptance gates.
    pub acceptance: AcceptanceSpec,
    /// Whether every declared case-local acceptance gate passed.
    pub acceptance_passed: bool,
    /// Observed lever latency, omitted in deterministic drift artifacts.
    pub added_compression_latency_micros: Option<u64>,
    /// Closed compression request outcome.
    pub outcome: String,
    /// Closed skip or failure reason, when present.
    pub reason: Option<String>,
}

/// Stable aggregation for one corpus or all cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateReport {
    /// Cases included in the aggregate.
    pub case_count: usize,
    /// Control-arm target-model tokens.
    pub input_tokens: u64,
    /// Treatment-arm target-model tokens.
    pub output_tokens: u64,
    /// Target-model tokens avoided.
    pub tokens_saved: u64,
    /// Aggregate saved-token ratio.
    pub savings_ratio: f64,
    /// Mean control quality.
    pub off_quality_score: Option<f64>,
    /// Mean treatment quality.
    pub on_quality_score: Option<f64>,
    /// Mean treatment minus control quality.
    pub quality_delta: Option<f64>,
    /// Total observed compression latency, absent from deterministic reports.
    pub added_compression_latency_micros: Option<u64>,
    /// Cases where at least one treatment lever applied and none failed.
    pub applied_count: u64,
    /// Cases where every treatment lever skipped.
    pub skipped_count: u64,
    /// Failed cases that fell back to the unchanged working message list.
    pub fallback_count: u64,
    /// Skipped cases divided by all cases.
    pub skip_rate: f64,
    /// Applied, skipped, and failed counts.
    pub outcomes: BTreeMap<String, u64>,
    /// Closed skip and failure reason counts.
    pub reasons: BTreeMap<String, u64>,
    /// Whether every case in this aggregate passed its declared acceptance gates.
    pub acceptance_passed: bool,
    /// Deterministic action recommendation.
    pub recommendation: Recommendation,
}

/// Complete deterministic report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Named compression profile evaluated.
    pub profile: String,
    /// Ordered typed production compression pipeline.
    pub pipeline: Vec<CompressionLeverConfig>,
    /// Token counter contract used by both arms.
    pub token_counter: String,
    /// Whether latency values are observed or intentionally omitted.
    pub latency_mode: String,
    /// Stable case rows sorted by corpus and identifier.
    pub cases: Vec<CaseReport>,
    /// Stable per-corpus summaries.
    pub corpora: BTreeMap<String, AggregateReport>,
    /// Summary across all corpora.
    pub overall: AggregateReport,
}

/// Evaluate every case with identical input through control and typed treatment arms.
pub async fn evaluate_cases(cases: &[EvalCase], config: &EvalConfig) -> Result<EvalReport> {
    if cases.is_empty() {
        bail!("evaluation requires at least one case");
    }
    if config.profile.trim().is_empty() {
        bail!("evaluation profile must not be empty");
    }
    for case in cases {
        case.acceptance.validate(&case.id)?;
    }
    let off_runner = CompressionRunner::with_model_counter(Vec::new());
    let on_runner = CompressionRunner::with_model_counter(build_stateless_levers(&config.levers)?);

    let mut rows = Vec::with_capacity(cases.len());
    for case in cases {
        let request = CompressionRequest::new(&case.target_model);
        let off = off_runner.run(&request, &case.messages).await;
        let on = on_runner.run(&request, &case.messages).await;
        let off_quality = score_quality(&case.quality, &off.messages, &off.messages, false);
        let on_quality = score_quality(&case.quality, &off.messages, &on.messages, true);
        let outcome = on.outcome();
        let reason = run_reason(outcome, &on.lever_results);
        let levers = on
            .lever_results
            .iter()
            .map(|result| {
                let (outcome, reason) = lever_outcome(result.outcome);
                CaseLeverReport {
                    lever: result.lever.as_str().to_string(),
                    outcome: outcome.to_string(),
                    reason,
                    before_tokens: result.before_tokens,
                    after_tokens: result.after_tokens,
                    tokens_saved: result.tokens_saved,
                }
            })
            .collect();
        let latency = if config.measure_latency {
            Some(
                on.lever_results
                    .iter()
                    .map(|result| u64::try_from(result.duration.as_micros()).unwrap_or(u64::MAX))
                    .sum(),
            )
        } else {
            None
        };
        let savings_ratio = ratio(on.tokens_saved, off.final_tokens);
        let quality_delta = match (off_quality, on_quality) {
            (Some(off), Some(on)) => Some(round_six(on - off)),
            _ => None,
        };
        if on.tokens_saved > 0 && quality_delta.is_none() {
            bail!(
                "case `{}` claims token savings without an off/on quality score",
                case.id
            );
        }
        let acceptance_passed =
            case.acceptance
                .passes(off.final_tokens, on.final_tokens, on_quality, quality_delta);
        rows.push(CaseReport {
            id: case.id.clone(),
            corpus: case.corpus.clone(),
            target_model: case.target_model.clone(),
            quality_metric: match &case.quality {
                QualitySpec::EvidenceRetention { .. } => "evidence_retention",
                QualitySpec::ExactMatch { .. } => "exact_match_accuracy",
                QualitySpec::StructuredEquivalence { .. } => "structured_equivalence",
                QualitySpec::EdgePlacement { .. } => "edge_placement",
            }
            .to_string(),
            off: ArmReport {
                input_tokens: off.initial_tokens,
                output_tokens: off.final_tokens,
                quality_score: off_quality,
            },
            on: ArmReport {
                input_tokens: on.initial_tokens,
                output_tokens: on.final_tokens,
                quality_score: on_quality,
            },
            tokens_saved: on.tokens_saved,
            savings_ratio,
            quality_delta,
            levers,
            acceptance: case.acceptance.clone(),
            acceptance_passed,
            added_compression_latency_micros: latency,
            outcome: outcome.as_str().to_string(),
            reason,
        });
    }
    rows.sort_by(|left, right| {
        left.corpus
            .cmp(&right.corpus)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut grouped: BTreeMap<String, Vec<&CaseReport>> = BTreeMap::new();
    for row in &rows {
        grouped.entry(row.corpus.clone()).or_default().push(row);
    }
    let corpora = grouped
        .into_iter()
        .map(|(corpus, rows)| (corpus, aggregate(&rows)))
        .collect();
    let overall = aggregate(&rows.iter().collect::<Vec<_>>());

    Ok(EvalReport {
        schema_version: 3,
        profile: config.profile.clone(),
        pipeline: config.levers.clone(),
        token_counter: "sbproxy_target_model".to_string(),
        latency_mode: if config.measure_latency {
            "observed_wall_clock"
        } else {
            "omitted_for_deterministic_gate"
        }
        .to_string(),
        cases: rows,
        corpora,
        overall,
    })
}

fn lever_outcome(outcome: LeverOutcome) -> (&'static str, Option<String>) {
    match outcome {
        LeverOutcome::Applied => ("applied", None),
        LeverOutcome::Skipped { reason } => ("skipped", Some(reason.as_str().to_string())),
        LeverOutcome::Failed { reason } => ("failed", Some(reason.as_str().to_string())),
    }
}

fn run_reason(
    outcome: RequestOutcome,
    results: &[sbproxy_ai::compression::LeverResult],
) -> Option<String> {
    match outcome {
        RequestOutcome::Applied => None,
        RequestOutcome::Failed => results.iter().find_map(|result| match result.outcome {
            LeverOutcome::Failed { reason } => Some(reason.as_str().to_string()),
            LeverOutcome::Applied | LeverOutcome::Skipped { .. } => None,
        }),
        RequestOutcome::Skipped => {
            if results.is_empty() {
                return Some("empty_pipeline".to_string());
            }
            results.iter().find_map(|result| match result.outcome {
                LeverOutcome::Skipped { reason } => Some(reason.as_str().to_string()),
                LeverOutcome::Applied | LeverOutcome::Failed { .. } => None,
            })
        }
    }
}

fn score_quality(
    spec: &QualitySpec,
    control_messages: &[Value],
    messages: &[Value],
    treatment_arm: bool,
) -> Option<f64> {
    match spec {
        QualitySpec::EvidenceRetention { required_evidence } => {
            if required_evidence.is_empty() {
                return None;
            }
            let serialized = serde_json::to_string(messages).ok()?;
            let retained = required_evidence
                .iter()
                .filter(|evidence| serialized.contains(evidence.as_str()))
                .count();
            Some(round_six(retained as f64 / required_evidence.len() as f64))
        }
        QualitySpec::ExactMatch {
            reference_answers,
            off_prediction,
            on_prediction,
        } => {
            if reference_answers.is_empty() {
                return None;
            }
            let prediction = if treatment_arm {
                on_prediction
            } else {
                off_prediction
            };
            let prediction = normalize_answer(prediction);
            Some(
                if reference_answers
                    .iter()
                    .any(|reference| normalize_answer(reference) == prediction)
                {
                    1.0
                } else {
                    0.0
                },
            )
        }
        QualitySpec::StructuredEquivalence { chunk_id } => {
            let control = selected_structured_value(control_messages, chunk_id)?;
            let candidate = selected_structured_value(messages, chunk_id);
            Some(if candidate.as_ref() == Some(&control) {
                1.0
            } else {
                0.0
            })
        }
        QualitySpec::EdgePlacement { chunk_id } => {
            edge_placement_score(control_messages, chunk_id)?;
            Some(edge_placement_score(messages, chunk_id).unwrap_or(0.0))
        }
    }
}

fn selected_structured_value(messages: &[Value], chunk_id: &str) -> Option<Value> {
    let snapshot = inspect_marked_context(messages).ok().flatten()?;
    let mut selected = snapshot
        .blocks
        .iter()
        .flat_map(|block| block.chunks.iter())
        .filter(|chunk| chunk.id == chunk_id);
    let chunk = selected.next()?;
    if selected.next().is_some() {
        return None;
    }
    match chunk.format.as_str() {
        "json" => serde_json::from_str(&chunk.body).ok(),
        "sbproxy_table_v1" => decode_sbproxy_table_v1(&chunk.body).ok(),
        _ => None,
    }
}

fn edge_placement_score(messages: &[Value], chunk_id: &str) -> Option<f64> {
    let snapshot = inspect_marked_context(messages).ok().flatten()?;
    let mut scores = snapshot.blocks.iter().filter_map(|block| {
        let mut matches = block
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.id == chunk_id);
        let (ordinal, _) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let maximum_distance = block.chunks.len().saturating_sub(1) / 2;
        if maximum_distance == 0 {
            return Some(1.0);
        }
        let nearest_edge = ordinal.min(block.chunks.len() - 1 - ordinal);
        Some(round_six(
            1.0 - nearest_edge as f64 / maximum_distance as f64,
        ))
    });
    let score = scores.next()?;
    if scores.next().is_some() {
        return None;
    }
    Some(score)
}

fn normalize_answer(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn aggregate(rows: &[&CaseReport]) -> AggregateReport {
    let input_tokens: u64 = rows.iter().map(|row| row.off.output_tokens).sum();
    let output_tokens: u64 = rows.iter().map(|row| row.on.output_tokens).sum();
    let tokens_saved = input_tokens.saturating_sub(output_tokens);
    let off_scores = rows
        .iter()
        .filter_map(|row| row.off.quality_score)
        .collect::<Vec<_>>();
    let on_scores = rows
        .iter()
        .filter_map(|row| row.on.quality_score)
        .collect::<Vec<_>>();
    let off_quality_score = mean(&off_scores, rows.len());
    let on_quality_score = mean(&on_scores, rows.len());
    let quality_delta = match (off_quality_score, on_quality_score) {
        (Some(off), Some(on)) => Some(round_six(on - off)),
        _ => None,
    };
    let latency_complete = rows
        .iter()
        .all(|row| row.added_compression_latency_micros.is_some());
    let added_compression_latency_micros = latency_complete.then(|| {
        rows.iter()
            .filter_map(|row| row.added_compression_latency_micros)
            .sum()
    });
    let mut outcomes = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    for row in rows {
        *outcomes.entry(row.outcome.clone()).or_insert(0) += 1;
        if let Some(reason) = &row.reason {
            *reasons.entry(reason.clone()).or_insert(0) += 1;
        }
    }
    let savings_ratio = ratio(tokens_saved, input_tokens);
    let applied_count = outcomes.get("applied").copied().unwrap_or_default();
    let skipped_count = outcomes.get("skipped").copied().unwrap_or_default();
    let fallback_count = outcomes.get("failed").copied().unwrap_or_default();
    let skip_rate = ratio(skipped_count, rows.len() as u64);
    let acceptance_passed = rows.iter().all(|row| row.acceptance_passed);
    let all_cases_have_explicit_acceptance = rows.iter().all(|row| row.acceptance.is_explicit());
    let recommendation = recommend(
        savings_ratio,
        on_quality_score,
        quality_delta,
        fallback_count,
        acceptance_passed,
        all_cases_have_explicit_acceptance,
    );

    AggregateReport {
        case_count: rows.len(),
        input_tokens,
        output_tokens,
        tokens_saved,
        savings_ratio,
        off_quality_score,
        on_quality_score,
        quality_delta,
        added_compression_latency_micros,
        applied_count,
        skipped_count,
        fallback_count,
        skip_rate,
        outcomes,
        reasons,
        acceptance_passed,
        recommendation,
    }
}

fn recommend(
    savings_ratio: f64,
    on_quality: Option<f64>,
    quality_delta: Option<f64>,
    failures: u64,
    acceptance_passed: bool,
    all_cases_have_explicit_acceptance: bool,
) -> Recommendation {
    if failures > 0 || !acceptance_passed {
        return Recommendation::Defer;
    }
    if all_cases_have_explicit_acceptance {
        return Recommendation::Build;
    }
    let (Some(on_quality), Some(quality_delta)) = (on_quality, quality_delta) else {
        return Recommendation::Defer;
    };
    if on_quality < 0.95 || quality_delta < -0.02 {
        Recommendation::Defer
    } else if savings_ratio >= 0.20 && on_quality >= 0.98 {
        Recommendation::Build
    } else if savings_ratio > 0.0 {
        Recommendation::Borrow
    } else {
        Recommendation::Defer
    }
}

fn mean(values: &[f64], expected_count: usize) -> Option<f64> {
    if values.len() != expected_count || values.is_empty() {
        None
    } else {
        Some(round_six(values.iter().sum::<f64>() / values.len() as f64))
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        round_six(numerator as f64 / denominator as f64)
    }
}

fn round_six(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}
