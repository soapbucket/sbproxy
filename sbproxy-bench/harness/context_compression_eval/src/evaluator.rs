use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, Result};
use sbproxy_ai::compression::{
    CompressionRequest, CompressionRunner, LeverOutcome, WindowFitConfig, WindowFitLever,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EvalCase, QualitySpec};

/// Immutable settings shared by every case in one evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalConfig {
    /// Named profile shown in reports.
    pub profile: String,
    /// Completion reserve used by the real window-fit lever.
    pub completion_reserve_tokens: u64,
    /// Include observed wall-clock latency in this non-gated artifact.
    pub measure_latency: bool,
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
    /// Window-fit treatment arm.
    pub on: ArmReport,
    /// Target-model tokens avoided by the treatment.
    pub tokens_saved: u64,
    /// Saved tokens divided by control output tokens.
    pub savings_ratio: f64,
    /// Treatment quality minus control quality.
    pub quality_delta: Option<f64>,
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
    /// Cases where window fit committed a reduction.
    pub applied_count: u64,
    /// Cases where window fit made no change for a closed skip reason.
    pub skipped_count: u64,
    /// Failed cases that fell back to the unchanged working message list.
    pub fallback_count: u64,
    /// Skipped cases divided by all cases.
    pub skip_rate: f64,
    /// Applied, skipped, and failed counts.
    pub outcomes: BTreeMap<String, u64>,
    /// Closed skip and failure reason counts.
    pub reasons: BTreeMap<String, u64>,
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

/// Evaluate every case with identical input through off and real window-fit arms.
pub async fn evaluate_cases(cases: &[EvalCase], config: &EvalConfig) -> Result<EvalReport> {
    if cases.is_empty() {
        bail!("evaluation requires at least one case");
    }
    if config.profile.trim().is_empty() {
        bail!("evaluation profile must not be empty");
    }

    let off_runner = CompressionRunner::with_model_counter(Vec::new());
    let window_fit_config: WindowFitConfig = serde_json::from_value(serde_json::json!({
        "completion_reserve_tokens": config.completion_reserve_tokens
    }))?;
    let on_runner = CompressionRunner::with_model_counter(vec![Arc::new(WindowFitLever::new(
        window_fit_config,
    ))]);

    let mut rows = Vec::with_capacity(cases.len());
    for case in cases {
        let request = CompressionRequest::new(&case.target_model);
        let off = off_runner.run(&request, &case.messages).await;
        let on = on_runner.run(&request, &case.messages).await;
        let off_quality = score_quality(&case.quality, &off.messages, false);
        let on_quality = score_quality(&case.quality, &on.messages, true);
        let lever = on.lever_results.first();
        let (outcome, reason) = match lever.map(|result| result.outcome) {
            Some(LeverOutcome::Applied) => ("applied", None),
            Some(LeverOutcome::Skipped { reason }) => {
                ("skipped", Some(reason.as_str().to_string()))
            }
            Some(LeverOutcome::Failed { reason }) => ("failed", Some(reason.as_str().to_string())),
            None => ("skipped", Some("empty_pipeline".to_string())),
        };
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
        rows.push(CaseReport {
            id: case.id.clone(),
            corpus: case.corpus.clone(),
            target_model: case.target_model.clone(),
            quality_metric: match &case.quality {
                QualitySpec::EvidenceRetention { .. } => "evidence_retention",
                QualitySpec::ExactMatch { .. } => "exact_match_accuracy",
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
            added_compression_latency_micros: latency,
            outcome: outcome.to_string(),
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
        schema_version: 1,
        profile: config.profile.clone(),
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

fn score_quality(spec: &QualitySpec, messages: &[Value], treatment_arm: bool) -> Option<f64> {
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
    }
}

fn normalize_answer(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn aggregate(rows: &[&CaseReport]) -> AggregateReport {
    let input_tokens = rows.iter().map(|row| row.off.output_tokens).sum();
    let output_tokens = rows.iter().map(|row| row.on.output_tokens).sum();
    let tokens_saved = input_tokens - output_tokens;
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
    let recommendation = recommend(
        savings_ratio,
        on_quality_score,
        quality_delta,
        fallback_count,
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
        recommendation,
    }
}

fn recommend(
    savings_ratio: f64,
    on_quality: Option<f64>,
    quality_delta: Option<f64>,
    failures: u64,
) -> Recommendation {
    let (Some(on_quality), Some(quality_delta)) = (on_quality, quality_delta) else {
        return Recommendation::Defer;
    };
    if failures > 0 || on_quality < 0.95 || quality_delta < -0.02 {
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
