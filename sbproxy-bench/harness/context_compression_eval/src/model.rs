use std::collections::BTreeSet;
use std::io::BufRead;

use anyhow::{anyhow, Context, Result};
use sbproxy_ai::compression::CompressionLeverConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Checked, ordered compression pipeline consumed by the evaluation CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalPipelineFile {
    /// Pipeline file schema version.
    pub schema_version: u32,
    /// Stable profile name copied into generated reports.
    pub profile: String,
    /// Ordered typed production compression levers.
    pub levers: Vec<CompressionLeverConfig>,
}

/// One normalized, provider-independent evaluation case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCase {
    /// Normalized case schema version.
    pub schema_version: u32,
    /// Stable case identifier within the corpus.
    pub id: String,
    /// Bounded corpus identifier reported by the smoke gate.
    pub corpus: String,
    /// Target model used by both evaluation arms.
    pub target_model: String,
    /// Original chat message list presented to both arms.
    pub messages: Vec<Value>,
    /// Deterministic or imported-prediction quality contract.
    pub quality: QualitySpec,
    /// Case-local deterministic acceptance gates.
    #[serde(default)]
    pub acceptance: AcceptanceSpec,
}

/// Optional deterministic acceptance gates for one evaluation case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceSpec {
    /// Minimum request-level token reduction ratio, in the inclusive 0 to 1 range.
    pub min_savings_ratio: Option<f64>,
    /// Minimum treatment quality score, in the inclusive 0 to 1 range.
    pub min_on_quality_score: Option<f64>,
    /// Minimum treatment-minus-control quality delta, in the inclusive -1 to 1 range.
    pub min_quality_delta: Option<f64>,
    /// Require the treatment token count not to exceed the control token count.
    #[serde(default)]
    pub require_non_expanding: bool,
}

impl AcceptanceSpec {
    /// Whether this case declares any explicit acceptance gate.
    pub fn is_explicit(&self) -> bool {
        self.min_savings_ratio.is_some()
            || self.min_on_quality_score.is_some()
            || self.min_quality_delta.is_some()
            || self.require_non_expanding
    }

    /// Evaluate the declared gates against one off/on result.
    pub fn passes(
        &self,
        off_tokens: u64,
        on_tokens: u64,
        on_quality_score: Option<f64>,
        quality_delta: Option<f64>,
    ) -> bool {
        if self.require_non_expanding && on_tokens > off_tokens {
            return false;
        }
        let savings_ratio = if off_tokens == 0 {
            if on_tokens == 0 {
                0.0
            } else {
                f64::NEG_INFINITY
            }
        } else {
            (off_tokens as f64 - on_tokens as f64) / off_tokens as f64
        };
        if self
            .min_savings_ratio
            .is_some_and(|minimum| savings_ratio < minimum)
        {
            return false;
        }
        if self
            .min_on_quality_score
            .is_some_and(|minimum| on_quality_score.is_none_or(|quality| quality < minimum))
        {
            return false;
        }
        if self
            .min_quality_delta
            .is_some_and(|minimum| quality_delta.is_none_or(|delta| delta < minimum))
        {
            return false;
        }
        true
    }

    pub(crate) fn validate(&self, case_id: &str) -> Result<()> {
        validate_threshold(
            case_id,
            "min_savings_ratio",
            self.min_savings_ratio,
            0.0,
            1.0,
        )?;
        validate_threshold(
            case_id,
            "min_on_quality_score",
            self.min_on_quality_score,
            0.0,
            1.0,
        )?;
        validate_threshold(
            case_id,
            "min_quality_delta",
            self.min_quality_delta,
            -1.0,
            1.0,
        )
    }
}

/// Quality evidence available without invoking an external model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualitySpec {
    /// Score the fraction of required evidence strings retained in each arm.
    EvidenceRetention {
        /// Literal evidence markers that must survive compression.
        required_evidence: Vec<String>,
    },
    /// Score already-generated model predictions with normalized exact match.
    ExactMatch {
        /// One or more accepted reference answers.
        reference_answers: Vec<String>,
        /// Prediction generated from the uncompressed arm.
        off_prediction: String,
        /// Prediction generated from the compressed arm.
        on_prediction: String,
    },
    /// Compare a selected marked JSON/table chunk with the control value.
    StructuredEquivalence {
        /// Stable marked chunk identifier to decode in both arms.
        chunk_id: String,
    },
    /// Score a selected chunk's normalized proximity to its containing block's edge.
    EdgePlacement {
        /// Stable marked chunk identifier to locate in both arms.
        chunk_id: String,
    },
}

/// Parse strict normalized JSONL input.
pub fn parse_cases(reader: impl BufRead) -> Result<Vec<EvalCase>> {
    let cases: Vec<EvalCase> = reader
        .lines()
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            line => Some((index, line)),
        })
        .map(|(index, line)| {
            let line = line.with_context(|| format!("read normalized JSONL line {}", index + 1))?;
            serde_json::from_str(&line)
                .map_err(|error| anyhow!("parse normalized JSONL line {}: {error}", index + 1))
        })
        .collect::<Result<_>>()?;
    let mut ids = BTreeSet::new();
    for case in &cases {
        if case.schema_version != 1 {
            return Err(anyhow!(
                "case `{}` uses unsupported schema version {}",
                case.id,
                case.schema_version
            ));
        }
        if !ids.insert(case.id.as_str()) {
            return Err(anyhow!("duplicate case id `{}`", case.id));
        }
        case.acceptance.validate(&case.id)?;
    }
    Ok(cases)
}

fn validate_threshold(
    case_id: &str,
    name: &str,
    value: Option<f64>,
    minimum: f64,
    maximum: f64,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if !value.is_finite() || !(minimum..=maximum).contains(&value) {
        let range = if minimum == 0.0 {
            "0 and 1"
        } else {
            "-1 and 1"
        };
        return Err(anyhow!(
            "case `{case_id}` acceptance {name} must be finite and between {range}"
        ));
    }
    Ok(())
}
