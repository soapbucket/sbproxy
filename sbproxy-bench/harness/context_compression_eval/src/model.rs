use std::collections::BTreeSet;
use std::io::BufRead;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    }
    Ok(cases)
}
