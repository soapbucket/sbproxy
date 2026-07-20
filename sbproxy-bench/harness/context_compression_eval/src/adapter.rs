use std::io::BufRead;

use anyhow::{anyhow, bail, Result};
use clap::ValueEnum;
use serde::Deserialize;
use serde_json::json;

use crate::{AcceptanceSpec, EvalCase, QualitySpec};

/// External suite label accepted by the generic interchange adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExternalSuite {
    /// NVIDIA RULER input exported by the operator.
    Ruler,
    /// Princeton HELMET input exported by the operator.
    Helmet,
    /// LongBench-v2 input exported by the operator.
    #[value(name = "longbench-v2")]
    LongBenchV2,
    /// NoLiMa input supplied by an operator under its own license.
    NoLiMa,
}

impl ExternalSuite {
    const fn corpus(self) -> &'static str {
        match self {
            Self::Ruler => "ruler_external",
            Self::Helmet => "helmet_external",
            Self::LongBenchV2 => "longbench_v2_external",
            Self::NoLiMa => "nolima_external",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalCase {
    id: String,
    context: String,
    question: String,
    reference_answers: Vec<String>,
    off_prediction: String,
    on_prediction: String,
}

/// Convert the documented external interchange JSONL into normalized cases.
pub fn adapt_external_jsonl(
    reader: impl BufRead,
    suite: ExternalSuite,
    target_model: &str,
) -> Result<String> {
    if target_model.trim().is_empty() {
        bail!("target model must not be empty");
    }
    let mut cases = reader
        .lines()
        .enumerate()
        .filter_map(|(index, line)| match line {
            Ok(line) if line.trim().is_empty() => None,
            line => Some((index, line)),
        })
        .map(|(index, line)| {
            let line = line.map_err(|error| anyhow!("read external JSONL line {}: {error}", index + 1))?;
            let external: ExternalCase = serde_json::from_str(&line).map_err(|error| {
                anyhow!("parse external JSONL line {}: {error}", index + 1)
            })?;
            if external.id.trim().is_empty() {
                bail!("external JSONL line {} has an empty id", index + 1);
            }
            if external.reference_answers.is_empty() {
                bail!(
                    "external JSONL line {} has no reference answers",
                    index + 1
                );
            }
            Ok(EvalCase {
                schema_version: 1,
                id: external.id,
                corpus: suite.corpus().to_string(),
                target_model: target_model.to_string(),
                messages: vec![
                    json!({
                        "role": "system",
                        "content": "Answer the external evaluation question from the supplied context."
                    }),
                    json!({"role": "user", "content": external.context}),
                    json!({"role": "user", "content": external.question}),
                ],
                quality: QualitySpec::ExactMatch {
                    reference_answers: external.reference_answers,
                    off_prediction: external.off_prediction,
                    on_prediction: external.on_prediction,
                },
                acceptance: AcceptanceSpec::default(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    let mut output = String::new();
    for case in cases {
        output.push_str(&serde_json::to_string(&case)?);
        output.push('\n');
    }
    Ok(output)
}
