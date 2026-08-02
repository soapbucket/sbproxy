//! Regenerate and evaluate the shipped safety-centroid artifact.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sbproxy_classifiers::{
    DefaultCentroid, DefaultCentroidArtifact, DefaultCentroidTaxonomyArtifact, OnnxEmbedder,
    DEFAULT_CENTROID_DIMENSION, DEFAULT_CENTROID_MODEL_ID, DEFAULT_CENTROID_MODEL_REVISION,
    DEFAULT_CENTROID_MODEL_SHA256, DEFAULT_CENTROID_TOKENIZER_SHA256,
};
use sha2::{Digest, Sha256};

type Fixtures = BTreeMap<String, BTreeMap<String, Vec<String>>>;

#[derive(Debug, Default)]
struct Counts {
    true_positive: usize,
    false_positive: usize,
    false_negative: usize,
    support: usize,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        bail!(
            "usage: regenerate-default-safety-centroids \
             <model.onnx> <tokenizer.json> <training.json> <evaluation.json> \
             <artifact.json> <report.md>"
        );
    }
    let model_path = PathBuf::from(&args[0]);
    let tokenizer_path = PathBuf::from(&args[1]);
    verify_sha256(&model_path, DEFAULT_CENTROID_MODEL_SHA256, "model")?;
    verify_sha256(
        &tokenizer_path,
        DEFAULT_CENTROID_TOKENIZER_SHA256,
        "tokenizer",
    )?;
    let training: Fixtures =
        serde_json::from_slice(&std::fs::read(&args[2]).context("read training fixtures")?)
            .context("parse training fixtures")?;
    let evaluation: Fixtures =
        serde_json::from_slice(&std::fs::read(&args[3]).context("read evaluation fixtures")?)
            .context("parse evaluation fixtures")?;
    if training.keys().collect::<Vec<_>>() != evaluation.keys().collect::<Vec<_>>() {
        bail!("training and evaluation taxonomy names differ");
    }

    let embedder = OnnxEmbedder::load(&model_path, &tokenizer_path)?;
    let mut taxonomies = BTreeMap::new();
    for (taxonomy, classes) in &training {
        let mut centroids = BTreeMap::new();
        for (label, examples) in classes {
            let vectors = examples
                .iter()
                .map(|text| embedder.embed(text).map(|output| output.values))
                .collect::<Result<Vec<_>>>()?;
            let vector = centroid(&vectors)
                .with_context(|| format!("build centroid for `{taxonomy}.{label}`"))?;
            centroids.insert(
                label.clone(),
                DefaultCentroid {
                    sample_count: examples.len(),
                    vector,
                },
            );
        }
        taxonomies.insert(
            taxonomy.clone(),
            DefaultCentroidTaxonomyArtifact {
                min_score: 0.30,
                min_margin: if taxonomy == "content_safety" {
                    0.08
                } else {
                    0.10
                },
                classes: centroids,
            },
        );
    }
    let artifact = DefaultCentroidArtifact {
        schema_version: 1,
        artifact_version: "safety-centroids-1.0.0".to_string(),
        model_id: DEFAULT_CENTROID_MODEL_ID.to_string(),
        model_revision: DEFAULT_CENTROID_MODEL_REVISION.to_string(),
        model_sha256: DEFAULT_CENTROID_MODEL_SHA256.to_string(),
        tokenizer_sha256: DEFAULT_CENTROID_TOKENIZER_SHA256.to_string(),
        dimension: DEFAULT_CENTROID_DIMENSION,
        taxonomies,
    };
    validate_fixture_shape(&artifact, &evaluation)?;
    let artifact_bytes = format!("{}\n", serde_json::to_string_pretty(&artifact)?).into_bytes();
    let artifact_sha256 = hex::encode(Sha256::digest(&artifact_bytes));
    let report = evaluation_report(&embedder, &artifact, &evaluation, &artifact_sha256)?;

    std::fs::write(&args[4], artifact_bytes).context("write centroid artifact")?;
    std::fs::write(&args[5], report).context("write evaluation report")?;
    println!("{artifact_sha256}");
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str, kind: &str) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {kind} at {path:?}"))?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        bail!("{kind} sha256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn centroid(vectors: &[Vec<f32>]) -> Option<Vec<f32>> {
    let dimension = vectors.first()?.len();
    if dimension == 0
        || vectors
            .iter()
            .any(|vector| vector.len() != dimension || vector.iter().any(|v| !v.is_finite()))
    {
        return None;
    }
    let mut sum = vec![0.0; dimension];
    for vector in vectors {
        for (total, value) in sum.iter_mut().zip(vector) {
            *total += value;
        }
    }
    normalize(&mut sum)?;
    // Remove platform-specific last-bit noise from SIMD reductions so the
    // committed JSON is reproducible across supported CPU architectures.
    for value in &mut sum {
        *value = (*value * 1_000_000.0).round() / 1_000_000.0;
    }
    Some(sum)
}

fn normalize(vector: &mut [f32]) -> Option<()> {
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= f32::EPSILON {
        return None;
    }
    for value in vector {
        *value /= norm;
    }
    Some(())
}

fn validate_fixture_shape(artifact: &DefaultCentroidArtifact, evaluation: &Fixtures) -> Result<()> {
    for (taxonomy, fixture_classes) in evaluation {
        let artifact_classes = artifact
            .taxonomies
            .get(taxonomy)
            .with_context(|| format!("evaluation taxonomy `{taxonomy}` is not trained"))?;
        if fixture_classes.keys().collect::<Vec<_>>()
            != artifact_classes.classes.keys().collect::<Vec<_>>()
        {
            bail!("evaluation classes differ for taxonomy `{taxonomy}`");
        }
        if fixture_classes.values().any(Vec::is_empty) {
            bail!("evaluation taxonomy `{taxonomy}` has an empty class");
        }
    }
    Ok(())
}

fn classify(embedding: &[f32], taxonomy: &DefaultCentroidTaxonomyArtifact) -> Option<String> {
    let mut scored: Vec<(f32, &str)> = taxonomy
        .classes
        .iter()
        .map(|(label, centroid)| {
            (
                embedding
                    .iter()
                    .zip(&centroid.vector)
                    .map(|(a, b)| a * b)
                    .sum(),
                label.as_str(),
            )
        })
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    let (best_score, best_label) = scored[0];
    if best_score < taxonomy.min_score {
        return None;
    }
    if scored
        .get(1)
        .is_some_and(|(second_score, _)| best_score - second_score < taxonomy.min_margin)
    {
        return None;
    }
    Some(best_label.to_string())
}

fn evaluation_report(
    embedder: &OnnxEmbedder,
    artifact: &DefaultCentroidArtifact,
    evaluation: &Fixtures,
    artifact_sha256: &str,
) -> Result<String> {
    let mut report = String::from(
        "# Default safety centroid evaluation\n\n\
         *Last modified: 2026-07-26*\n\n\
         This report is generated from repo-authored, held-out fixtures. The \
         training and evaluation prompts are disjoint. No external attack \
         corpus is vendored or redistributed.\n\n\
         ## Method\n\n\
         The regeneration tool embeds each training prompt with the pinned \
         `all-MiniLM-L6-v2` ONNX model, averages each class into a unit \
         centroid, rounds vector components to six decimal places for \
         cross-CPU reproducibility, then classifies held-out prompts by cosine similarity. A \
         verdict requires a score of at least 0.30 and a 0.10 lead over the \
         runner-up for the binary taxonomies, or a 0.08 lead for the \
         six-class content-safety taxonomy. The false-positive budget is zero unsafe verdicts on the \
         10 held-out safe prompts in each taxonomy. This conservative budget \
         takes priority over recall because these guardrails block requests \
         before provider egress. Threshold abstentions are allowed.\n\n",
    );
    writeln!(
        report,
        "- Artifact version: `safety-centroids-1.0.0`\n\
         - Artifact SHA-256: `{artifact_sha256}`\n\
         - Model: `{}` at revision `{}`\n\
         - Model SHA-256: `{}`\n\
         - Tokenizer SHA-256: `{}`\n",
        DEFAULT_CENTROID_MODEL_ID,
        DEFAULT_CENTROID_MODEL_REVISION,
        DEFAULT_CENTROID_MODEL_SHA256,
        DEFAULT_CENTROID_TOKENIZER_SHA256
    )?;

    for (taxonomy_name, fixtures) in evaluation {
        let taxonomy = &artifact.taxonomies[taxonomy_name];
        let mut counts: BTreeMap<String, Counts> = taxonomy
            .classes
            .keys()
            .map(|label| (label.clone(), Counts::default()))
            .collect();
        let mut safe_false_positives = 0;
        let mut abstentions = 0;
        for (expected, prompts) in fixtures {
            for prompt in prompts {
                let embedding = embedder.embed(prompt)?.values;
                let predicted = classify(&embedding, taxonomy);
                counts.get_mut(expected).expect("closed class").support += 1;
                if predicted.is_none() {
                    abstentions += 1;
                }
                for (label, class_counts) in &mut counts {
                    if predicted.as_deref() == Some(label) && expected == label {
                        class_counts.true_positive += 1;
                    } else if predicted.as_deref() == Some(label) {
                        class_counts.false_positive += 1;
                    } else if expected == label {
                        class_counts.false_negative += 1;
                    }
                }
                if expected == "safe" && predicted.as_deref().is_some_and(|label| label != "safe") {
                    safe_false_positives += 1;
                }
            }
        }
        if safe_false_positives != 0 {
            bail!(
                "taxonomy `{taxonomy_name}` exceeded its zero false-positive budget: \
                 {safe_false_positives}/10"
            );
        }
        for (label, class_counts) in &counts {
            if label != "safe"
                && ratio(
                    class_counts.true_positive,
                    class_counts.true_positive + class_counts.false_negative,
                ) < 0.80
            {
                bail!("taxonomy `{taxonomy_name}` class `{label}` recall fell below 0.80");
            }
        }
        writeln!(report, "## `{taxonomy_name}`\n")?;
        writeln!(
            report,
            "Safe-prompt false positives: {safe_false_positives}/10. Abstentions: {abstentions}/{}.\n",
            fixtures.values().map(Vec::len).sum::<usize>()
        )?;
        writeln!(
            report,
            "| Class | Support | Precision | Recall |\n|---|---:|---:|---:|"
        )?;
        for (label, class_counts) in counts {
            let precision = ratio(
                class_counts.true_positive,
                class_counts.true_positive + class_counts.false_positive,
            );
            let recall = ratio(
                class_counts.true_positive,
                class_counts.true_positive + class_counts.false_negative,
            );
            writeln!(
                report,
                "| `{label}` | {} | {precision:.3} | {recall:.3} |",
                class_counts.support
            )?;
        }
        report.push('\n');
    }
    Ok(format!("{}\n", report.trim_end()))
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
