// SPDX-License-Identifier: Apache-2.0
//! Versioned, precomputed centroids for the built-in safety taxonomies.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use sbproxy_ai::guardrails::DefaultCentroidTaxonomy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ARTIFACT_BYTES: &[u8] = include_bytes!("../artifacts/default-safety-centroids-v1.json");
const ARTIFACT_SHA256: &str = include_str!("../artifacts/default-safety-centroids-v1.sha256");

/// Exact embedding model identity required by the shipped vectors.
pub const DEFAULT_CENTROID_MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";
/// Immutable Hugging Face revision used to produce the shipped vectors.
pub const DEFAULT_CENTROID_MODEL_REVISION: &str = "5641a7880f40ebf4035d05e60c5f9b7a9c272c84";
/// SHA-256 of the ONNX model at [`DEFAULT_CENTROID_MODEL_REVISION`].
pub const DEFAULT_CENTROID_MODEL_SHA256: &str =
    "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452";
/// SHA-256 of the tokenizer at [`DEFAULT_CENTROID_MODEL_REVISION`].
pub const DEFAULT_CENTROID_TOKENIZER_SHA256: &str =
    "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037";
/// Hidden-state dimension produced by the pinned model.
pub const DEFAULT_CENTROID_DIMENSION: usize = 384;

/// One normalized centroid plus the number of examples it represents.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultCentroid {
    /// Number of repo-authored training examples averaged into `vector`.
    pub sample_count: usize,
    /// L2-normalized centroid vector.
    pub vector: Vec<f32>,
}

/// Thresholds and centroids for one closed safety taxonomy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultCentroidTaxonomyArtifact {
    /// Minimum winning cosine similarity.
    pub min_score: f32,
    /// Minimum gap between the winning and runner-up scores.
    pub min_margin: f32,
    /// Closed class label to precomputed centroid.
    pub classes: BTreeMap<String, DefaultCentroid>,
}

/// Model identity and vectors embedded in the released binary.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultCentroidArtifact {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Human-readable artifact release version.
    pub artifact_version: String,
    /// Embedding model repository identity.
    pub model_id: String,
    /// Immutable upstream revision.
    pub model_revision: String,
    /// SHA-256 of the ONNX model bytes.
    pub model_sha256: String,
    /// SHA-256 of the tokenizer bytes.
    pub tokenizer_sha256: String,
    /// Embedding vector dimension.
    pub dimension: usize,
    /// Per-guardrail centroid sets.
    pub taxonomies: BTreeMap<String, DefaultCentroidTaxonomyArtifact>,
}

static ARTIFACT: OnceLock<Result<DefaultCentroidArtifact, String>> = OnceLock::new();

/// Parse and validate the embedded artifact, including its detached digest.
pub fn default_centroid_artifact() -> Result<&'static DefaultCentroidArtifact> {
    match ARTIFACT.get_or_init(|| {
        parse_and_validate_artifact(ARTIFACT_BYTES, ARTIFACT_SHA256.trim())
            .map_err(|error| error.to_string())
    }) {
        Ok(artifact) => Ok(artifact),
        Err(error) => Err(anyhow!("{error}")),
    }
}

/// Return the shipped centroid set selected by a built-in safety guardrail.
pub fn default_safety_centroids(
    taxonomy: DefaultCentroidTaxonomy,
) -> Result<&'static DefaultCentroidTaxonomyArtifact> {
    let key = match taxonomy {
        DefaultCentroidTaxonomy::Toxicity => "toxicity",
        DefaultCentroidTaxonomy::Jailbreak => "jailbreak",
        DefaultCentroidTaxonomy::ContentSafety => "content_safety",
    };
    default_centroid_artifact()?
        .taxonomies
        .get(key)
        .ok_or_else(|| anyhow!("default centroid artifact is missing taxonomy `{key}`"))
}

fn parse_and_validate_artifact(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<DefaultCentroidArtifact> {
    let actual_sha256 = hex::encode(Sha256::digest(bytes));
    if actual_sha256 != expected_sha256 {
        bail!(
            "default centroid artifact sha256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        );
    }
    let artifact: DefaultCentroidArtifact =
        serde_json::from_slice(bytes).context("failed to parse default centroid artifact")?;
    validate_artifact(&artifact)?;
    Ok(artifact)
}

fn validate_artifact(artifact: &DefaultCentroidArtifact) -> Result<()> {
    if artifact.schema_version != 1 || artifact.artifact_version != "safety-centroids-1.0.0" {
        bail!("unsupported default centroid artifact version");
    }
    if artifact.model_id != DEFAULT_CENTROID_MODEL_ID
        || artifact.model_revision != DEFAULT_CENTROID_MODEL_REVISION
        || artifact.model_sha256 != DEFAULT_CENTROID_MODEL_SHA256
        || artifact.tokenizer_sha256 != DEFAULT_CENTROID_TOKENIZER_SHA256
        || artifact.dimension != DEFAULT_CENTROID_DIMENSION
    {
        bail!("default centroid artifact model identity does not match the compiled pin");
    }
    let expected = [
        ("toxicity", &["safe", "toxic"][..]),
        ("jailbreak", &["jailbreak", "safe"][..]),
        (
            "content_safety",
            &[
                "hate_speech",
                "illegal",
                "safe",
                "self_harm",
                "sexual",
                "violence",
            ][..],
        ),
    ];
    if artifact.taxonomies.len() != expected.len() {
        bail!("default centroid artifact contains an unexpected taxonomy");
    }
    for (taxonomy, labels) in expected {
        let set = artifact
            .taxonomies
            .get(taxonomy)
            .ok_or_else(|| anyhow!("default centroid artifact is missing taxonomy `{taxonomy}`"))?;
        let actual: Vec<&str> = set.classes.keys().map(String::as_str).collect();
        if actual != labels {
            bail!("default centroid taxonomy `{taxonomy}` has unexpected classes");
        }
        if !(0.0..=1.0).contains(&set.min_score) || !(0.0..=2.0).contains(&set.min_margin) {
            bail!("default centroid taxonomy `{taxonomy}` has invalid thresholds");
        }
        for (label, centroid) in &set.classes {
            if centroid.sample_count == 0
                || centroid.vector.len() != DEFAULT_CENTROID_DIMENSION
                || centroid.vector.iter().any(|value| !value.is_finite())
            {
                bail!("default centroid `{taxonomy}.{label}` is malformed");
            }
            let norm = centroid
                .vector
                .iter()
                .map(|value| value * value)
                .sum::<f32>()
                .sqrt();
            if (norm - 1.0).abs() > 1e-4 {
                bail!("default centroid `{taxonomy}.{label}` is not normalized");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_artifact_matches_its_digest_model_pin_and_closed_taxonomies() {
        let artifact = default_centroid_artifact().expect("shipped artifact must validate");
        assert_eq!(artifact.schema_version, 1);
        assert_eq!(artifact.dimension, DEFAULT_CENTROID_DIMENSION);
        assert_eq!(artifact.taxonomies.len(), 3);
    }

    #[test]
    fn artifact_digest_mismatch_is_a_hard_error() {
        let error = parse_and_validate_artifact(b"{}", &"0".repeat(64))
            .expect_err("tampered bytes must not parse")
            .to_string();
        assert!(
            error.contains("sha256 mismatch"),
            "unexpected error: {error}"
        );
    }
}
