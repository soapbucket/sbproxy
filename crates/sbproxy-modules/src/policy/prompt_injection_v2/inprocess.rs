// SPDX-License-Identifier: Apache-2.0
//! In-process ONNX detector for `prompt_injection_v2`.
//!
//! Runs the tract ONNX classifier inside the proxy address space. WOR-612
//! removed the original in-process detector because an unsandboxed model
//! parse could OOM the proxy. This implementation verifies mandatory
//! SHA-256 pins and size limits before parsing. Operators can select it
//! explicitly or omit `detector` to activate it when a complete verified
//! artifact pair is staged. Operators who want process isolation should
//! still prefer `detector: "sidecar"`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context as _};
use sbproxy_classifiers::{
    default_model_cache_dir, lookup_known_model, parse_ed25519_pubkey, LoadOptions,
    LocalArtifactVerification, OnnxClassifier,
};
use serde::Deserialize;

use super::detector::{DetectionLabel, DetectionResult, Detector};

/// Config name selecting this detector (`detector: "inprocess"`).
pub const INPROCESS_DETECTOR_NAME: &str = "inprocess";

const DEFAULT_INJECTION_LABEL: &str = "INJECTION";
const DEFAULT_THRESHOLD: f64 = 0.5;
const DEFAULT_MODEL_NAME: &str = "prompt-injection-v2";
const DEFAULT_MODEL_FILENAME: &str = "model.onnx";
const DEFAULT_TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Map a `[0,1]` injection score onto the v2 label vocabulary. Same
/// cutoffs as the sidecar detector so the two report identically.
fn classify_score(score: f64, threshold: f64) -> DetectionLabel {
    if score >= threshold {
        DetectionLabel::Injection
    } else if score >= 0.3 {
        DetectionLabel::Suspicious
    } else {
        DetectionLabel::Clean
    }
}

/// Deserializable `detector_config` block for the in-process detector.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InprocessDetectorConfig {
    /// Path to the ONNX model file.
    #[serde(default)]
    model_path: Option<PathBuf>,
    /// Path to the tokenizer.json file.
    #[serde(default)]
    tokenizer_path: Option<PathBuf>,
    /// Known-model registry name used for pins when explicit hashes are
    /// omitted.
    #[serde(default = "default_model_name")]
    model: String,
    /// SHA-256 pin for the ONNX file.
    #[serde(default)]
    model_sha256: Option<String>,
    /// SHA-256 pin for the tokenizer file.
    #[serde(default)]
    tokenizer_sha256: Option<String>,
    /// Optional detached Ed25519 signature for the ONNX file.
    #[serde(default)]
    model_signature_path: Option<PathBuf>,
    /// Optional detached Ed25519 signature for the tokenizer file.
    #[serde(default)]
    tokenizer_signature_path: Option<PathBuf>,
    /// Ed25519 public key as a PEM SPKI block or 64 hex characters.
    #[serde(default)]
    signature_public_key: Option<String>,
    /// Optional class labels indexed by output class. When omitted, the
    /// prompt-injection vocabulary defaults to `SAFE`, `INJECTION`.
    #[serde(default)]
    labels: Option<Vec<String>>,
    /// Label name (case-insensitive) treated as the injection verdict.
    #[serde(default = "default_injection_label")]
    injection_label: String,
    /// Score at or above which a verdict is labelled `injection`.
    #[serde(default = "default_threshold")]
    threshold: f64,
    /// Hard upper bound on the ONNX model file size in bytes. None uses
    /// the engine default (200 MB). This is the guard that bounds the
    /// OOM risk WOR-612 flagged.
    #[serde(default)]
    max_model_bytes: Option<u64>,
    /// Optional tokenizer size override. None uses the same 200 MiB engine
    /// default.
    #[serde(default)]
    max_tokenizer_bytes: Option<u64>,
}

fn default_model_name() -> String {
    DEFAULT_MODEL_NAME.to_string()
}
fn default_injection_label() -> String {
    DEFAULT_INJECTION_LABEL.to_string()
}
fn default_threshold() -> f64 {
    DEFAULT_THRESHOLD
}

/// Detector that runs ONNX classification in-process via tract.
pub struct InprocessDetector {
    classifier: OnnxClassifier,
    injection_label: String,
    threshold: f64,
    name: &'static str,
}

pub(super) enum AutoInprocessSelection {
    Loaded(Arc<dyn Detector>),
    Absent {
        model_path: PathBuf,
        tokenizer_path: PathBuf,
    },
}

impl InprocessDetector {
    /// Build from the policy's `detector_config` block. Loads the model at
    /// construction time (the slow path) so `detect` stays cheap; the
    /// size guard is enforced before the graph is parsed.
    pub fn from_config(value: &serde_json::Value) -> anyhow::Result<Arc<dyn Detector>> {
        let cfg = parse_config(value)?;
        let (model_path, tokenizer_path) = configured_paths(&cfg)
            .context("inprocess detector config requires model_path and tokenizer_path")?;
        Self::load_verified(cfg, &model_path, &tokenizer_path)
    }

    pub(super) fn from_auto_config(
        value: &serde_json::Value,
    ) -> anyhow::Result<AutoInprocessSelection> {
        Self::from_auto_config_at_cache_root(value, &default_model_cache_dir())
    }

    fn from_auto_config_at_cache_root(
        value: &serde_json::Value,
        default_cache_root: &Path,
    ) -> anyhow::Result<AutoInprocessSelection> {
        let cfg = parse_config(value)?;
        let (model_path, tokenizer_path) = auto_paths(&cfg, default_cache_root)?;
        let model_present = model_path
            .try_exists()
            .with_context(|| format!("checking model_path {}", model_path.display()))?;
        let tokenizer_present = tokenizer_path
            .try_exists()
            .with_context(|| format!("checking tokenizer_path {}", tokenizer_path.display()))?;

        match (model_present, tokenizer_present) {
            (false, false) => Ok(AutoInprocessSelection::Absent {
                model_path,
                tokenizer_path,
            }),
            (true, false) | (false, true) => bail!(
                "prompt_injection_v2 auto-selection requires model_path and tokenizer_path \
                 together; resolved model_path={} (present={model_present}), \
                 tokenizer_path={} (present={tokenizer_present})",
                model_path.display(),
                tokenizer_path.display(),
            ),
            (true, true) => Self::load_verified(cfg, &model_path, &tokenizer_path)
                .map(AutoInprocessSelection::Loaded),
        }
    }

    fn load_verified(
        cfg: InprocessDetectorConfig,
        model_path: &Path,
        tokenizer_path: &Path,
    ) -> anyhow::Result<Arc<dyn Detector>> {
        if !(0.0..=1.0).contains(&cfg.threshold) {
            bail!(
                "inprocess detector threshold must be in [0.0, 1.0], got {}",
                cfg.threshold
            );
        }
        let mut options = LoadOptions::default();
        if let Some(bytes) = cfg.max_model_bytes {
            options = options.with_max_model_bytes(bytes);
        }
        if let Some(bytes) = cfg.max_tokenizer_bytes {
            options = options.with_max_tokenizer_bytes(bytes);
        }
        let mut verification = verification_for(&cfg)?;
        if let (Some(model_signature_path), Some(tokenizer_signature_path), Some(public_key)) = (
            cfg.model_signature_path.as_ref(),
            cfg.tokenizer_signature_path.as_ref(),
            cfg.signature_public_key.as_deref(),
        ) {
            verification = verification.with_signatures(
                model_signature_path,
                tokenizer_signature_path,
                parse_ed25519_pubkey(public_key)
                    .context("inprocess detector signature_public_key")?,
            );
        }
        let labels = cfg
            .labels
            .unwrap_or_else(|| vec!["SAFE".to_string(), "INJECTION".to_string()]);
        if !labels
            .iter()
            .any(|label| label.eq_ignore_ascii_case(&cfg.injection_label))
        {
            bail!(
                "inprocess detector labels must contain injection_label {:?}",
                cfg.injection_label
            );
        }
        let classifier = OnnxClassifier::load_verified_local_with_options(
            model_path,
            tokenizer_path,
            Some(labels),
            &verification,
            &options,
        )
        .map_err(|e| anyhow::anyhow!("inprocess detector: {e}"))?;
        Ok(Arc::new(Self {
            classifier,
            injection_label: cfg.injection_label,
            threshold: cfg.threshold,
            name: INPROCESS_DETECTOR_NAME,
        }))
    }
}

fn parse_config(value: &serde_json::Value) -> anyhow::Result<InprocessDetectorConfig> {
    let value = if value.is_null() {
        serde_json::json!({})
    } else {
        value.clone()
    };
    serde_json::from_value(value).map_err(|e| anyhow::anyhow!("inprocess detector config: {e}"))
}

fn configured_paths(cfg: &InprocessDetectorConfig) -> anyhow::Result<(PathBuf, PathBuf)> {
    match (&cfg.model_path, &cfg.tokenizer_path) {
        (Some(model), Some(tokenizer)) => Ok((model.clone(), tokenizer.clone())),
        _ => bail!("both model_path and tokenizer_path are required"),
    }
}

fn auto_paths(
    cfg: &InprocessDetectorConfig,
    default_cache_root: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    match (&cfg.model_path, &cfg.tokenizer_path) {
        (Some(model), Some(tokenizer)) => Ok((model.clone(), tokenizer.clone())),
        (None, None) => {
            let root = default_cache_root.join(DEFAULT_MODEL_NAME);
            Ok((
                root.join(DEFAULT_MODEL_FILENAME),
                root.join(DEFAULT_TOKENIZER_FILENAME),
            ))
        }
        _ => bail!(
            "prompt_injection_v2 auto-selection requires both model_path and tokenizer_path \
             when either is configured"
        ),
    }
}

fn verification_for(cfg: &InprocessDetectorConfig) -> anyhow::Result<LocalArtifactVerification> {
    let (model_sha256, tokenizer_sha256) = match (&cfg.model_sha256, &cfg.tokenizer_sha256) {
        (Some(model), Some(tokenizer)) => (model.as_str(), tokenizer.as_str()),
        (None, None) => lookup_known_model(&cfg.model)
            .and_then(|model| model.pinned_pair())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "inprocess detector requires model_sha256 and tokenizer_sha256; \
                         known model {:?} has no complete trusted pin pair",
                    cfg.model
                )
            })?,
        _ => bail!("inprocess detector requires model_sha256 and tokenizer_sha256 together"),
    };

    match (
        cfg.model_signature_path.as_ref(),
        cfg.tokenizer_signature_path.as_ref(),
        cfg.signature_public_key.as_ref(),
    ) {
        (None, None, None) | (Some(_), Some(_), Some(_)) => {}
        _ => bail!(
            "model_signature_path, tokenizer_signature_path, and signature_public_key \
             must be configured together"
        ),
    }

    LocalArtifactVerification::new(model_sha256, tokenizer_sha256)
        .context("inprocess detector artifact pins")
}

impl Detector for InprocessDetector {
    fn detect(&self, prompt: &str) -> DetectionResult {
        match self.classifier.classify(prompt) {
            Ok(output) => {
                let score = output.score as f64;
                let is_injection_label = output.label.eq_ignore_ascii_case(&self.injection_label);
                // A non-injection top label is read as confidence the prompt
                // is benign, so invert it (mirrors the sidecar detector).
                let (score_for_policy, label) = if is_injection_label {
                    (score, classify_score(score, self.threshold))
                } else {
                    (1.0 - score, classify_score(1.0 - score, self.threshold))
                };
                DetectionResult {
                    score: score_for_policy,
                    label,
                    reason: Some(format!(
                        "inprocess label={} score={:.3}",
                        output.label, output.score
                    )),
                }
            }
            Err(e) => {
                // Inference failure fails open (clean) so a model hiccup never
                // wedges the request path; operators who want fail-closed use
                // the sidecar detector's policy.
                tracing::warn!(error = %e, "inprocess prompt-injection inference failed; failing open");
                DetectionResult::clean()
            }
        }
    }

    fn name(&self) -> &str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_requires_model_and_tokenizer_paths() {
        // Missing both paths: a config error, not a panic.
        let err = match InprocessDetector::from_config(&serde_json::json!({})) {
            Ok(_) => panic!("config without paths must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("inprocess detector config"));
    }

    #[test]
    fn from_config_missing_model_file_errors() {
        let err = match InprocessDetector::from_config(&serde_json::json!({
            "model_path": "/nonexistent/model.onnx",
            "tokenizer_path": "/nonexistent/tokenizer.json",
            "model_sha256":
                "0000000000000000000000000000000000000000000000000000000000000001",
            "tokenizer_sha256":
                "0000000000000000000000000000000000000000000000000000000000000002"
        })) {
            Ok(_) => panic!("nonexistent model must fail at load"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("stat local model artifact"));
    }

    #[test]
    fn classify_score_maps_to_the_v2_vocabulary() {
        // At or above threshold => injection.
        assert_eq!(classify_score(0.9, 0.5), DetectionLabel::Injection);
        assert_eq!(classify_score(0.5, 0.5), DetectionLabel::Injection);
        // In [0.3, threshold) => suspicious.
        assert_eq!(classify_score(0.49, 0.5), DetectionLabel::Suspicious);
        assert_eq!(classify_score(0.3, 0.5), DetectionLabel::Suspicious);
        // Below 0.3 => clean.
        assert_eq!(classify_score(0.29, 0.5), DetectionLabel::Clean);
        assert_eq!(classify_score(0.0, 0.5), DetectionLabel::Clean);
    }

    #[test]
    fn classify_score_threshold_is_inclusive_and_configurable() {
        // A higher threshold widens the suspicious band.
        assert_eq!(classify_score(0.85, 0.9), DetectionLabel::Suspicious);
        assert_eq!(classify_score(0.9, 0.9), DetectionLabel::Injection);
        // A low threshold collapses suspicious: 0.3 still suspicious, 0.31 injects.
        assert_eq!(classify_score(0.31, 0.31), DetectionLabel::Injection);
    }

    #[test]
    fn default_injection_label_and_threshold_are_stable() {
        assert_eq!(DEFAULT_INJECTION_LABEL, "INJECTION");
        assert_eq!(default_injection_label(), "INJECTION");
        assert_eq!(default_threshold(), 0.5);
    }

    #[test]
    fn from_config_rejects_paths_only_partially_given() {
        // model_path without tokenizer_path is a config error, not a panic.
        let err = InprocessDetector::from_config(&serde_json::json!({
            "model_path": "/some/model.onnx"
        }))
        .err()
        .expect("partial paths must fail");
        assert!(err.to_string().contains("inprocess detector config"));
    }

    #[test]
    fn conventional_cache_partial_pair_is_a_hard_error() {
        let cache = tempfile::tempdir().unwrap();
        let model_dir = cache.path().join(DEFAULT_MODEL_NAME);
        std::fs::create_dir(&model_dir).unwrap();
        std::fs::write(model_dir.join(DEFAULT_MODEL_FILENAME), b"model").unwrap();

        let error = match InprocessDetector::from_auto_config_at_cache_root(
            &serde_json::json!({}),
            cache.path(),
        ) {
            Ok(_) => panic!("partial conventional pair must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("present=true"));
        assert!(error.to_string().contains("present=false"));
    }

    #[test]
    fn signature_fields_are_all_or_nothing() {
        let cfg = parse_config(&serde_json::json!({
            "model_sha256":
                "0000000000000000000000000000000000000000000000000000000000000001",
            "tokenizer_sha256":
                "0000000000000000000000000000000000000000000000000000000000000002",
            "model_signature_path": "/tmp/model.sig"
        }))
        .unwrap();

        let error = verification_for(&cfg).unwrap_err();
        assert!(error.to_string().contains("must be configured together"));
    }
}
