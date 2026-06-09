// SPDX-License-Identifier: Apache-2.0
//! In-process ONNX detector for `prompt_injection_v2` (opt-in).
//!
//! Runs the tract ONNX classifier inside the proxy address space. WOR-612
//! removed the original in-process detector because an unsandboxed model
//! parse could OOM the proxy; this brings it back only behind an explicit
//! `detector: "inprocess"` opt-in plus a hard `max_model_bytes` size guard,
//! and the operator supplies the model + tokenizer paths. Operators who
//! want process isolation should still prefer `detector: "sidecar"`.

use std::path::Path;
use std::sync::Arc;

use sbproxy_classifiers::{LoadOptions, OnnxClassifier};
use serde::Deserialize;

use super::detector::{DetectionLabel, DetectionResult, Detector};

/// Config name selecting this detector (`detector: "inprocess"`).
pub const INPROCESS_DETECTOR_NAME: &str = "inprocess";

const DEFAULT_INJECTION_LABEL: &str = "INJECTION";
const DEFAULT_THRESHOLD: f64 = 0.5;

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
struct InprocessDetectorConfig {
    /// Path to the ONNX model file.
    model_path: String,
    /// Path to the tokenizer.json file.
    tokenizer_path: String,
    /// Optional class labels indexed by output class. When omitted, the
    /// model's argmax is reported as `class_<n>`.
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

impl InprocessDetector {
    /// Build from the policy's `detector_config` block. Loads the model at
    /// construction time (the slow path) so `detect` stays cheap; the
    /// size guard is enforced before the graph is parsed.
    pub fn from_config(value: &serde_json::Value) -> anyhow::Result<Arc<dyn Detector>> {
        let cfg: InprocessDetectorConfig = serde_json::from_value(value.clone())
            .map_err(|e| anyhow::anyhow!("inprocess detector config: {e}"))?;
        let mut options = LoadOptions::default();
        if let Some(bytes) = cfg.max_model_bytes {
            options = options.with_max_model_bytes(bytes);
        }
        let classifier = OnnxClassifier::load_with_options(
            Path::new(&cfg.model_path),
            Path::new(&cfg.tokenizer_path),
            cfg.labels,
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
            "tokenizer_path": "/nonexistent/tokenizer.json"
        })) {
            Ok(_) => panic!("nonexistent model must fail at load"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("inprocess detector"));
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
}
