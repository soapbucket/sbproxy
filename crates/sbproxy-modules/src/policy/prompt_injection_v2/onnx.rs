//! ONNX-based prompt-injection detector.
//!
//! Wraps an [`sbproxy_classifiers::OnnxClassifier`] in the
//! [`Detector`] trait so the `prompt_injection_v2` policy can use a
//! real classification model when one is configured.
//!
//! # Configuration
//!
//! The detector is selected with `detector: "onnx"` in the policy
//! config. The supported keys are:
//!
//! ```yaml
//! - type: prompt_injection_v2
//!   detector: onnx
//!   detector_config:
//!     model_url: https://example.com/model.onnx
//!     tokenizer_url: https://example.com/tokenizer.json
//!     model_sha256: <hex>           # optional, recommended
//!     tokenizer_sha256: <hex>       # optional, recommended
//!     cache_dir: /var/cache/sbproxy # optional, default cache dir
//!     threshold: 0.5                # optional, default 0.5
//!     labels: [benign, injection]   # optional
//!     injection_label: injection    # optional, default "injection"
//! ```
//!
//! # Offline fallback
//!
//! If model loading fails for any reason (network down, sha256
//! mismatch, malformed model), [`OnnxDetector::from_config`] logs a
//! `tracing::warn!` and returns the heuristic detector instead. This
//! keeps the policy functional offline; operators who need a hard
//! failure on missing models should health-check the configured URL
//! out of band.
//!
//! # Inventory wiring
//!
//! Unlike the heuristic detector this entry does not register a
//! zero-arg factory because the ONNX detector requires
//! configuration. Instead, the policy builder calls
//! [`OnnxDetector::from_config`] directly when it sees
//! `detector: "onnx"`. The constructor name is registered in the
//! inventory so config validation can list it as a valid option.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use super::detector::{DetectionLabel, DetectionResult, Detector};
use super::heuristic::HeuristicDetector;

/// Stable name reported by [`OnnxDetector::name`].
pub const ONNX_DETECTOR_NAME: &str = "onnx";

/// Detector backed by [`sbproxy_classifiers::OnnxClassifier`].
pub struct OnnxDetector {
    inner: Arc<sbproxy_classifiers::OnnxClassifier>,
    threshold: f64,
    /// Output label that, when chosen by the model, means
    /// "this prompt is an injection". Configurable so models with
    /// different label vocabularies still work (e.g. "INJECTION",
    /// "JAILBREAK", "1").
    injection_label: String,
    /// Stable detector name. Always [`ONNX_DETECTOR_NAME`].
    name: &'static str,
}

#[derive(Debug, Deserialize)]
struct OnnxDetectorConfig {
    /// Optional reference to an entry in the
    /// [`sbproxy_classifiers::known_models`] registry. When set, the
    /// `model_url`, `tokenizer_url`, and SHA-256 pins all default to
    /// the registry entry. Explicit fields still win so operators
    /// running a private mirror can override the URLs without dropping
    /// the convenience of the named pin.
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    model_url: Option<String>,
    #[serde(default)]
    tokenizer_url: Option<String>,
    #[serde(default)]
    model_sha256: Option<String>,
    #[serde(default)]
    tokenizer_sha256: Option<String>,
    #[serde(default)]
    cache_dir: Option<PathBuf>,
    #[serde(default = "default_threshold")]
    threshold: f64,
    /// Optional label vocabulary indexed by the model's softmax output.
    #[serde(default)]
    labels: Option<Vec<String>>,
    #[serde(default = "default_injection_label")]
    injection_label: String,
}

fn default_threshold() -> f64 {
    0.5
}

fn default_injection_label() -> String {
    "injection".to_string()
}

impl OnnxDetector {
    /// Build an ONNX detector from a JSON config.
    ///
    /// On any load error, this logs a warning and returns the
    /// heuristic detector instead. The returned `Arc<dyn Detector>`
    /// is therefore guaranteed to be usable; callers do not need to
    /// re-wrap with their own fallback.
    pub fn from_config(value: &serde_json::Value) -> Arc<dyn Detector> {
        match Self::try_from_config(value) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to load ONNX prompt-injection detector; falling back to heuristic",
                );
                Arc::new(HeuristicDetector::new())
            }
        }
    }

    /// Build an ONNX detector from a JSON config without falling back.
    ///
    /// Useful for tests that need to assert the failure mode. Most
    /// production callers should use [`OnnxDetector::from_config`].
    pub fn try_from_config(value: &serde_json::Value) -> Result<Arc<dyn Detector>> {
        let cfg: OnnxDetectorConfig =
            serde_json::from_value(value.clone()).context("parsing onnx detector config")?;
        if !(0.0..=1.0).contains(&cfg.threshold) {
            return Err(anyhow!(
                "onnx detector threshold must be in [0.0, 1.0], got {}",
                cfg.threshold
            ));
        }

        // Resolve URL + SHA pins. Explicit fields beat the registry
        // entry; the registry only fills in what the operator left
        // blank. This is the design contract: operators with a
        // private mirror set `model_url` / `tokenizer_url` and keep
        // `model:` so they still get the SHA pins, or vice versa.
        let known = match cfg.model.as_deref() {
            Some(name) => Some(
                sbproxy_classifiers::lookup_known_model(name).ok_or_else(|| {
                    anyhow!(
                        "onnx detector: unknown model {:?}; registered names: {}",
                        name,
                        sbproxy_classifiers::known_models::registered_names().join(", ")
                    )
                })?,
            ),
            None => None,
        };
        let model_url = cfg
            .model_url
            .clone()
            .or_else(|| known.map(|k| k.model_url.to_string()))
            .ok_or_else(|| {
                anyhow!(
                    "onnx detector: must set either `model: <name>` or explicit `model_url` / `tokenizer_url`"
                )
            })?;
        let tokenizer_url = cfg
            .tokenizer_url
            .clone()
            .or_else(|| known.map(|k| k.tokenizer_url.to_string()))
            .ok_or_else(|| {
                anyhow!(
                    "onnx detector: must set either `model: <name>` or explicit `model_url` / `tokenizer_url`"
                )
            })?;

        let cache_dir = cfg
            .cache_dir
            .clone()
            .unwrap_or_else(sbproxy_classifiers::default_model_cache_dir);

        // Effective SHA pins: explicit > registry > none. The (Some,
        // None) / (None, Some) mixed case still rejects so a half-
        // configured pin can never sneak in.
        let registry_pair = known.and_then(|k| k.pinned_pair());
        let model_sha_str = cfg
            .model_sha256
            .clone()
            .or_else(|| registry_pair.map(|(m, _)| m.to_string()));
        let tokenizer_sha_str = cfg
            .tokenizer_sha256
            .clone()
            .or_else(|| registry_pair.map(|(_, t)| t.to_string()));
        let pinned = match (model_sha_str.as_deref(), tokenizer_sha_str.as_deref()) {
            (Some(m), Some(t)) => Some((m, t)),
            (Some(_), None) | (None, Some(_)) => {
                return Err(anyhow!(
                    "onnx detector: either both or neither of model_sha256 / tokenizer_sha256 must be set"
                ));
            }
            (None, None) => None,
        };

        let classifier = sbproxy_classifiers::OnnxClassifier::download_and_load(
            &model_url,
            &tokenizer_url,
            pinned,
            &cache_dir,
        )?;
        // Re-load with labels if the user provided a vocabulary.
        let classifier = if let Some(labels) = cfg.labels {
            let model_path = cache_dir.join(format!("model-{}.onnx", short_url_hash(&model_url)));
            let tokenizer_path =
                cache_dir.join(format!("tokenizer-{}.json", short_url_hash(&tokenizer_url)));
            // The previous call cached files under the same names;
            // load_with_labels just attaches the vocabulary.
            sbproxy_classifiers::OnnxClassifier::load_with_labels(
                &model_path,
                &tokenizer_path,
                Some(labels),
            )
            .unwrap_or(classifier)
        } else {
            classifier
        };

        Ok(Arc::new(Self {
            inner: Arc::new(classifier),
            threshold: cfg.threshold,
            injection_label: cfg.injection_label,
            name: ONNX_DETECTOR_NAME,
        }))
    }

    /// Build an `OnnxDetector` directly from a constructed classifier.
    /// Used by tests that want to skip the network-tied config path.
    pub fn from_classifier(
        classifier: Arc<sbproxy_classifiers::OnnxClassifier>,
        threshold: f64,
        injection_label: impl Into<String>,
    ) -> Self {
        Self {
            inner: classifier,
            threshold,
            injection_label: injection_label.into(),
            name: ONNX_DETECTOR_NAME,
        }
    }
}

fn short_url_hash(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(url.as_bytes());
    let full = hex::encode(h.finalize());
    full[..16].to_string()
}

impl Detector for OnnxDetector {
    fn detect(&self, prompt: &str) -> DetectionResult {
        match self.inner.classify(prompt) {
            Ok(out) => {
                let score = out.score as f64;
                let is_injection_label = out.label.eq_ignore_ascii_case(&self.injection_label);
                // Map score + label onto the v2 vocabulary.
                let (score_for_policy, label) = if is_injection_label {
                    (score, classify_score(score, self.threshold))
                } else {
                    // The model is confident this is *not* an injection;
                    // surface a low score regardless of internal
                    // confidence so the policy stays clean.
                    (1.0 - score, classify_score(1.0 - score, self.threshold))
                };
                DetectionResult {
                    score: score_for_policy,
                    label,
                    reason: Some(format!("onnx model={} score={:.3}", out.label, out.score)),
                }
            }
            Err(e) => {
                // Per-request inference errors should never break the
                // request; degrade to clean and log.
                tracing::warn!(error = %e, "onnx classifier inference failed; returning clean");
                DetectionResult::clean()
            }
        }
    }

    fn name(&self) -> &str {
        self.name
    }
}

fn classify_score(score: f64, threshold: f64) -> DetectionLabel {
    if score >= threshold {
        DetectionLabel::Injection
    } else if score >= 0.3 {
        DetectionLabel::Suspicious
    } else {
        DetectionLabel::Clean
    }
}

/// Inventory factory for the ONNX detector.
///
/// Without configuration the ONNX detector cannot construct itself,
/// so the registered factory falls back to the heuristic detector.
/// Operators who reference `detector: "onnx"` in their policy go
/// through `crate::policy::prompt_injection_v2::lookup_detector_with_config`
/// instead, which honours the `detector_config` block.
fn onnx_factory_fallback() -> Arc<dyn Detector> {
    tracing::warn!("onnx detector requested without detector_config; using heuristic fallback",);
    Arc::new(HeuristicDetector::new())
}

crate::register_prompt_injection_detector!(ONNX_DETECTOR_NAME, onnx_factory_fallback);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_falls_back_when_urls_unreachable() {
        let cfg = serde_json::json!({
            "model_url": "https://127.0.0.1:1/no-such-model.onnx",
            "tokenizer_url": "https://127.0.0.1:1/no-such-tokenizer.json",
        });
        let d = OnnxDetector::from_config(&cfg);
        // The heuristic fallback reports its own name, not the ONNX
        // one. That's the contract: callers get *something* that
        // implements Detector even when the model fails to load.
        assert_eq!(d.name(), super::super::heuristic::HEURISTIC_DETECTOR_NAME);
    }

    #[test]
    fn try_from_config_rejects_partial_sha_pinning() {
        let cfg = serde_json::json!({
            "model_url": "https://example.com/m.onnx",
            "tokenizer_url": "https://example.com/t.json",
            "model_sha256": "deadbeef",
            // tokenizer_sha256 omitted on purpose.
        });
        let err = match OnnxDetector::try_from_config(&cfg) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("model_sha256"));
    }

    #[test]
    fn try_from_config_rejects_out_of_range_threshold() {
        let cfg = serde_json::json!({
            "model_url": "https://example.com/m.onnx",
            "tokenizer_url": "https://example.com/t.json",
            "threshold": 2.0,
        });
        let err = match OnnxDetector::try_from_config(&cfg) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn classify_score_thresholds() {
        assert_eq!(classify_score(0.9, 0.5), DetectionLabel::Injection);
        assert_eq!(classify_score(0.5, 0.5), DetectionLabel::Injection);
        assert_eq!(classify_score(0.4, 0.5), DetectionLabel::Suspicious);
        assert_eq!(classify_score(0.1, 0.5), DetectionLabel::Clean);
    }

    #[test]
    fn registered_detector_includes_onnx() {
        let names = super::super::registered_detector_names();
        assert!(names.contains(&ONNX_DETECTOR_NAME));
    }
}
