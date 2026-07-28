//! `prompt_injection_v2` policy: scoring detector + configurable action.
//!
//! Successor to the v1 `prompt_injection` heuristic guardrail. The v2
//! policy splits *detection* from *enforcement*: a swappable detector
//! returns a score in `[0.0, 1.0]` plus a categorical label, and the
//! policy maps the score onto an action (`tag`, `block`, `log`).
//!
//! The OSS build ships heuristic, in-process ONNX, and sidecar
//! detectors. When `detector` is omitted, a complete verified local
//! artifact pair selects in-process inference; an entirely absent pair
//! selects the heuristic. Explicit detector names always win. The
//! inventory registry exposed by [`Detector`] and the
//! `register_prompt_injection_detector!` macro remains the extension
//! point for custom detectors.

mod body_aware;
mod detector;
mod heuristic;
mod inprocess;
mod sidecar;

pub use body_aware::{
    classification_cache_stats, evaluate_body, evaluate_body_with_audit,
    reset_classification_cache, BodyAwareAuditContext, BodyAwareConfig, BodyAwareOutcome,
    ClassificationCacheStats,
};
pub use detector::{
    lookup_detector, registered_detector_names, DetectionLabel, DetectionResult, Detector,
    DetectorFactory,
};
pub use heuristic::{HeuristicDetector, HEURISTIC_DETECTOR_NAME};
pub use inprocess::{InprocessDetector, INPROCESS_DETECTOR_NAME};
pub use sidecar::{SidecarDetector, SIDECAR_DETECTOR_NAME};

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::Deserialize;

/// What the policy does when the detector flags a prompt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptInjectionAction {
    /// Forward the request, but stamp the score / label headers on the
    /// upstream so the application can react. Default; the safest
    /// rollout for a probabilistic detector.
    #[default]
    Tag,
    /// Reject the request with `403 Forbidden`. Opt in once
    /// false-positive rates have been measured against real traffic.
    Block,
    /// Forward the request unchanged but emit a structured warn log
    /// describing the hit. Useful for offline analysis before flipping
    /// to `tag` or `block`.
    Log,
}

impl PromptInjectionAction {
    /// Stable string used in metrics and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::Block => "block",
            Self::Log => "log",
        }
    }
}

/// Outcome of running the policy against a single prompt.
#[derive(Clone, Debug)]
pub enum PromptInjectionV2Outcome {
    /// Score below threshold; nothing to do.
    Clean,
    /// Score at or above threshold. Carries the headers the policy
    /// wants stamped on the upstream when `action: tag`, or the body
    /// to return when `action: block`.
    Hit {
        /// Detection result that triggered the hit.
        result: DetectionResult,
    },
}

/// Heuristic detector used when auto-selection finds no local artifacts.
pub const DEFAULT_DETECTOR: &str = HEURISTIC_DETECTOR_NAME;

/// Default score threshold above which the policy fires.
pub const DEFAULT_THRESHOLD: f64 = 0.5;

/// Default header name carrying the numeric score.
pub const DEFAULT_SCORE_HEADER: &str = "x-prompt-injection-score";

/// Default header name carrying the categorical label.
pub const DEFAULT_LABEL_HEADER: &str = "x-prompt-injection-label";

/// Default response body when `action: block` fires.
pub const DEFAULT_BLOCK_BODY: &str = "prompt injection detected";

/// Raw, deserializable shape of the policy config. Exists so we can
/// keep [`PromptInjectionV2Policy`] non-`Deserialize` and inject the
/// resolved `Arc<dyn Detector>` at compile time.
#[derive(Debug, Deserialize)]
struct RawConfig {
    /// Name of the detector to use (must be registered via the
    /// inventory registry). Omission enables verified local
    /// auto-selection.
    #[serde(default)]
    detector: Option<String>,
    /// Score threshold; the policy fires when `score >= threshold`.
    /// Defaults to `0.5`.
    #[serde(default = "default_threshold")]
    threshold: f64,
    /// Action on a hit. Defaults to `tag`.
    #[serde(default)]
    action: PromptInjectionAction,
    /// Header that carries the numeric score when `action: tag`.
    /// Defaults to `x-prompt-injection-score`.
    #[serde(default = "default_score_header")]
    score_header: String,
    /// Header that carries the categorical label when `action: tag`.
    /// Defaults to `x-prompt-injection-label`.
    #[serde(default = "default_label_header")]
    label_header: String,
    /// Body returned on `action: block`. Defaults to a generic
    /// message; operators typically override with their own JSON.
    #[serde(default = "default_block_body")]
    block_body: String,
    /// Content-Type for the block body. Defaults to `text/plain`.
    #[serde(default = "default_block_content_type")]
    block_content_type: String,
    /// Detector-specific config block. Forwarded verbatim to the
    /// detector when its constructor needs configuration (e.g. the
    /// ONNX detector's model URLs). Detectors that take no config
    /// ignore it.
    #[serde(default)]
    detector_config: serde_json::Value,
    /// Run the body-aware scan inside the AI proxy hot path.
    /// Defaults to `false`: the OSS scaffold remains URI + header
    /// scanning at request-filter time. When set to `true` and the
    /// origin is wired through `ai_proxy`, the proxy additionally
    /// runs the detector against the parsed prompt body before the
    /// upstream provider call. Operators flip this on once they have
    /// measured false-positive rates against their traffic.
    #[serde(default)]
    enable_body_aware: bool,
}

fn default_threshold() -> f64 {
    DEFAULT_THRESHOLD
}
fn default_score_header() -> String {
    DEFAULT_SCORE_HEADER.to_string()
}
fn default_label_header() -> String {
    DEFAULT_LABEL_HEADER.to_string()
}
fn default_block_body() -> String {
    DEFAULT_BLOCK_BODY.to_string()
}
fn default_block_content_type() -> String {
    "text/plain".to_string()
}

/// `prompt_injection_v2` policy.
///
/// Holds a resolved detector and the operator-configured thresholds /
/// action. Construct via [`PromptInjectionV2Policy::from_config`];
/// the policy is `Send + Sync` and shared across worker threads.
pub struct PromptInjectionV2Policy {
    detector: Arc<dyn Detector>,
    detector_name: String,
    threshold: f64,
    action: PromptInjectionAction,
    score_header: String,
    label_header: String,
    block_body: String,
    block_content_type: String,
    enable_body_aware: bool,
}

impl std::fmt::Debug for PromptInjectionV2Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptInjectionV2Policy")
            .field("detector", &self.detector_name)
            .field("threshold", &self.threshold)
            .field("action", &self.action)
            .field("score_header", &self.score_header)
            .field("label_header", &self.label_header)
            .finish()
    }
}

impl PromptInjectionV2Policy {
    /// Build a policy from a JSON config value.
    ///
    /// Unknown detector names are a hard error so misconfigured
    /// configs surface at startup rather than the first request. The
    /// fallback detector is always available because the OSS build
    /// registers `heuristic-v1`. Omission attempts verified local
    /// in-process selection before using that fallback.
    pub fn from_config(value: serde_json::Value) -> Result<Self> {
        let raw: RawConfig = serde_json::from_value(value)
            .map_err(|e| anyhow!("prompt_injection_v2 config: {e}"))?;
        Self::from_raw_with_auto_loader(raw, inprocess::InprocessDetector::from_auto_config)
    }

    fn from_raw_with_auto_loader<F>(raw: RawConfig, auto_loader: F) -> Result<Self>
    where
        F: FnOnce(&serde_json::Value) -> Result<inprocess::AutoInprocessSelection>,
    {
        if !(0.0..=1.0).contains(&raw.threshold) {
            return Err(anyhow!(
                "prompt_injection_v2 threshold must be in [0.0, 1.0], got {}",
                raw.threshold
            ));
        }
        let (detector, detector_name) = if let Some(name) = raw.detector.as_deref() {
            (
                resolve_explicit_detector(name, &raw.detector_config)?,
                name.to_string(),
            )
        } else {
            match auto_loader(&raw.detector_config)? {
                inprocess::AutoInprocessSelection::Loaded(detector) => {
                    (detector, INPROCESS_DETECTOR_NAME.to_string())
                }
                inprocess::AutoInprocessSelection::Absent {
                    model_path,
                    tokenizer_path,
                } => {
                    tracing::info!(
                        target: "sbproxy::prompt_injection_v2",
                        detector = HEURISTIC_DETECTOR_NAME,
                        model_path = %model_path.display(),
                        tokenizer_path = %tokenizer_path.display(),
                        "verified in-process artifacts are absent; using heuristic detector",
                    );
                    (
                        lookup_detector(HEURISTIC_DETECTOR_NAME)
                            .expect("the built-in heuristic detector is registered"),
                        HEURISTIC_DETECTOR_NAME.to_string(),
                    )
                }
            }
        };
        Ok(Self {
            detector,
            detector_name,
            threshold: raw.threshold,
            action: raw.action,
            score_header: raw.score_header,
            label_header: raw.label_header,
            block_body: raw.block_body,
            block_content_type: raw.block_content_type,
            enable_body_aware: raw.enable_body_aware,
        })
    }

    /// Build a policy directly from an arbitrary detector. Used by
    /// tests and by future call sites that want to inject a custom
    /// detector without going through the inventory registry.
    pub fn with_detector(detector: Arc<dyn Detector>) -> Self {
        let name = detector.name().to_string();
        Self {
            detector,
            detector_name: name,
            threshold: DEFAULT_THRESHOLD,
            action: PromptInjectionAction::Tag,
            score_header: DEFAULT_SCORE_HEADER.to_string(),
            label_header: DEFAULT_LABEL_HEADER.to_string(),
            block_body: DEFAULT_BLOCK_BODY.to_string(),
            block_content_type: "text/plain".to_string(),
            enable_body_aware: false,
        }
    }

    /// Override the configured action. Used by tests.
    pub fn with_action(mut self, action: PromptInjectionAction) -> Self {
        self.action = action;
        self
    }

    /// Override the score threshold. Used by tests.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Configured action.
    pub fn action(&self) -> PromptInjectionAction {
        self.action
    }

    /// Score threshold. The policy fires when `score >= threshold`.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Header used for the numeric score on `action: tag`.
    pub fn score_header(&self) -> &str {
        &self.score_header
    }

    /// Header used for the categorical label on `action: tag`.
    pub fn label_header(&self) -> &str {
        &self.label_header
    }

    /// Body returned for `action: block`.
    pub fn block_body(&self) -> &str {
        &self.block_body
    }

    /// Content-Type for the block body.
    pub fn block_content_type(&self) -> &str {
        &self.block_content_type
    }

    /// Detector name reported in logs.
    pub fn detector_name(&self) -> &str {
        &self.detector_name
    }

    /// Whether the body-aware scan should run inside `ai_proxy`.
    ///
    /// Defaults to `false`. The AI handler reads this and skips the
    /// extra extraction + classification pipeline when unset, which
    /// keeps the new path opt-in until operators have measured the
    /// detector's false-positive rate against their own traffic.
    pub fn body_aware_enabled(&self) -> bool {
        self.enable_body_aware
    }

    /// Override the body-aware flag. Used by tests and by the AI
    /// handler integration shim that wants to force-enable the path
    /// during integration tests.
    pub fn with_body_aware(mut self, enable: bool) -> Self {
        self.enable_body_aware = enable;
        self
    }

    /// Run the detector on `prompt` and decide what to do.
    ///
    /// The policy itself does not stamp headers or write logs; that is
    /// the caller's job (the dispatcher in `sbproxy-core`). Splitting
    /// detection from side-effects keeps this module trivially
    /// testable.
    pub fn evaluate(&self, prompt: &str) -> PromptInjectionV2Outcome {
        let result = self.detector.detect(prompt);
        if result.score >= self.threshold && result.label != DetectionLabel::Clean {
            PromptInjectionV2Outcome::Hit { result }
        } else {
            PromptInjectionV2Outcome::Clean
        }
    }
}

fn resolve_explicit_detector(
    name: &str,
    detector_config: &serde_json::Value,
) -> Result<Arc<dyn Detector>> {
    // The sidecar and in-process detectors need configuration, so they go
    // through their constructors. Everything else uses the zero-argument
    // inventory factory. An explicit name never invokes auto-selection.
    if name == "onnx" {
        return Err(anyhow!(
            "prompt_injection_v2 detector \"onnx\" was removed; use detector: \
             \"inprocess\" or detector: \"sidecar\" (see docs/prompt-injection-v2.md)"
        ));
    }
    if name == sidecar::SIDECAR_DETECTOR_NAME {
        return sidecar::SidecarDetector::from_config(detector_config);
    }
    if name == inprocess::INPROCESS_DETECTOR_NAME {
        return inprocess::InprocessDetector::from_config(detector_config);
    }
    lookup_detector(name).ok_or_else(|| {
        anyhow!(
            "prompt_injection_v2 detector {:?} not registered; available: {}",
            name,
            registered_detector_names().join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture detector returning a fixed score / label.
    struct StubDetector {
        score: f64,
        label: DetectionLabel,
        reason: Option<&'static str>,
    }

    impl Detector for StubDetector {
        fn detect(&self, _prompt: &str) -> DetectionResult {
            DetectionResult {
                score: self.score,
                label: self.label,
                reason: self.reason.map(|s| s.to_string()),
            }
        }
        fn name(&self) -> &str {
            "stub"
        }
    }

    fn stub(score: f64, label: DetectionLabel) -> Arc<dyn Detector> {
        Arc::new(StubDetector {
            score,
            label,
            reason: Some("stub reason"),
        })
    }

    #[test]
    fn from_config_resolves_default_detector() {
        let dir = tempfile::tempdir().unwrap();
        let p = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector_config": {
                "model_path": dir.path().join("missing-model.onnx"),
                "tokenizer_path": dir.path().join("missing-tokenizer.json"),
            }
        }))
        .unwrap();
        assert_eq!(p.detector_name(), HEURISTIC_DETECTOR_NAME);
        assert_eq!(p.action(), PromptInjectionAction::Tag);
        assert_eq!(p.threshold(), DEFAULT_THRESHOLD);
    }

    #[test]
    fn omitted_detector_rejects_a_partial_artifact_pair() {
        let err = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector_config": {
                "model_path": "/tmp/only-model.onnx",
            }
        }))
        .expect_err("partial auto-selection must not silently choose the heuristic");

        assert!(err.to_string().contains("model_path"));
        assert!(err.to_string().contains("tokenizer_path"));
    }

    #[test]
    fn omitted_detector_does_not_downgrade_a_tampered_pair() {
        let dir = tempfile::tempdir().unwrap();
        let model = dir.path().join("model.onnx");
        let tokenizer = dir.path().join("tokenizer.json");
        std::fs::write(&model, b"tampered model").unwrap();
        std::fs::write(&tokenizer, b"tampered tokenizer").unwrap();

        let err = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector_config": {
                "model_path": model,
                "tokenizer_path": tokenizer,
                "model_sha256":
                    "0000000000000000000000000000000000000000000000000000000000000001",
                "tokenizer_sha256":
                    "0000000000000000000000000000000000000000000000000000000000000002",
            }
        }))
        .expect_err("a present unverified pair must fail instead of downgrading");

        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn explicit_heuristic_ignores_artifact_configuration() {
        let policy = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector": "heuristic-v1",
            "detector_config": {
                "model_path": "/tmp/only-model.onnx",
                "model_sha256": "not-a-digest",
            }
        }))
        .expect("an explicit heuristic selection must win");

        assert_eq!(policy.detector_name(), HEURISTIC_DETECTOR_NAME);
    }

    #[test]
    fn omitted_detector_reports_inprocess_when_verified_loader_succeeds() {
        let raw: RawConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        let policy = PromptInjectionV2Policy::from_raw_with_auto_loader(raw, |_| {
            Ok(inprocess::AutoInprocessSelection::Loaded(stub(
                0.1,
                DetectionLabel::Clean,
            )))
        })
        .unwrap();

        assert_eq!(policy.detector_name(), INPROCESS_DETECTOR_NAME);
    }

    #[test]
    fn omitted_detector_with_verified_files_uses_the_real_inprocess_loader() {
        use prost11::Message as _;
        use sha2::Digest as _;

        let dir = tempfile::tempdir().unwrap();
        let model_path = dir.path().join("model.onnx");
        let tokenizer_path = dir.path().join("tokenizer.json");
        let model = tract_onnx::pb::ModelProto {
            ir_version: 8,
            producer_name: "sbproxy-test".to_string(),
            opset_import: vec![tract_onnx::pb::OperatorSetIdProto {
                domain: String::new(),
                version: 13,
            }],
            graph: Some(tract_onnx::pb::GraphProto {
                name: "constant-classifier".to_string(),
                initializer: vec![tract_onnx::pb::TensorProto {
                    dims: vec![1, 2],
                    data_type: tract_onnx::pb::tensor_proto::DataType::Float as i32,
                    float_data: vec![0.9, 0.1],
                    name: "logits".to_string(),
                    ..Default::default()
                }],
                output: vec![tract_onnx::pb::ValueInfoProto {
                    name: "logits".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut model_bytes = Vec::new();
        model.encode(&mut model_bytes).unwrap();
        std::fs::write(&model_path, &model_bytes).unwrap();
        let tokenizer_bytes = br#"{
          "version":"1.0",
          "truncation":null,
          "padding":null,
          "added_tokens":[],
          "normalizer":null,
          "pre_tokenizer":{"type":"Whitespace"},
          "post_processor":null,
          "decoder":null,
          "model":{"type":"WordLevel","vocab":{"[UNK]":0,"hello":1},"unk_token":"[UNK]"}
        }"#;
        std::fs::write(&tokenizer_path, tokenizer_bytes).unwrap();
        let model_sha256 = hex::encode(sha2::Sha256::digest(&model_bytes));
        let tokenizer_sha256 = hex::encode(sha2::Sha256::digest(tokenizer_bytes));

        let policy = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector_config": {
                "model_path": model_path,
                "tokenizer_path": tokenizer_path,
                "model_sha256": model_sha256,
                "tokenizer_sha256": tokenizer_sha256,
            }
        }))
        .unwrap();

        assert_eq!(policy.detector_name(), INPROCESS_DETECTOR_NAME);
    }

    #[test]
    fn absent_auto_artifacts_log_once_and_select_the_heuristic() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Metadata, Subscriber};

        #[derive(Clone)]
        struct TargetCounter(Arc<AtomicUsize>);

        impl Subscriber for TargetCounter {
            fn enabled(&self, metadata: &Metadata<'_>) -> bool {
                metadata.target() == "sbproxy::prompt_injection_v2"
            }

            fn new_span(&self, _span: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &Record<'_>) {}

            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

            fn event(&self, event: &Event<'_>) {
                if event.metadata().target() == "sbproxy::prompt_injection_v2" {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }

            fn enter(&self, _span: &Id) {}

            fn exit(&self, _span: &Id) {}
        }

        let dir = tempfile::tempdir().unwrap();
        let model_path = dir.path().join("missing-model.onnx");
        let tokenizer_path = dir.path().join("missing-tokenizer.json");
        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = TargetCounter(Arc::clone(&events));
        let policy = tracing::subscriber::with_default(subscriber, || {
            PromptInjectionV2Policy::from_config(serde_json::json!({
                "detector_config": {
                    "model_path": model_path,
                    "tokenizer_path": tokenizer_path,
                }
            }))
            .unwrap()
        });

        assert_eq!(policy.detector_name(), HEURISTIC_DETECTOR_NAME);
        assert_eq!(events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn from_config_rejects_unknown_detector() {
        let err = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector": "does-not-exist",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("does-not-exist"));
    }

    #[test]
    fn from_config_rejects_out_of_range_threshold() {
        let err = PromptInjectionV2Policy::from_config(serde_json::json!({
            "threshold": 2.5,
        }))
        .unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn evaluate_below_threshold_is_clean() {
        let p = PromptInjectionV2Policy::with_detector(stub(0.3, DetectionLabel::Suspicious))
            .with_threshold(0.5);
        match p.evaluate("anything") {
            PromptInjectionV2Outcome::Clean => {}
            other => panic!("expected clean, got {:?}", other),
        }
    }

    #[test]
    fn evaluate_at_or_above_threshold_is_hit() {
        let p = PromptInjectionV2Policy::with_detector(stub(0.7, DetectionLabel::Injection))
            .with_threshold(0.5);
        match p.evaluate("anything") {
            PromptInjectionV2Outcome::Hit { result } => {
                assert_eq!(result.label, DetectionLabel::Injection);
                assert!(result.score >= 0.5);
            }
            other => panic!("expected hit, got {:?}", other),
        }
    }

    #[test]
    fn clean_label_never_fires_even_at_threshold() {
        // Defensive: a detector that returns a high score with the
        // `Clean` label should not trigger the policy. Catches bugs in
        // future detectors that misuse the score channel.
        let p = PromptInjectionV2Policy::with_detector(stub(0.99, DetectionLabel::Clean));
        match p.evaluate("anything") {
            PromptInjectionV2Outcome::Clean => {}
            other => panic!("expected clean, got {:?}", other),
        }
    }

    #[test]
    fn block_action_round_trips() {
        let p = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector": "heuristic-v1",
            "action": "block",
        }))
        .unwrap();
        assert_eq!(p.action(), PromptInjectionAction::Block);
    }

    #[test]
    fn log_action_round_trips() {
        let p = PromptInjectionV2Policy::from_config(serde_json::json!({
            "detector": "heuristic-v1",
            "action": "log",
        }))
        .unwrap();
        assert_eq!(p.action(), PromptInjectionAction::Log);
    }

    #[test]
    fn registered_detectors_includes_heuristic() {
        let names = registered_detector_names();
        assert!(names.contains(&HEURISTIC_DETECTOR_NAME));
    }
}
