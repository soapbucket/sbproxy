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
use std::time::Duration;

use anyhow::{bail, Context as _};
use sbproxy_classifiers::{
    default_model_cache_dir, lookup_known_model, parse_ed25519_pubkey, LoadOptions,
    LocalArtifactVerification, OnnxClassifier,
};
use serde::Deserialize;

use super::detector::{
    DetectionFailure, DetectionFailureKind, DetectionLabel, DetectionResult, Detector,
    DetectorCacheNamespace,
};

/// Config name selecting this detector (`detector: "inprocess"`).
pub const INPROCESS_DETECTOR_NAME: &str = "inprocess";

const DEFAULT_INJECTION_LABEL: &str = "INJECTION";
const DEFAULT_THRESHOLD: f64 = 0.5;
const DEFAULT_MODEL_NAME: &str = "prompt-injection-v2";
const DEFAULT_MODEL_FILENAME: &str = "model.onnx";
const DEFAULT_TOKENIZER_FILENAME: &str = "tokenizer.json";
const DEFAULT_MAX_CONCURRENT: usize = 2;
const DEFAULT_MAX_QUEUED: usize = 16;
const DEFAULT_INFERENCE_TIMEOUT_MS: u64 = 500;

/// Largest supported in-process inference concurrency.
pub const INPROCESS_MAX_CONCURRENT: usize = 64;
/// Largest supported in-process inference wait queue.
pub const INPROCESS_MAX_QUEUED: usize = 1_024;
/// Largest supported end-to-end in-process inference deadline.
pub const INPROCESS_MAX_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Maximum number of ONNX evaluations running for this detector.
    #[serde(default = "default_max_concurrent")]
    max_concurrent: usize,
    /// Maximum number of evaluations waiting for a running slot. Must be in
    /// `1..=1024`; once both the running and queued budgets are occupied,
    /// later work is refused immediately.
    #[serde(default = "default_max_queued")]
    max_queued: usize,
    /// End-to-end admission and evaluation deadline.
    #[serde(default = "default_inference_timeout_ms")]
    inference_timeout_ms: u64,
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
fn default_max_concurrent() -> usize {
    DEFAULT_MAX_CONCURRENT
}
fn default_max_queued() -> usize {
    DEFAULT_MAX_QUEUED
}
fn default_inference_timeout_ms() -> u64 {
    DEFAULT_INFERENCE_TIMEOUT_MS
}

struct InprocessAdmission {
    running: Arc<tokio::sync::Semaphore>,
    queued: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
}

impl InprocessAdmission {
    fn validate(max_concurrent: usize, max_queued: usize, timeout: Duration) -> anyhow::Result<()> {
        if !(1..=INPROCESS_MAX_CONCURRENT).contains(&max_concurrent) {
            bail!("inprocess detector max_concurrent must be in 1..={INPROCESS_MAX_CONCURRENT}");
        }
        if !(1..=INPROCESS_MAX_QUEUED).contains(&max_queued) {
            bail!("inprocess detector max_queued must be in 1..={INPROCESS_MAX_QUEUED}");
        }
        if timeout.is_zero() || timeout > INPROCESS_MAX_TIMEOUT {
            bail!("inprocess detector inference_timeout_ms must be in 1..=30000");
        }
        Ok(())
    }

    fn new(max_concurrent: usize, max_queued: usize, timeout: Duration) -> anyhow::Result<Self> {
        Self::validate(max_concurrent, max_queued, timeout)?;
        Ok(Self {
            running: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            queued: Arc::new(tokio::sync::Semaphore::new(max_queued)),
            timeout,
        })
    }

    async fn run<F, T>(&self, work: F) -> Result<T, DetectionFailure>
    where
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        tokio::time::timeout(self.timeout, async {
            let running = match Arc::clone(&self.running).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let queued = Arc::clone(&self.queued)
                        .try_acquire_owned()
                        .map_err(|_| DetectionFailure::direct(DetectionFailureKind::QueueFull))?;
                    let running = Arc::clone(&self.running)
                        .acquire_owned()
                        .await
                        .map_err(|_| DetectionFailure::direct(DetectionFailureKind::Worker))?;
                    drop(queued);
                    running
                }
            };
            let result = tokio::task::spawn_blocking(move || {
                let _running = running;
                work()
            })
            .await
            .map_err(|_| DetectionFailure::direct(DetectionFailureKind::Worker))?;
            result.map_err(|_| DetectionFailure::direct(DetectionFailureKind::Inference))
        })
        .await
        .map_err(|_| DetectionFailure::direct(DetectionFailureKind::Deadline))?
    }
}

/// Detector that runs ONNX classification in-process via tract.
pub struct InprocessDetector {
    classifier: Arc<OnnxClassifier>,
    admission: InprocessAdmission,
    injection_label: String,
    threshold: f64,
    name: &'static str,
    cache_namespace: DetectorCacheNamespace,
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
        InprocessAdmission::validate(
            cfg.max_concurrent,
            cfg.max_queued,
            Duration::from_millis(cfg.inference_timeout_ms),
        )?;
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
            .clone()
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
        let cache_namespace = cache_namespace_for(&cfg, &labels)?;
        let classifier = OnnxClassifier::load_verified_local_with_options(
            model_path,
            tokenizer_path,
            Some(labels),
            &verification,
            &options,
        )
        .map_err(|e| anyhow::anyhow!("inprocess detector: {e}"))?;
        let admission = InprocessAdmission::new(
            cfg.max_concurrent,
            cfg.max_queued,
            Duration::from_millis(cfg.inference_timeout_ms),
        )?;
        Ok(Arc::new(Self {
            classifier: Arc::new(classifier),
            admission,
            injection_label: cfg.injection_label,
            threshold: cfg.threshold,
            name: INPROCESS_DETECTOR_NAME,
            cache_namespace,
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
    let (model_sha256, tokenizer_sha256) = resolved_pins(cfg)?;

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

fn resolved_pins(cfg: &InprocessDetectorConfig) -> anyhow::Result<(&str, &str)> {
    let pins = match (&cfg.model_sha256, &cfg.tokenizer_sha256) {
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
    Ok(pins)
}

fn cache_namespace_for(
    cfg: &InprocessDetectorConfig,
    labels: &[String],
) -> anyhow::Result<DetectorCacheNamespace> {
    let (model_sha256, tokenizer_sha256) = resolved_pins(cfg)?;
    let model_sha256 = model_sha256.to_ascii_lowercase();
    let tokenizer_sha256 = tokenizer_sha256.to_ascii_lowercase();
    let injection_label = cfg.injection_label.to_ascii_lowercase();
    let threshold = cfg.threshold.to_bits().to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![
        INPROCESS_DETECTOR_NAME.as_bytes(),
        b"semantic-version-1",
        model_sha256.as_bytes(),
        tokenizer_sha256.as_bytes(),
        injection_label.as_bytes(),
        &threshold,
    ];
    for label in labels {
        parts.push(label.as_bytes());
    }
    Ok(DetectorCacheNamespace::derive(&parts))
}

impl Detector for InprocessDetector {
    fn detect(&self, prompt: &str) -> DetectionResult {
        self.try_detect(prompt)
            .unwrap_or_else(|failure| DetectionResult {
                // Legacy direct callers cannot carry the typed error. Preserve a
                // conservative non-clean result; production policy evaluation
                // calls `try_detect` and handles the exact failure explicitly.
                score: 1.0,
                label: DetectionLabel::Injection,
                reason: Some(failure.to_string()),
            })
    }

    fn try_detect(&self, prompt: &str) -> Result<DetectionResult, DetectionFailure> {
        let outcome = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                let classifier = Arc::clone(&self.classifier);
                let prompt = prompt.to_string();
                tokio::task::block_in_place(|| {
                    handle.block_on(self.admission.run(move || classifier.classify(&prompt)))
                })
            }
            _ => Err(DetectionFailure::direct(DetectionFailureKind::Runtime)),
        };
        match outcome {
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
                Ok(DetectionResult {
                    score: score_for_policy,
                    label,
                    reason: Some(format!(
                        "inprocess label={} score={:.3}",
                        output.label, output.score
                    )),
                })
            }
            Err(error) => Err(error),
        }
    }

    fn name(&self) -> &str {
        self.name
    }

    fn cache_namespace(&self) -> Option<DetectorCacheNamespace> {
        Some(self.cache_namespace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capacity or deadline accepted here reaches Tokio construction or
    /// request-time arithmetic before the surrounding policy can render a
    /// controlled refusal. Pin the public operational envelope at this
    /// boundary so even direct library construction cannot panic on values
    /// deserialized from operator config.
    #[test]
    fn admission_rejects_zero_and_values_above_operational_maxima_without_panicking() {
        for (running, queued, timeout) in [
            (0, 1, Duration::from_millis(1)),
            (1, 0, Duration::from_millis(1)),
            (65, 1, Duration::from_millis(1)),
            (1, 1_025, Duration::from_millis(1)),
            (1, 1, Duration::ZERO),
            (1, 1, Duration::from_millis(30_001)),
            (1, 1, Duration::from_millis(u64::MAX)),
        ] {
            assert!(
                InprocessAdmission::new(running, queued, timeout).is_err(),
                "running={running}, queued={queued}, timeout={timeout:?} must be rejected"
            );
        }

        for (running, queued) in [(usize::MAX, 1), (1, usize::MAX)] {
            let result = std::panic::catch_unwind(|| {
                InprocessAdmission::new(running, queued, Duration::from_millis(1))
            });
            assert!(
                result.is_ok(),
                "operator capacity running={running}, queued={queued} must return an error, not panic"
            );
            assert!(result.expect("constructor did not panic").is_err());
        }

        assert!(
            InprocessAdmission::new(
                INPROCESS_MAX_CONCURRENT,
                INPROCESS_MAX_QUEUED,
                INPROCESS_MAX_TIMEOUT,
            )
            .is_ok(),
            "the documented exact operational maxima must remain accepted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inference_admission_refuses_work_beyond_running_and_queue_budget() {
        let admission = Arc::new(InprocessAdmission::new(1, 1, Duration::from_secs(1)).unwrap());
        let first = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move {
                admission
                    .run(|| {
                        std::thread::sleep(Duration::from_millis(100));
                        Ok::<_, anyhow::Error>(())
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        let queued = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move { admission.run(|| Ok::<_, anyhow::Error>(())).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        let error = admission
            .run(|| Ok::<_, anyhow::Error>(()))
            .await
            .expect_err("work beyond the configured queue budget must be refused");
        assert_eq!(
            error.terminal().kind,
            DetectionFailureKind::QueueFull,
            "work beyond the configured queue budget must retain its typed reason"
        );
        first.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inference_admission_preserves_deadline_and_worker_failures() {
        let deadline = InprocessAdmission::new(1, 1, Duration::from_millis(10)).unwrap();
        let error = deadline
            .run(|| {
                std::thread::sleep(Duration::from_millis(50));
                Ok::<_, anyhow::Error>(())
            })
            .await
            .expect_err("slow work must reach the bounded deadline");
        assert_eq!(error.terminal().kind, DetectionFailureKind::Deadline);

        let worker = InprocessAdmission::new(1, 1, Duration::from_secs(1)).unwrap();
        let error = worker
            .run(|| -> anyhow::Result<()> { panic!("test worker panic") })
            .await
            .expect_err("a panicked blocking worker must remain typed");
        assert_eq!(error.terminal().kind, DetectionFailureKind::Worker);
    }

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
    fn configured_operational_limits_fail_before_artifact_loading() {
        for (field, value, expected) in [
            ("max_concurrent", serde_json::json!(0), "max_concurrent"),
            ("max_concurrent", serde_json::json!(65), "max_concurrent"),
            ("max_concurrent", serde_json::json!(usize::MAX), "max_concurrent"),
            ("max_queued", serde_json::json!(0), "max_queued"),
            ("max_queued", serde_json::json!(1_025), "max_queued"),
            ("max_queued", serde_json::json!(usize::MAX), "max_queued"),
            (
                "inference_timeout_ms",
                serde_json::json!(0),
                "inference_timeout_ms",
            ),
            (
                "inference_timeout_ms",
                serde_json::json!(u64::MAX),
                "inference_timeout_ms",
            ),
        ] {
            let mut config = serde_json::json!({
                "model_path": "/nonexistent/model.onnx",
                "tokenizer_path": "/nonexistent/tokenizer.json",
                "model_sha256": "0000000000000000000000000000000000000000000000000000000000000001",
                "tokenizer_sha256": "0000000000000000000000000000000000000000000000000000000000000002"
            });
            config[field] = value;
            let error = InprocessDetector::from_config(&config)
                .err()
                .expect("unsafe operational limit must fail config");
            assert!(
                error.to_string().contains(expected),
                "{field} failed at the wrong boundary: {error}"
            );
            assert!(
                !error.to_string().contains("artifact"),
                "{field} must be rejected before artifact loading: {error}"
            );
        }
    }

    #[test]
    fn configured_exact_operational_maxima_pass_limit_validation() {
        let error = InprocessDetector::from_config(&serde_json::json!({
            "model_path": "/nonexistent/model.onnx",
            "tokenizer_path": "/nonexistent/tokenizer.json",
            "model_sha256": "0000000000000000000000000000000000000000000000000000000000000001",
            "tokenizer_sha256": "0000000000000000000000000000000000000000000000000000000000000002",
            "max_concurrent": INPROCESS_MAX_CONCURRENT,
            "max_queued": INPROCESS_MAX_QUEUED,
            "inference_timeout_ms": 30_000
        }))
        .err()
        .expect("the nonexistent artifact still prevents construction");
        assert!(
            error.to_string().contains("stat local model artifact"),
            "exact maxima must pass limit validation and reach artifact loading: {error}"
        );
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
