//! Sidecar-backed detector for `prompt_injection_v2`.
//!
//! Routes detection to the out-of-process classifier sidecar over gRPC instead
//! of running ONNX inference inside the proxy. The sidecar (the minimal OSS one
//! or the richer enterprise one) implements the shared `InferenceService`; this
//! detector owns one lazily-connected client and maps its response onto the v2
//! label vocabulary, reusing the ONNX detector's score cutoffs so the two
//! report identically. The gRPC channel is built on the first `detect` call,
//! not at construction: tonic channel creation spawns onto the Tokio runtime
//! and config-load runs outside one, so building it eagerly panicked the
//! proxy at boot (WOR-1783).
//!
//! Response validation lives in the client (`validate_classify_response` in
//! `sbproxy-classifier-client`): a structurally malformed sidecar response
//! reaches this detector as a protocol error and follows the configured
//! failure posture like any other sidecar failure, never a clean verdict
//! (WOR-2161).
//!
//! The [`Detector`] trait is synchronous and runs on the request hot path,
//! while the gRPC client is async. We bridge with `tokio::task::block_in_place`
//! plus `Handle::block_on`, which requires the multi-threaded runtime the proxy
//! already runs on. Unit tests that call `detect` directly must therefore use a
//! `multi_thread` runtime flavor.

use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use sbproxy_classifier_client::ClassifyResponse;
use sbproxy_classifier_client::{ClassifierClient, ClassifierClientError, Label};
use sbproxy_config::types::FailureMode;
use serde::Deserialize;

use super::detector::{DetectionLabel, DetectionResult, Detector};

/// Map a `[0,1]` injection score onto the v2 label vocabulary. Owned by
/// the sidecar detector (the in-process ONNX detector that previously
/// shared it was removed in WOR-612).
fn classify_score(score: f64, threshold: f64) -> DetectionLabel {
    if score >= threshold {
        DetectionLabel::Injection
    } else if score >= 0.3 {
        DetectionLabel::Suspicious
    } else {
        DetectionLabel::Clean
    }
}

/// Config name selecting this detector (`detector: "sidecar"`).
pub const SIDECAR_DETECTOR_NAME: &str = "sidecar";

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:9440";
const DEFAULT_MODEL: &str = "prompt-injection";
const DEFAULT_INJECTION_LABEL: &str = "injection";
const DEFAULT_TIMEOUT_MS: u64 = 250;
const DEFAULT_THRESHOLD: f64 = 0.5;

/// Deserializable `detector_config` block for the sidecar detector.
#[derive(Debug, Deserialize)]
struct SidecarDetectorConfig {
    /// Sidecar gRPC endpoint, e.g. `http://127.0.0.1:9440`.
    #[serde(default = "default_endpoint")]
    endpoint: String,
    /// Model id to request (empty selects the sidecar's default model).
    #[serde(default = "default_model")]
    model: String,
    /// Label name the sidecar uses for an injection verdict. A returned label
    /// matching this (case-insensitive) is treated as the injection score; any
    /// other top label is read as a confidence that the prompt is benign.
    /// Must be non-empty; validated at config load.
    #[serde(default = "default_injection_label")]
    injection_label: String,
    /// Per-call timeout in milliseconds (covers the lazy connect on first use).
    /// Must be greater than zero; validated at config load.
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// Legacy failure knob: when `true`, a sidecar error (down, timeout, rpc
    /// status, malformed response) is treated as a high-confidence injection
    /// (deny). Defaults to `false`: errors degrade to `clean` so a sidecar
    /// outage never takes the request path down.
    ///
    /// Superseded by `failure_posture`, which spells the same decision with
    /// a word instead of a boolean: `fail_closed: true` is
    /// `failure_posture: closed` and `fail_closed: false` (or an omitted
    /// key) is `failure_posture: open`. Still parsed, and still the value
    /// used when `failure_posture` is absent, so existing configs are
    /// unaffected. Setting both keys to values that disagree is a
    /// config-load error.
    ///
    /// Read through [`Self::failure_posture()`], never directly.
    #[serde(default)]
    fail_closed: Option<bool>,
    /// What this detector reports when the sidecar cannot return a verdict
    /// (down, slower than `timeout_ms`, rpc error, malformed response).
    ///
    /// - `closed` reports a high-confidence injection, so `action: block`
    ///   denies the request. Pair it with `action: block` only when a
    ///   missing verdict should deny, and budget for the sidecar's
    ///   availability accordingly.
    /// - `open` (the default, and what `fail_closed: false` resolves to)
    ///   reports a clean verdict, so an inference outage never takes the
    ///   request path down.
    /// - `degraded` is rejected at config load. The detector has no channel
    ///   yet to mark an admitted request's detection guarantee as waived
    ///   (that is WOR-2185), so `degraded` would behave exactly like `open`
    ///   while claiming more.
    /// - `observe` is rejected at config load. This posture applies when
    ///   the sidecar produced no verdict, so there is no verdict whose
    ///   counterfactual could be recorded.
    #[serde(default)]
    failure_posture: Option<FailureMode>,
    /// Score at or above which a sidecar verdict is labelled `injection`.
    /// Must be finite and in `[0.0, 1.0]`; validated at config load.
    #[serde(default = "default_threshold")]
    threshold: f64,
}

fn default_endpoint() -> String {
    DEFAULT_ENDPOINT.to_string()
}
fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}
fn default_injection_label() -> String {
    DEFAULT_INJECTION_LABEL.to_string()
}
fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}
fn default_threshold() -> f64 {
    DEFAULT_THRESHOLD
}

impl SidecarDetectorConfig {
    /// Effective failure posture for this detector.
    ///
    /// The explicit `failure_posture` key wins. When it is absent the
    /// legacy `fail_closed` boolean is converted, so a config written
    /// before the key existed keeps its exact behaviour: `fail_closed:
    /// true` is [`FailureMode::Closed`] and `fail_closed: false` (or an
    /// omitted key) is [`FailureMode::Open`].
    ///
    /// This is the only supported read path. Do not branch on
    /// `fail_closed` directly; the polarity conversion belongs in one
    /// place.
    fn failure_posture(&self) -> FailureMode {
        self.failure_posture
            .unwrap_or_else(|| FailureMode::from_fail_closed(self.fail_closed.unwrap_or(false)))
    }

    /// Reject a failure axis that says two things at once, or that says
    /// something this detector cannot honour.
    fn validate_failure_posture(&self) -> anyhow::Result<()> {
        let Some(posture) = self.failure_posture else {
            return Ok(());
        };
        if posture == FailureMode::Observe {
            anyhow::bail!(
                "sidecar detector: `failure_posture: observe` is not meaningful here. \
                 This posture applies when the sidecar could not return a verdict, so \
                 there is no verdict whose counterfactual could be recorded. Use \
                 `closed` to deny the request or `open` to admit it."
            );
        }
        if posture == FailureMode::Degraded {
            // WOR-2185 is the ticket that would build the degraded
            // semantics for this site; until it lands, accepting the
            // word would promise a record nothing writes.
            anyhow::bail!(
                "sidecar detector: `failure_posture: degraded` is not supported here \
                 yet. The detector has no way to mark an admitted request's detection \
                 guarantee as waived, so `degraded` would behave exactly like `open` \
                 while claiming more. Use `open` or `closed`."
            );
        }
        if let Some(fail_closed) = self.fail_closed {
            let legacy = FailureMode::from_fail_closed(fail_closed);
            if legacy != posture {
                anyhow::bail!(
                    "fail_closed: {fail_closed} and failure_posture: {} disagree on the \
                     sidecar detector; fail_closed: {fail_closed} means failure_posture: \
                     {}. Remove fail_closed and keep failure_posture",
                    posture.as_label(),
                    legacy.as_label()
                );
            }
        }
        Ok(())
    }
}

/// Detector that delegates classification to the classifier sidecar.
pub struct SidecarDetector {
    /// Validated at config load; the channel is built on first use.
    endpoint: String,
    timeout: Duration,
    /// The lazily-built client. `OnceLock` because construction must
    /// happen on a runtime thread (first `detect`), not at config load
    /// (WOR-1783). A lost set race just drops a cheap unconnected
    /// channel.
    client: std::sync::OnceLock<ClassifierClient>,
    model: String,
    injection_label: String,
    threshold: f64,
    /// Resolved once at config load from the explicit `failure_posture`
    /// key or the legacy `fail_closed` boolean
    /// ([`SidecarDetectorConfig::failure_posture`]). Only `closed` and
    /// `open` survive validation.
    failure_posture: FailureMode,
    name: &'static str,
}

impl SidecarDetector {
    /// Build from the policy's `detector_config` block.
    ///
    /// An invalid endpoint URI, a non-finite or out-of-range `threshold`, a
    /// zero `timeout_ms`, an empty `injection_label`, a `failure_posture`
    /// this detector cannot honour (`observe`, `degraded`), or a
    /// `failure_posture` that disagrees with the legacy `fail_closed`
    /// boolean fails here, at config load. The channel is built on the
    /// first `detect` call, so a sidecar that is not yet up does not block
    /// startup and construction is safe outside a Tokio runtime.
    /// Per-request transport and protocol errors are routed through the
    /// configured failure posture in [`detect`](Detector::detect).
    pub fn from_config(value: &serde_json::Value) -> anyhow::Result<Arc<dyn Detector>> {
        Ok(Arc::new(Self::parse(value)?))
    }

    /// Deserialize and validate the config block (see
    /// [`from_config`](Self::from_config) for what is rejected).
    pub(super) fn parse(value: &serde_json::Value) -> anyhow::Result<Self> {
        let cfg: SidecarDetectorConfig = serde_json::from_value(value.clone())
            .map_err(|e| anyhow::anyhow!("sidecar detector config: {e}"))?;
        ClassifierClient::validate_endpoint(&cfg.endpoint)
            .map_err(|e| anyhow::anyhow!("sidecar detector: {e}"))?;
        if !cfg.threshold.is_finite() || !(0.0..=1.0).contains(&cfg.threshold) {
            return Err(anyhow::anyhow!(
                "sidecar detector threshold must be a finite number in [0.0, 1.0], got {}",
                cfg.threshold
            ));
        }
        if cfg.timeout_ms == 0 {
            return Err(anyhow::anyhow!(
                "sidecar detector timeout_ms must be greater than zero; \
                 with 0 every call would time out immediately"
            ));
        }
        if cfg.injection_label.is_empty() {
            return Err(anyhow::anyhow!(
                "sidecar detector injection_label must not be empty; set the label \
                 your model emits for an injection verdict (default \"injection\")"
            ));
        }
        cfg.validate_failure_posture()?;
        let failure_posture = cfg.failure_posture();
        Ok(Self {
            endpoint: cfg.endpoint,
            timeout: Duration::from_millis(cfg.timeout_ms),
            client: std::sync::OnceLock::new(),
            model: cfg.model,
            injection_label: cfg.injection_label,
            threshold: cfg.threshold,
            failure_posture,
            name: SIDECAR_DETECTOR_NAME,
        })
    }

    /// Map a classify outcome onto a detection result.
    ///
    /// The client validates every classification response before returning
    /// it (at least one label, non-empty unique names, finite scores in
    /// `[0.0, 1.0]`, sorted highest score first), so a malformed response
    /// arrives here as `Err(ClassifierClientError::Protocol)` and flows
    /// through the configured failure posture exactly like a transport error.
    /// A malformed response must never read as a clean verdict (WOR-2161).
    #[cfg(test)]
    fn map_outcome(
        &self,
        outcome: Result<ClassifyResponse, ClassifierClientError>,
    ) -> DetectionResult {
        let resp = match outcome {
            Ok(resp) => resp,
            Err(e) => return self.on_error(&e),
        };
        // The client guarantees labels are sorted highest score first, so
        // the sidecar's verdict is the first entry.
        let Some(Label { name, score }) = resp.labels.into_iter().next() else {
            // Unreachable: the client rejects a response with no labels.
            // Kept as a guard so a future client regression still follows
            // the fail policy instead of inventing a clean verdict.
            return self.on_error(&ClassifierClientError::Protocol(
                "classification response contains no labels".to_string(),
            ));
        };
        let is_injection_label = name.eq_ignore_ascii_case(&self.injection_label);
        // Same mapping as the ONNX detector: a non-injection top label is
        // read as confidence the prompt is benign, so invert it. The client
        // bounds every score to [0.0, 1.0], so the inversion stays in range.
        let (score_for_policy, label) = if is_injection_label {
            (score, classify_score(score, self.threshold))
        } else {
            (1.0 - score, classify_score(1.0 - score, self.threshold))
        };
        DetectionResult {
            score: score_for_policy,
            label,
            reason: Some(format!(
                "sidecar model={} label={} score={:.3}",
                self.model, name, score
            )),
        }
    }

    /// Ask the sidecar for a verdict without applying its terminal failure
    /// posture. The shipping policy uses this entry point so a transport or
    /// protocol failure can be handed to its verified local ONNX fallback.
    pub(super) fn try_detect(
        &self,
        prompt: &str,
    ) -> Result<DetectionResult, ClassifierClientError> {
        // Build the channel on first use, once a Tokio runtime is available.
        let client = match self.client.get() {
            Some(client) => client,
            None => {
                let client = ClassifierClient::connect_lazy(&self.endpoint, self.timeout)?;
                let _ = self.client.set(client);
                self.client.get().expect("client just set")
            }
        };
        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.classify(&self.model, prompt))
        })?;

        let Some(Label { name, score }) = response.labels.into_iter().next() else {
            return Err(ClassifierClientError::Protocol(
                "classification response contains no labels".to_string(),
            ));
        };
        let is_injection_label = name.eq_ignore_ascii_case(&self.injection_label);
        let (score_for_policy, label) = if is_injection_label {
            (score, classify_score(score, self.threshold))
        } else {
            (1.0 - score, classify_score(1.0 - score, self.threshold))
        };
        Ok(DetectionResult {
            score: score_for_policy,
            label,
            reason: Some(format!(
                "sidecar model={} label={} score={:.3}",
                self.model, name, score
            )),
        })
    }

    /// Map a transport/rpc/protocol error onto the configured failure
    /// posture.
    fn on_error(&self, err: &ClassifierClientError) -> DetectionResult {
        match self.failure_posture {
            FailureMode::Closed => {
                tracing::warn!(
                    error = %err,
                    failure_posture = self.failure_posture.as_label(),
                    "classifier sidecar unavailable; failing closed (injection)"
                );
                DetectionResult {
                    score: 1.0,
                    label: DetectionLabel::Injection,
                    reason: Some("classifier sidecar unavailable (fail-closed)".to_string()),
                }
            }
            FailureMode::Open => {
                tracing::warn!(
                    error = %err,
                    failure_posture = self.failure_posture.as_label(),
                    "classifier sidecar unavailable; failing open (clean)"
                );
                DetectionResult::clean()
            }
            // Both are rejected by `parse`, so these arms are unreachable
            // from a loaded config. Kept explicit (no wildcard) so building
            // the degraded semantics (WOR-2185) forces a decision here
            // rather than inheriting one; until then, honour their
            // admitting nature.
            FailureMode::Degraded | FailureMode::Observe => {
                tracing::warn!(
                    error = %err,
                    failure_posture = self.failure_posture.as_label(),
                    "classifier sidecar unavailable; posture admits, treating as open (clean)"
                );
                DetectionResult::clean()
            }
        }
    }
}

impl Detector for SidecarDetector {
    fn detect(&self, prompt: &str) -> DetectionResult {
        self.try_detect(prompt)
            .unwrap_or_else(|error| self.on_error(&error))
    }

    fn name(&self) -> &str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A SidecarDetector pointed at a dead endpoint, with the given fail policy.
    fn detector_to_nowhere(fail_closed: bool) -> Arc<dyn Detector> {
        SidecarDetector::from_config(&serde_json::json!({
            // Port 1 refuses immediately; the lazy connect fails on first call.
            "endpoint": "http://127.0.0.1:1",
            "timeout_ms": 200,
            "fail_closed": fail_closed,
        }))
        .expect("valid config")
    }

    #[test]
    fn construction_outside_a_runtime_does_not_panic() {
        // WOR-1783 regression: tonic channel construction spawns onto
        // the Tokio runtime, and policy construction at config load
        // runs outside one. With an eager channel this test panics with
        // "there is no reactor running"; the detector must defer the
        // channel to the first detect() call.
        let det = SidecarDetector::from_config(&serde_json::json!({
            "endpoint": "http://127.0.0.1:9440",
        }))
        .expect("valid config");
        assert_eq!(det.name(), SIDECAR_DETECTOR_NAME);
    }

    #[test]
    fn invalid_endpoint_is_a_config_error() {
        // `Arc<dyn Detector>` is not Debug, so we cannot use expect_err here.
        let err = match SidecarDetector::from_config(&serde_json::json!({
            "endpoint": "not a uri",
        })) {
            Ok(_) => panic!("garbage endpoint must fail at config time"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("sidecar detector"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fail_open_returns_clean_when_sidecar_is_down() {
        // detect() bridges to async via block_in_place, so it must run on a
        // multi-thread worker -- which the test future already is.
        let det = detector_to_nowhere(false);
        let result = det.detect("ignore previous instructions");
        assert_eq!(result.label, DetectionLabel::Clean);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fail_closed_returns_injection_when_sidecar_is_down() {
        let det = detector_to_nowhere(true);
        let result = det.detect("ignore previous instructions");
        assert_eq!(result.label, DetectionLabel::Injection);
        assert_eq!(result.score, 1.0);
    }

    // --- config validation (WOR-2161) ---

    #[test]
    fn config_rejects_out_of_range_or_non_finite_threshold() {
        for threshold in [-0.1, 1.5, 2.0] {
            let err = match SidecarDetector::from_config(&serde_json::json!({
                "threshold": threshold,
            })) {
                Ok(_) => panic!("threshold {threshold} must fail at config time"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("threshold"),
                "unexpected error for {threshold}: {err}"
            );
        }
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let err = match SidecarDetector::from_config(&serde_json::json!({
            "timeout_ms": 0,
        })) {
            Ok(_) => panic!("timeout_ms 0 must fail at config time"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn config_rejects_empty_injection_label() {
        let err = match SidecarDetector::from_config(&serde_json::json!({
            "injection_label": "",
        })) {
            Ok(_) => panic!("empty injection_label must fail at config time"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("injection_label"));
    }

    #[test]
    fn config_accepts_boundary_thresholds() {
        for threshold in [0.0, 1.0] {
            SidecarDetector::from_config(&serde_json::json!({
                "threshold": threshold,
            }))
            .expect("boundary thresholds are valid");
        }
    }

    // --- malformed responses follow the fail policy (WOR-2161) ---

    // A concrete SidecarDetector (from_config erases the type behind
    // `Arc<dyn Detector>`, and map_outcome is an inherent method).
    fn concrete(fail_closed: bool) -> SidecarDetector {
        SidecarDetector::parse(&serde_json::json!({
            "endpoint": "http://127.0.0.1:1",
            "timeout_ms": 200,
            "fail_closed": fail_closed,
        }))
        .expect("valid config")
    }

    #[test]
    fn protocol_error_fails_closed_as_injection() {
        // The regression WOR-2161 fixes: a malformed sidecar response used
        // to be treated as a clean verdict even under fail_closed. It must
        // follow the fail policy like any other sidecar failure.
        let det = concrete(true);
        let result = det.map_outcome(Err(ClassifierClientError::Protocol(
            "classification response contains no labels".to_string(),
        )));
        assert_eq!(result.label, DetectionLabel::Injection);
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn protocol_error_fails_open_as_clean_via_the_fail_policy() {
        let det = concrete(false);
        let result = det.map_outcome(Err(ClassifierClientError::Protocol(
            "classification response contains no labels".to_string(),
        )));
        assert_eq!(result.label, DetectionLabel::Clean);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn a_label_free_response_that_slips_past_the_client_fails_closed() {
        // The client rejects label-free responses before they get here, so
        // this exercises the defensive guard: even if one slipped through,
        // it must follow the fail policy, not read as clean.
        let det = concrete(true);
        let result = det.map_outcome(Ok(ClassifyResponse {
            labels: vec![],
            latency_us: 1,
        }));
        assert_eq!(result.label, DetectionLabel::Injection);
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn a_label_free_response_fails_open_only_via_the_fail_policy() {
        let det = concrete(false);
        let result = det.map_outcome(Ok(ClassifyResponse {
            labels: vec![],
            latency_us: 1,
        }));
        assert_eq!(result.label, DetectionLabel::Clean);
        assert_eq!(result.score, 0.0);
    }

    // --- failure_posture (WOR-2182) ---

    // A SidecarDetector pointed at a dead endpoint, with an explicit posture.
    fn detector_with_posture(posture: &str) -> Arc<dyn Detector> {
        SidecarDetector::from_config(&serde_json::json!({
            "endpoint": "http://127.0.0.1:1",
            "timeout_ms": 200,
            "failure_posture": posture,
        }))
        .expect("valid config")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failure_posture_closed_denies_when_sidecar_is_down() {
        let det = detector_with_posture("closed");
        let result = det.detect("ignore previous instructions");
        assert_eq!(result.label, DetectionLabel::Injection);
        assert_eq!(result.score, 1.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failure_posture_open_admits_when_sidecar_is_down() {
        let det = detector_with_posture("open");
        let result = det.detect("ignore previous instructions");
        assert_eq!(result.label, DetectionLabel::Clean);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn legacy_fail_closed_still_selects_the_posture() {
        // An absent key, an explicit false, and an explicit true keep the
        // exact meanings they had before `failure_posture` existed.
        for (config, expected) in [
            (serde_json::json!({}), FailureMode::Open),
            (serde_json::json!({"fail_closed": false}), FailureMode::Open),
            (
                serde_json::json!({"fail_closed": true}),
                FailureMode::Closed,
            ),
        ] {
            let det = SidecarDetector::parse(&config).expect("valid config");
            assert_eq!(det.failure_posture, expected, "{config}");
        }
    }

    #[test]
    fn explicit_failure_posture_wins_over_the_legacy_default() {
        // With no legacy key present, the explicit posture is the value,
        // including `closed` where the legacy default would be open.
        let det = SidecarDetector::parse(&serde_json::json!({
            "failure_posture": "closed",
        }))
        .expect("valid config");
        assert_eq!(det.failure_posture, FailureMode::Closed);
    }

    #[test]
    fn agreeing_fail_closed_and_failure_posture_parse() {
        for (fail_closed, posture, expected) in [
            (true, "closed", FailureMode::Closed),
            (false, "open", FailureMode::Open),
        ] {
            let det = SidecarDetector::parse(&serde_json::json!({
                "fail_closed": fail_closed,
                "failure_posture": posture,
            }))
            .expect("a redundant but consistent pair stays valid");
            assert_eq!(det.failure_posture, expected);
        }
    }

    #[test]
    fn conflicting_fail_closed_and_failure_posture_is_a_config_error() {
        for (fail_closed, posture) in [(true, "open"), (false, "closed")] {
            let err = match SidecarDetector::from_config(&serde_json::json!({
                "fail_closed": fail_closed,
                "failure_posture": posture,
            })) {
                Ok(_) => panic!("disagreeing spellings must fail at config load"),
                Err(e) => e,
            };
            let msg = err.to_string();
            assert!(msg.contains("fail_closed"), "{msg}");
            assert!(msg.contains("failure_posture"), "{msg}");
        }
    }

    #[test]
    fn observe_failure_posture_is_rejected_at_config_load() {
        let err = match SidecarDetector::from_config(&serde_json::json!({
            "failure_posture": "observe",
        })) {
            Ok(_) => panic!("observe must fail at config time"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("observe"), "{msg}");
        assert!(msg.contains("sidecar detector"), "{msg}");
    }

    #[test]
    fn degraded_failure_posture_is_rejected_at_config_load() {
        // The degraded semantics for this site are not built (WOR-2185);
        // until they are, the word must not parse here.
        let err = match SidecarDetector::from_config(&serde_json::json!({
            "failure_posture": "degraded",
        })) {
            Ok(_) => panic!("degraded must fail at config time"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("degraded"), "{msg}");
        assert!(msg.contains("not supported"), "{msg}");
    }

    #[test]
    fn a_valid_injection_verdict_maps_onto_the_v2_vocabulary() {
        let det = concrete(false);
        let result = det.map_outcome(Ok(ClassifyResponse {
            labels: vec![
                Label {
                    name: "INJECTION".to_string(),
                    score: 0.9,
                },
                Label {
                    name: "benign".to_string(),
                    score: 0.1,
                },
            ],
            latency_us: 1,
        }));
        assert_eq!(result.label, DetectionLabel::Injection);
        assert_eq!(result.score, 0.9);
    }

    #[test]
    fn a_benign_top_label_inverts_into_a_low_injection_score() {
        let det = concrete(false);
        let result = det.map_outcome(Ok(ClassifyResponse {
            labels: vec![Label {
                name: "benign".to_string(),
                score: 0.9,
            }],
            latency_us: 1,
        }));
        assert_eq!(result.label, DetectionLabel::Clean);
        assert!((result.score - 0.1).abs() < 1e-9);
    }
}
