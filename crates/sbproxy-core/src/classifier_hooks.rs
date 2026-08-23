//! A real [`crate::hooks::IntentDetectionHook`] backed by the classifier
//! sidecar (WOR-2661/WOR-2665), closing the gap
//! `crate::intent_detection`'s module doc used to call out: "no
//! sidecar-backed implementation ships in this OSS tree today."
//!
//! [`crate::classifier_hooks::ClassifierIntentHook`] wraps
//! [`sbproxy_classifier_client::FallbackClassifier`], the WOR-2665
//! optional-degrade client, so it inherits its exact three-case contract:
//!
//! - No sidecar configured (`sidecar: None`): every call runs the local
//!   keyword heuristic ([`crate::intent_detection::detect_intent_heuristic`]).
//!   No connection is ever attempted.
//! - A sidecar is configured but unreachable, times out, or errors: the
//!   call degrades to the heuristic for that request.
//! - A sidecar is configured and healthy: its classification is used, and
//!   the heuristic is not run at all.
//!
//! # What the sidecar has to return
//!
//! The sidecar's generic `Classify` RPC returns a label plus a confidence
//! score; it has no built-in notion of "intent". This hook maps the
//! top label back to [`crate::hooks::IntentCategory`] by exact,
//! lowercase name (`"coding"`, `"vision"`, `"analysis"`,
//! `"summarization"`, `"general"`), so it only produces a useful result
//! when the sidecar's tenant is configured with a label set that matches
//! those five names. A label outside that set degrades to `None`, which
//! is a real "the hook declined" per
//! [`crate::hooks::IntentDetectionHook::detect`]'s contract, not a bug:
//! [`crate::intent_detection::detect_intent_with_source`] runs the
//! heuristic on `None` the same as it would for a missing hook.
//!
//! Stock proxy configuration can install both intent and provider-quality
//! hooks. Intent maps a classifier model's top label to the five categories
//! above. Quality maps each provider to a classifier model plus the exact
//! positive label whose score represents suitability for the current prompt.
//! This deliberately uses `Classify`, not the rich sidecar's completed-text
//! `Quality` RPC: provider routing happens before any provider has produced a
//! response. Every configured candidate must answer inside one shared
//! deadline or the request preserves its configured routing order.

use async_trait::async_trait;
use sbproxy_classifier_client::{
    ClassifierClient, ClassifierClientError, ClassifyResponse, FallbackClassifier,
    InProcessClassifier, Verdict,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::hooks::{
    Hooks, IntentCategory, IntentDetectionHook, QualityRequest, QualityScore, QualityScoringHook,
};
use crate::intent_detection::detect_intent_heuristic;

/// Adapts [`detect_intent_heuristic`] to [`InProcessClassifier`] so
/// [`FallbackClassifier`] can degrade to it without a network round trip.
struct IntentHeuristic;

impl InProcessClassifier for IntentHeuristic {
    fn classify(&self, text: &str) -> Verdict {
        let category: IntentCategory = detect_intent_heuristic(text).into();
        Verdict {
            label: intent_label(category).to_string(),
            // The heuristic does not produce a confidence score; 1.0
            // marks "this categorical rule fired", not a calibrated
            // probability. `ClassifierIntentHook::detect` never reads
            // this field, only `label`.
            score: 1.0,
        }
    }
}

/// Canonical lowercase label [`ClassifierIntentHook`] expects the sidecar
/// (or the in-process heuristic fallback) to use for each category.
fn intent_label(category: IntentCategory) -> &'static str {
    match category {
        IntentCategory::Coding => "coding",
        IntentCategory::Vision => "vision",
        IntentCategory::Analysis => "analysis",
        IntentCategory::Summarization => "summarization",
        IntentCategory::General => "general",
    }
}

/// The inverse of [`intent_label`]. Returns `None` for any label the
/// sidecar returns that this hook does not recognize, which the caller
/// treats as "declined to decide" per the hook's fail-open contract.
fn category_from_label(label: &str) -> Option<IntentCategory> {
    match label {
        "coding" => Some(IntentCategory::Coding),
        "vision" => Some(IntentCategory::Vision),
        "analysis" => Some(IntentCategory::Analysis),
        "summarization" => Some(IntentCategory::Summarization),
        "general" => Some(IntentCategory::General),
        _ => None,
    }
}

/// [`IntentDetectionHook`] backed by the classifier sidecar, degrading to
/// the local keyword heuristic per [`FallbackClassifier`]'s contract. See
/// the module docs for the label contract and why `QualityScoringHook` is
/// not built the same way.
pub struct ClassifierIntentHook {
    inner: FallbackClassifier<IntentHeuristic>,
}

impl ClassifierIntentHook {
    /// Build a hook that classifies through `sidecar` (`None` runs the
    /// heuristic on every call, the common OSS case: no sidecar deployed
    /// at all) using `model` as the sidecar's logical model id for the
    /// `Classify` RPC (empty selects the sidecar's default).
    pub fn new(sidecar: Option<ClassifierClient>, model: impl Into<String>) -> Self {
        Self {
            inner: FallbackClassifier::new(sidecar, model, IntentHeuristic),
        }
    }

    /// True when a sidecar is configured (whether or not it is currently
    /// reachable). Exposed for callers that want to log or report which
    /// mode a request ran in without duplicating the `Option` check.
    pub fn has_sidecar_configured(&self) -> bool {
        self.inner.has_sidecar_configured()
    }
}

#[async_trait]
impl IntentDetectionHook for ClassifierIntentHook {
    async fn detect(&self, prompt: &str) -> Option<IntentCategory> {
        let verdict = self.inner.classify(prompt).await;
        category_from_label(&verdict.label)
    }
}

/// One lazily constructed channel shared by the stock intent and quality
/// hooks. Pipeline compilation is synchronous and may run without a Tokio
/// runtime, so only URI validation happens there. The channel is constructed
/// on the first request-path call, inside the runtime, and then reused.
struct LazyClassifierClient {
    endpoint: String,
    timeout: Duration,
    client: tokio::sync::OnceCell<ClassifierClient>,
}

impl LazyClassifierClient {
    fn new(endpoint: String, timeout: Duration) -> Self {
        Self {
            endpoint,
            timeout,
            client: tokio::sync::OnceCell::new(),
        }
    }

    async fn classify(
        &self,
        model: &str,
        text: &str,
    ) -> Result<ClassifyResponse, ClassifierClientError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                ClassifierClient::connect_lazy(&self.endpoint, self.timeout)
            })
            .await?;
        client.classify(model, text).await
    }
}

/// Stock sidecar intent hook. Unlike [`ClassifierIntentHook`], it returns
/// `None` when the configured sidecar fails so the shared dispatcher can
/// report `heuristic_degraded` separately from unconfigured heuristic mode.
struct StockClassifierIntentHook {
    client: Arc<LazyClassifierClient>,
    model: String,
}

#[async_trait]
impl IntentDetectionHook for StockClassifierIntentHook {
    async fn detect(&self, prompt: &str) -> Option<IntentCategory> {
        match self.client.classify(&self.model, prompt).await {
            Ok(response) => response
                .labels
                .first()
                .and_then(|label| category_from_label(&label.name)),
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "configured intent classifier unavailable; using heuristic fallback"
                );
                None
            }
        }
    }
}

/// Stock prompt-aware provider scorer backed by per-provider classifier
/// contracts from `proxy.classifier_hooks.quality.provider_models`.
struct ClassifierQualityHook {
    client: Arc<LazyClassifierClient>,
    timeout: Duration,
    minimum_score: f64,
    provider_models: HashMap<String, sbproxy_config::ClassifierProviderModelConfig>,
}

#[async_trait]
impl QualityScoringHook for ClassifierQualityHook {
    fn minimum_score(&self) -> f64 {
        self.minimum_score
    }

    async fn score_providers(&self, req: &QualityRequest) -> Option<Vec<QualityScore>> {
        const MAX_CANDIDATES: usize = 64;
        if req.candidate_providers.len() > MAX_CANDIDATES {
            tracing::warn!(
                candidates = req.candidate_providers.len(),
                maximum = MAX_CANDIDATES,
                "quality classifier candidate limit exceeded; preserving configured routing"
            );
            return None;
        }

        let contracts = req
            .candidate_providers
            .iter()
            .map(|provider| {
                self.provider_models
                    .get(provider)
                    .cloned()
                    .map(|contract| (provider.clone(), contract))
            })
            .collect::<Option<Vec<_>>>()?;

        let calls = contracts.into_iter().map(|(provider, contract)| {
            let client = Arc::clone(&self.client);
            let prompt = req.prompt.clone();
            async move {
                let response = client.classify(&contract.model, &prompt).await;
                (provider, contract.label, response)
            }
        });
        let results = tokio::time::timeout(self.timeout, futures::future::join_all(calls))
            .await
            .ok()?;

        let mut scores = Vec::with_capacity(results.len());
        for (provider, positive_label, response) in results {
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(
                        error = %error,
                        provider,
                        "configured quality classifier unavailable; preserving configured routing"
                    );
                    return None;
                }
            };
            let score = response
                .labels
                .iter()
                .find(|label| label.name == positive_label)
                .map(|label| label.score)?;
            scores.push(QualityScore { provider, score });
        }
        Some(scores)
    }
}

/// Compile stock classifier hooks from operator configuration without
/// dialing the sidecar. URI and resource-bound validation is eager; network
/// availability remains fail-open on each request.
pub(crate) fn hooks_from_config(
    config: Option<&sbproxy_config::ClassifierHooksConfig>,
) -> anyhow::Result<Hooks> {
    let Some(config) = config else {
        return Ok(Hooks::default());
    };
    config.validate()?;
    ClassifierClient::validate_endpoint(&config.endpoint)
        .map_err(|error| anyhow::anyhow!("proxy.classifier_hooks.endpoint: {error}"))?;

    let timeout = Duration::from_millis(config.timeout_ms);
    let client = Arc::new(LazyClassifierClient::new(config.endpoint.clone(), timeout));
    let intent_detection = config.intent.as_ref().map(|intent| {
        Arc::new(StockClassifierIntentHook {
            client: Arc::clone(&client),
            model: intent.model.clone(),
        }) as Arc<dyn IntentDetectionHook>
    });
    let quality_scoring = config.quality.as_ref().map(|quality| {
        Arc::new(ClassifierQualityHook {
            client,
            timeout,
            minimum_score: quality.minimum_score,
            provider_models: quality.provider_models.clone(),
        }) as Arc<dyn QualityScoringHook>
    });

    Ok(Hooks {
        intent_detection,
        quality_scoring,
        ..Hooks::default()
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn no_sidecar_configured_runs_heuristic_directly() {
        let hook = ClassifierIntentHook::new(None, "intent");
        assert!(!hook.has_sidecar_configured());
        assert_eq!(
            hook.detect("please help me debug this function").await,
            Some(IntentCategory::Coding)
        );
        assert_eq!(
            hook.detect("what is the capital of France?").await,
            Some(IntentCategory::General)
        );
    }

    /// A configured-but-unreachable sidecar (a refused connection on a
    /// dead loopback port, exactly the fallback.rs pattern this hook
    /// wraps) degrades to the heuristic rather than returning `None`
    /// outright, so a broken sidecar makes intent detection revert to
    /// the OSS default instead of going silent.
    #[tokio::test]
    async fn unreachable_sidecar_degrades_to_heuristic() {
        // Port 1 is a privileged port nothing in a test sandbox is
        // listening on; `connect_lazy` never dials until the first RPC,
        // so building the client here cannot itself fail.
        let dead_client =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let hook = ClassifierIntentHook::new(Some(dead_client), "intent");
        assert!(hook.has_sidecar_configured());
        assert_eq!(
            hook.detect("please implement a binary search").await,
            Some(IntentCategory::Coding)
        );
    }

    #[test]
    fn label_round_trips_every_category() {
        for category in [
            IntentCategory::Coding,
            IntentCategory::Vision,
            IntentCategory::Analysis,
            IntentCategory::Summarization,
            IntentCategory::General,
        ] {
            assert_eq!(category_from_label(intent_label(category)), Some(category));
        }
    }

    #[test]
    fn unrecognized_label_declines_rather_than_guessing() {
        assert_eq!(category_from_label("spam"), None);
        assert_eq!(category_from_label(""), None);
    }

    #[test]
    fn heuristic_adapter_produces_a_recognized_label() {
        let verdict = IntentHeuristic.classify("summarize this article for me");
        assert_eq!(verdict.label, "summarization");
        assert_eq!(
            category_from_label(&verdict.label),
            Some(IntentCategory::Summarization)
        );
    }

    /// The counting-in-process pattern from
    /// `sbproxy-classifier-client/src/fallback.rs`'s own tests, applied
    /// at this hook's level rather than `FallbackClassifier`'s: proves
    /// the degrade path actually runs the heuristic exactly once per
    /// call when the sidecar is unreachable, rather than merely
    /// returning a plausible-looking category.
    #[tokio::test]
    async fn degrade_path_invokes_heuristic_exactly_once() {
        struct CountingHeuristic(Arc<AtomicUsize>);
        impl InProcessClassifier for CountingHeuristic {
            fn classify(&self, text: &str) -> Verdict {
                self.0.fetch_add(1, Ordering::SeqCst);
                let category: IntentCategory = detect_intent_heuristic(text).into();
                Verdict {
                    label: intent_label(category).to_string(),
                    score: 1.0,
                }
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let dead_client =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let inner = FallbackClassifier::new(
            Some(dead_client),
            "intent",
            CountingHeuristic(Arc::clone(&calls)),
        );
        let verdict = inner.classify("describe this screenshot").await;
        assert_eq!(verdict.label, "vision");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
