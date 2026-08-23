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
//! # `QualityScoringHook` is deliberately not built here
//!
//! The sidecar's `quality` RPC ([`sbproxy_classifier_client::ClassifierClient::quality`])
//! scores the *quality of a completed response text* (hedging, coherence,
//! repetition, length: see `crates/sbproxy-classifier/src/quality.rs`),
//! which answers a different question than
//! [`crate::hooks::QualityScoringHook::score_providers`] asks: "which of
//! these *not-yet-called* providers should this prompt route to." There
//! is no text to score before a provider has answered, so wiring the
//! sidecar's `quality` RPC into `QualityScoringHook` would mean scoring
//! the prompt itself and calling it a provider verdict, which is not
//! what the signal measures. An operator who wants sidecar-informed
//! provider routing implements `QualityScoringHook` directly against
//! whatever provider-reputation or cost signal they have; the seam
//! ([`crate::quality_routing`]) does not require a classifier-shaped
//! backend the way intent detection naturally does.

use async_trait::async_trait;
use sbproxy_classifier_client::{
    ClassifierClient, FallbackClassifier, InProcessClassifier, Verdict,
};

use crate::hooks::{IntentCategory, IntentDetectionHook};
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
