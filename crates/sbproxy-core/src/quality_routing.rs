//! Quality-based provider routing.
//!
//! Port of `sbproxy-enterprise-ai::quality_routing` (WOR-2672). Routes
//! requests to the AI provider with the highest quality score that meets
//! a configurable minimum threshold.
//!
//! Two selection entrypoints are exposed:
//!
//! - [`select_by_quality`] is a pure synchronous helper over a slice of
//!   pre-computed [`QualityScore`] values. It is used by unit tests and
//!   any caller that already has scores in hand.
//! - [`select_by_quality_async`] is the entrypoint a provider-selection
//!   call site plugs in. It accepts an optional
//!   [`crate::hooks::QualityScoringHook`] and, when present, asks it to
//!   score each candidate provider (typically via a classifier sidecar).
//!   On any failure it falls back to the first candidate so routing never
//!   hard-fails.
//!
//! # This hook has a slot but no caller yet
//!
//! [`crate::hooks::Hooks::quality_scoring`] is a real slot on the
//! pipeline's hook bundle, but as of this port nothing in
//! [`crate::server::ai_dispatch`] or elsewhere calls
//! `QualityScoringHook::score_providers` (confirmed by grepping the
//! request path: only the trait definition and two `is_none()` tests
//! reference it). That is unlike [`crate::intent_detection`], whose hook
//! is dispatched live. This module is therefore shipped as the reusable
//! routing-decision library the epic asked for; wiring
//! `select_by_quality_async` into an actual provider-candidate call site
//! in [`crate::server::ai_dispatch`] is follow-up work, not assumed by
//! this port. A future caller reaches this exactly the way
//! [`crate::intent_detection::detect_intent_async`] is reached today.

use std::sync::Arc;

use crate::hooks::{QualityRequest, QualityScoringHook};

// --- Types ---

/// A quality assessment for a single provider.
#[derive(Debug, Clone)]
pub struct QualityScore {
    /// Provider identifier (e.g. "openai", "anthropic", "cohere").
    pub provider: String,
    /// Quality score, typically in [0.0, 1.0] but unconstrained.
    pub score: f64,
}

impl QualityScore {
    /// Create a new quality score entry.
    pub fn new(provider: impl Into<String>, score: f64) -> Self {
        Self {
            provider: provider.into(),
            score,
        }
    }
}

// --- Selection logic ---

/// Select the provider with the highest quality score that is at or above
/// `min_threshold`. Returns `None` when no provider meets the threshold or
/// the slice is empty.
pub fn select_by_quality(scores: &[QualityScore], min_threshold: f64) -> Option<&str> {
    scores
        .iter()
        .filter(|s| s.score >= min_threshold)
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| s.provider.as_str())
}

/// Select the top-N providers by quality score, all meeting `min_threshold`.
/// Results are ordered from highest to lowest score.
pub fn top_providers(scores: &[QualityScore], min_threshold: f64, n: usize) -> Vec<&str> {
    let mut filtered: Vec<&QualityScore> =
        scores.iter().filter(|s| s.score >= min_threshold).collect();
    filtered.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    filtered
        .into_iter()
        .take(n)
        .map(|s| s.provider.as_str())
        .collect()
}

// --- Async hook-driven selection ---

/// Request-path entrypoint for quality-based routing.
///
/// When `hook` is `Some`, we ask it to score every provider in
/// `req.candidate_providers` and pick the highest-scoring one at or above
/// `min_threshold`. When the hook is absent, returns `None`, yields an
/// empty score vector, or leaves no provider above the threshold, we fall
/// back to the first candidate in the input list. This keeps routing
/// deterministic and strictly fail-open: a broken classifier never blocks
/// a request from reaching an upstream.
///
/// Returns an owned `String` (rather than a borrowed `&str`) because the
/// selected provider name is pulled from an inner response owned by the
/// function.
pub async fn select_by_quality_async(
    hook: Option<&Arc<dyn QualityScoringHook>>,
    req: QualityRequest,
    min_threshold: f64,
) -> Option<String> {
    // --- Hook path ---
    //
    // Ask the hook for per-provider scores. `Some(vec)` means success;
    // `None` signals a classifier-side failure and we fall through to
    // the default selection below.
    if let Some(h) = hook {
        if let Some(scores) = h.score_providers(&req).await {
            // Pick the highest score at or above the threshold. Ties are
            // broken by input order (max_by is stable for equal keys).
            let picked = scores
                .into_iter()
                .filter(|s| s.score >= min_threshold)
                .max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            if let Some(s) = picked {
                return Some(s.provider);
            }
            // Hook succeeded but nothing cleared the threshold: drop
            // through to the fallback so the request still routes.
        }
    }

    // --- Fallback ---
    //
    // No hook, hook failed, or no candidate above threshold. Return the
    // first candidate so the caller has a deterministic target. An empty
    // candidate list yields None (nothing to route to).
    req.candidate_providers.into_iter().next()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scores() -> Vec<QualityScore> {
        vec![
            QualityScore::new("openai", 0.85),
            QualityScore::new("anthropic", 0.92),
            QualityScore::new("cohere", 0.70),
            QualityScore::new("mistral", 0.60),
        ]
    }

    #[test]
    fn selects_highest_scoring_provider() {
        let scores = sample_scores();
        assert_eq!(select_by_quality(&scores, 0.0), Some("anthropic"));
    }

    #[test]
    fn threshold_filters_out_low_scorers() {
        let scores = sample_scores();
        // cohere (0.70) and mistral (0.60) are below 0.80
        let selected = select_by_quality(&scores, 0.80);
        assert!(matches!(selected, Some("anthropic") | Some("openai")));
        // Specifically anthropic wins as highest above 0.80
        assert_eq!(selected, Some("anthropic"));
    }

    #[test]
    fn threshold_at_exact_score_is_inclusive() {
        let scores = vec![
            QualityScore::new("alpha", 0.75),
            QualityScore::new("beta", 0.50),
        ];
        assert_eq!(select_by_quality(&scores, 0.75), Some("alpha"));
    }

    #[test]
    fn returns_none_when_all_below_threshold() {
        let scores = sample_scores();
        assert_eq!(select_by_quality(&scores, 0.99), None);
    }

    #[test]
    fn returns_none_for_empty_slice() {
        assert_eq!(select_by_quality(&[], 0.0), None);
    }

    #[test]
    fn single_provider_above_threshold_is_selected() {
        let scores = vec![QualityScore::new("only", 0.80)];
        assert_eq!(select_by_quality(&scores, 0.50), Some("only"));
    }

    #[test]
    fn single_provider_below_threshold_returns_none() {
        let scores = vec![QualityScore::new("only", 0.40)];
        assert_eq!(select_by_quality(&scores, 0.50), None);
    }

    #[test]
    fn top_providers_returns_sorted_results() {
        let scores = sample_scores();
        let top = top_providers(&scores, 0.0, 2);
        assert_eq!(top, vec!["anthropic", "openai"]);
    }

    #[test]
    fn top_providers_respects_threshold() {
        let scores = sample_scores();
        // Only anthropic (0.92) and openai (0.85) are above 0.80
        let top = top_providers(&scores, 0.80, 10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], "anthropic");
    }

    #[test]
    fn top_providers_empty_when_none_qualify() {
        let scores = sample_scores();
        assert!(top_providers(&scores, 0.99, 5).is_empty());
    }

    // --- Async selector ---

    use crate::hooks::{QualityScore as HookScore, QualityScoringHook};
    use async_trait::async_trait;

    /// Hook stub that returns a fixed score map keyed by provider name.
    struct StubHook {
        verdict: Option<Vec<HookScore>>,
    }

    #[async_trait]
    impl QualityScoringHook for StubHook {
        async fn score_providers(&self, _req: &QualityRequest) -> Option<Vec<HookScore>> {
            self.verdict.clone()
        }
    }

    fn mk_req(candidates: &[&str]) -> QualityRequest {
        QualityRequest {
            origin: "example.com".into(),
            model_id: None,
            prompt: "hello".into(),
            candidate_providers: candidates.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn async_picks_highest_scoring_provider_from_hook() {
        let hook: Arc<dyn QualityScoringHook> = Arc::new(StubHook {
            verdict: Some(vec![
                HookScore {
                    provider: "openai".into(),
                    score: 0.70,
                },
                HookScore {
                    provider: "anthropic".into(),
                    score: 0.92,
                },
            ]),
        });
        let got = select_by_quality_async(Some(&hook), mk_req(&["openai", "anthropic"]), 0.0).await;
        assert_eq!(got.as_deref(), Some("anthropic"));
    }

    #[tokio::test]
    async fn async_falls_back_when_hook_returns_none() {
        let hook: Arc<dyn QualityScoringHook> = Arc::new(StubHook { verdict: None });
        let got = select_by_quality_async(Some(&hook), mk_req(&["openai", "anthropic"]), 0.0).await;
        // Fail-open: first candidate wins.
        assert_eq!(got.as_deref(), Some("openai"));
    }

    #[tokio::test]
    async fn async_falls_back_when_threshold_excludes_all() {
        let hook: Arc<dyn QualityScoringHook> = Arc::new(StubHook {
            verdict: Some(vec![
                HookScore {
                    provider: "openai".into(),
                    score: 0.10,
                },
                HookScore {
                    provider: "anthropic".into(),
                    score: 0.20,
                },
            ]),
        });
        let got =
            select_by_quality_async(Some(&hook), mk_req(&["openai", "anthropic"]), 0.99).await;
        // None cleared 0.99; fall back to first candidate.
        assert_eq!(got.as_deref(), Some("openai"));
    }

    #[tokio::test]
    async fn async_returns_first_candidate_when_hook_absent() {
        let got = select_by_quality_async(None, mk_req(&["cohere", "mistral"]), 0.50).await;
        assert_eq!(got.as_deref(), Some("cohere"));
    }

    #[tokio::test]
    async fn async_returns_none_when_no_candidates_and_no_hook() {
        let got = select_by_quality_async(None, mk_req(&[]), 0.0).await;
        assert_eq!(got, None);
    }
}
