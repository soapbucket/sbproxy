//! Runnable demonstration of the intent-detection hook-or-heuristic
//! fallback and quality-based routing (WOR-2672), the two AI gateway
//! extras that live in `sbproxy-core` because they consume its hook
//! traits directly.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p sbproxy-core --example intent_detection_fallback
//! ```
//!
//! Walks through the two cases [`sbproxy_core::intent_detection::detect_intent_with_source`]
//! covers, printing which path answered each prompt:
//!
//! 1. No hook registered at all - the common OSS case for a deployment
//!    that never wired a classifier sidecar behind `IntentDetectionHook`.
//! 2. A hook that answers for some prompts and declines (fail-open) for
//!    others, matching how a sidecar-backed hook behaves when it is
//!    unreachable for a subset of traffic.
//!
//! Then demonstrates `sbproxy_core::quality_routing`'s pure synchronous
//! selection helpers and its async, hook-driven, fail-open entrypoint.

use async_trait::async_trait;
use sbproxy_core::hooks::{IntentCategory, IntentDetectionHook, QualityRequest};
use sbproxy_core::intent_detection::{
    detect_intent_heuristic, detect_intent_with_source, IntentSource,
};
use sbproxy_core::quality_routing::{
    select_by_quality, select_by_quality_async, top_providers, QualityScore,
};
use std::sync::Arc;

const PROMPTS: &[&str] = &[
    "Please review this code snippet for bugs",
    "Describe this image for me",
    "What is the capital of France?",
];

/// Stand-in for a sidecar-backed hook: answers `Coding` for anything that
/// contains "code", declines everything else. A real implementation would
/// call out to the classifier sidecar via `sbproxy-classifier-client`'s
/// `FallbackClassifier` (see `docs/classifier-sidecar.md`) rather than
/// hardcoding a rule.
struct PartialHook;

#[async_trait]
impl IntentDetectionHook for PartialHook {
    async fn detect(&self, prompt: &str) -> Option<IntentCategory> {
        if prompt.to_lowercase().contains("code") {
            Some(IntentCategory::Coding)
        } else {
            None
        }
    }
}

#[tokio::main]
async fn main() {
    println!("--- No hook registered (the common OSS case) ---");
    for prompt in PROMPTS {
        let (category, source) = detect_intent_with_source(None, prompt).await;
        println!("{source:>9} -> {category:?}  {prompt:?}");
    }

    println!("\n--- A hook that answers for some prompts, declines for others ---");
    let hook: Arc<dyn IntentDetectionHook> = Arc::new(PartialHook);
    for prompt in PROMPTS {
        let (category, source): (IntentCategory, IntentSource) =
            detect_intent_with_source(Some(&hook), prompt).await;
        println!("{source:>9} -> {category:?}  {prompt:?}");
    }

    println!("\n--- The synchronous heuristic alone (no hook plumbing at all) ---");
    for prompt in PROMPTS {
        println!("{:?}  {prompt:?}", detect_intent_heuristic(prompt));
    }

    // --- Quality-based routing: sync helpers ---
    println!("\n--- Quality routing: sync selection over pre-computed scores ---");
    let scores = vec![
        QualityScore::new("openai", 0.85),
        QualityScore::new("anthropic", 0.92),
        QualityScore::new("cohere", 0.60),
    ];
    println!("Best above 0.80: {:?}", select_by_quality(&scores, 0.80));
    println!("Top 2 above 0.0: {:?}", top_providers(&scores, 0.0, 2));

    // --- Quality-based routing: the async, hook-driven, fail-open entrypoint ---
    println!("\n--- Quality routing: no hook registered, falls back to the first candidate ---");
    let req = QualityRequest {
        origin: "api.example.com".to_string(),
        model_id: None,
        prompt: "Summarize the quarterly earnings call".to_string(),
        candidate_providers: vec!["openai".to_string(), "anthropic".to_string()],
    };
    let picked = select_by_quality_async(None, req, 0.75).await;
    println!("Picked (no hook, deterministic first candidate): {picked:?}");
}
