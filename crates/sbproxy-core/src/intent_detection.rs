//! Semantic intent detection - classifies prompts into high-level categories.
//!
//! Port of `sbproxy-enterprise-ai::intent_detection` (WOR-2672). The
//! request path calls out to an external classifier sidecar via
//! [`crate::hooks::IntentDetectionHook`], dispatched from
//! `crate::server::ai_dispatch`. When no hook is registered (the
//! common OSS case) or the hook declines to decide (fail-open path on
//! RPC error, timeout, or an unreachable sidecar), callers fall back to
//! the local keyword heuristic in this module so intent detection never
//! goes silent.
//!
//! A stock SBproxy process installs a sidecar-backed implementation when
//! `proxy.classifier_hooks.intent` is configured. The hook is lazy, bounded
//! by the configured deadline, and reports a failed call as
//! [`crate::intent_detection::IntentSource::HeuristicDegraded`]; omitting the
//! config reports
//! [`crate::intent_detection::IntentSource::HeuristicUnconfigured`]. See
//! [`crate::intent_detection::detect_intent_async`] for exactly where it
//! plugs in, and `docs/ai-gateway.md`'s intent-detection section for the
//! operator-facing picture.
//!
//! # Two types, one concept
//!
//! This crate's own [`crate::hooks::IntentCategory`] is the wire type the
//! hook trait uses. This module historically (in the enterprise source)
//! carried its own [`crate::intent_detection::IntentCategory`] (with a
//! `Display` impl, non-`Copy`).
//! Both are retained here, and `From` conversions are provided in both
//! directions, so callers can pick whichever shape fits best with the
//! lowest churn.

use crate::hooks as core_hooks;

// --- Intent categories ---

/// High-level categories a user prompt can be classified into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentCategory {
    /// The user is asking for code generation, debugging, or programming help.
    Coding,
    /// The user is asking about an image or visual content.
    Vision,
    /// The user wants comparative, evaluative, or analytical reasoning.
    Analysis,
    /// The user wants a condensed version of a longer text.
    Summarization,
    /// No specific pattern matched; treated as a general query.
    General,
}

impl std::fmt::Display for IntentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Coding => write!(f, "coding"),
            Self::Vision => write!(f, "vision"),
            Self::Analysis => write!(f, "analysis"),
            Self::Summarization => write!(f, "summarization"),
            Self::General => write!(f, "general"),
        }
    }
}

// --- Conversions to/from the core hook type ---
//
// We keep the local enum for backward compatibility (`Display`, existing
// callers, re-export in `lib.rs`) and add lossless conversions to/from the
// OSS hook enum so the async path can return either shape without churn.

impl From<core_hooks::IntentCategory> for IntentCategory {
    fn from(v: core_hooks::IntentCategory) -> Self {
        match v {
            core_hooks::IntentCategory::Coding => Self::Coding,
            core_hooks::IntentCategory::Vision => Self::Vision,
            core_hooks::IntentCategory::Analysis => Self::Analysis,
            core_hooks::IntentCategory::Summarization => Self::Summarization,
            core_hooks::IntentCategory::General => Self::General,
        }
    }
}

impl From<IntentCategory> for core_hooks::IntentCategory {
    fn from(v: IntentCategory) -> Self {
        match v {
            IntentCategory::Coding => Self::Coding,
            IntentCategory::Vision => Self::Vision,
            IntentCategory::Analysis => Self::Analysis,
            IntentCategory::Summarization => Self::Summarization,
            IntentCategory::General => Self::General,
        }
    }
}

// --- Detection logic ---

/// Classify a prompt using keyword heuristics.
///
/// Checks are evaluated in priority order: Coding > Vision > Analysis >
/// Summarization > General. The first match wins.
///
/// This is the fallback used when the classifier sidecar is unreachable or
/// not configured. For async call sites that also want the sidecar path,
/// prefer [`detect_intent_async`].
pub fn detect_intent_heuristic(prompt: &str) -> IntentCategory {
    // Intent shows in a prompt's head. Bounding the lowercased window keeps
    // this hot-path fallback from allocating a full copy of an arbitrarily
    // large prompt (a 1 MiB chat body previously cost a 1 MiB allocation
    // plus ~30 linear scans here on every request).
    const MAX_HEURISTIC_SCAN_BYTES: usize = 8 * 1024;
    let lower = sbproxy_util::truncate_utf8(prompt, MAX_HEURISTIC_SCAN_BYTES).to_lowercase();

    if lower.contains("code")
        || lower.contains("function")
        || lower.contains("implement")
        || lower.contains("debug")
        || lower.contains("error in")
        || lower.contains("compile")
        || lower.contains("syntax")
        || lower.contains("refactor")
    {
        return IntentCategory::Coding;
    }

    if lower.contains("image")
        || lower.contains("picture")
        || lower.contains("photo")
        || lower.contains("describe what you see")
        || lower.contains("screenshot")
        || lower.contains("diagram")
    {
        return IntentCategory::Vision;
    }

    if lower.contains("analyze")
        || lower.contains("compare")
        || lower.contains("evaluate")
        || lower.contains("assess")
        || lower.contains("contrast")
        || lower.contains("examine")
    {
        return IntentCategory::Analysis;
    }

    if lower.contains("summarize")
        || lower.contains("summary")
        || lower.contains("tldr")
        || lower.contains("tl;dr")
        || lower.contains("brief")
        || lower.contains("condense")
        || lower.contains("key points")
    {
        return IntentCategory::Summarization;
    }

    IntentCategory::General
}

/// Sync convenience wrapper  -  delegates to [`detect_intent_heuristic`].
///
/// Kept as the original name so existing sync callers and the public
/// re-export in `lib.rs` keep working unchanged.
pub fn detect_intent(prompt: &str) -> IntentCategory {
    detect_intent_heuristic(prompt)
}

/// Async detection path that prefers the classifier sidecar hook and falls
/// back to [`detect_intent_heuristic`] on `None`.
///
/// Returns the OSS [`core_hooks::IntentCategory`] shape so the result can
/// flow straight into request-path code that speaks the hook vocabulary.
/// Use `.into()` to convert to the local [`IntentCategory`] if needed.
///
/// - Hook missing (OSS build): runs the heuristic.
/// - Hook present but returns `None` (RPC failure / fail-open): runs the
///   heuristic.
/// - Hook returns `Some(category)`: that category is used.
///
/// A thin wrapper over [`detect_intent_with_source`] for callers that do
/// not need to know which path answered.
pub async fn detect_intent_async(
    hook: Option<&std::sync::Arc<dyn core_hooks::IntentDetectionHook>>,
    prompt: &str,
) -> core_hooks::IntentCategory {
    detect_intent_with_source(hook, prompt).await.0
}

/// Which path produced an intent category: the registered sidecar hook,
/// or this module's local keyword heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentSource {
    /// A registered [`core_hooks::IntentDetectionHook`] returned `Some`.
    Hook,
    /// No hook was configured; [`detect_intent_heuristic`] answered.
    HeuristicUnconfigured,
    /// A configured hook returned `None` (fail-open), so
    /// [`detect_intent_heuristic`] answered during a degradation.
    HeuristicDegraded,
}

impl std::fmt::Display for IntentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hook => write!(f, "hook"),
            Self::HeuristicUnconfigured => write!(f, "heuristic"),
            Self::HeuristicDegraded => write!(f, "heuristic_degraded"),
        }
    }
}

/// Same detection path as [`detect_intent_async`], additionally reporting
/// which path answered (WOR-2672), so a call site can distinguish a live
/// classifier sidecar from the fallback heuristic for metrics and
/// structured logging without re-running detection.
pub async fn detect_intent_with_source(
    hook: Option<&std::sync::Arc<dyn core_hooks::IntentDetectionHook>>,
    prompt: &str,
) -> (core_hooks::IntentCategory, IntentSource) {
    let source = match hook {
        Some(h) => {
            if let Some(cat) = h.detect(prompt).await {
                return (cat, IntentSource::Hook);
            }
            IntentSource::HeuristicDegraded
        }
        None => IntentSource::HeuristicUnconfigured,
    };
    (detect_intent_heuristic(prompt).into(), source)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[test]
    fn detects_coding_from_code_keyword() {
        assert_eq!(
            detect_intent("Write some code to sort a list"),
            IntentCategory::Coding
        );
    }

    #[test]
    fn detects_coding_from_function_keyword() {
        assert_eq!(
            detect_intent("Create a function that reverses a string"),
            IntentCategory::Coding
        );
    }

    #[test]
    fn detects_coding_from_debug_keyword() {
        assert_eq!(
            detect_intent("Help me debug this crash"),
            IntentCategory::Coding
        );
    }

    #[test]
    fn detects_coding_from_implement_keyword() {
        assert_eq!(
            detect_intent("Implement a binary search tree in Rust"),
            IntentCategory::Coding
        );
    }

    #[test]
    fn detects_coding_from_error_in_phrase() {
        assert_eq!(
            detect_intent("There is an error in my script"),
            IntentCategory::Coding
        );
    }

    #[test]
    fn detects_vision_from_image_keyword() {
        assert_eq!(
            detect_intent("Describe this image for me"),
            IntentCategory::Vision
        );
    }

    #[test]
    fn detects_vision_from_picture_keyword() {
        assert_eq!(
            detect_intent("What is in this picture?"),
            IntentCategory::Vision
        );
    }

    #[test]
    fn detects_vision_from_photo_keyword() {
        assert_eq!(
            detect_intent("Can you look at this photo?"),
            IntentCategory::Vision
        );
    }

    #[test]
    fn detects_vision_from_describe_phrase() {
        assert_eq!(
            detect_intent("Describe what you see in this attachment"),
            IntentCategory::Vision
        );
    }

    #[test]
    fn detects_analysis_from_analyze_keyword() {
        assert_eq!(
            detect_intent("Analyze the market trends"),
            IntentCategory::Analysis
        );
    }

    #[test]
    fn detects_analysis_from_compare_keyword() {
        assert_eq!(
            detect_intent("Compare GPT-4 and Claude"),
            IntentCategory::Analysis
        );
    }

    #[test]
    fn detects_analysis_from_evaluate_keyword() {
        assert_eq!(
            detect_intent("Evaluate the pros and cons"),
            IntentCategory::Analysis
        );
    }

    #[test]
    fn detects_summarization_from_summarize_keyword() {
        assert_eq!(
            detect_intent("Summarize this article"),
            IntentCategory::Summarization
        );
    }

    #[test]
    fn detects_summarization_from_summary_keyword() {
        assert_eq!(
            detect_intent("Give me a summary of the meeting notes"),
            IntentCategory::Summarization
        );
    }

    #[test]
    fn detects_summarization_from_tldr_keyword() {
        assert_eq!(
            detect_intent("TL;DR this report"),
            IntentCategory::Summarization
        );
    }

    #[test]
    fn detects_summarization_from_brief_keyword() {
        assert_eq!(
            detect_intent("Give me a brief on the situation"),
            IntentCategory::Summarization
        );
    }

    #[test]
    fn falls_back_to_general() {
        assert_eq!(
            detect_intent("What is the capital of France?"),
            IntentCategory::General
        );
    }

    #[test]
    fn general_for_empty_prompt() {
        assert_eq!(detect_intent(""), IntentCategory::General);
    }

    #[test]
    fn case_insensitive_detection() {
        assert_eq!(
            detect_intent("SUMMARIZE this text"),
            IntentCategory::Summarization
        );
        assert_eq!(detect_intent("ANALYZE the data"), IntentCategory::Analysis);
    }

    #[test]
    fn display_shows_lowercase_name() {
        assert_eq!(IntentCategory::Coding.to_string(), "coding");
        assert_eq!(IntentCategory::General.to_string(), "general");
    }

    #[test]
    fn heuristic_alias_matches_detect_intent() {
        // detect_intent is the public sync API; detect_intent_heuristic is
        // the same function surfaced under its new descriptive name.
        assert_eq!(
            detect_intent("Write code"),
            detect_intent_heuristic("Write code")
        );
    }

    #[test]
    fn local_to_core_conversion_roundtrips() {
        for cat in [
            IntentCategory::Coding,
            IntentCategory::Vision,
            IntentCategory::Analysis,
            IntentCategory::Summarization,
            IntentCategory::General,
        ] {
            let core: core_hooks::IntentCategory = cat.clone().into();
            let back: IntentCategory = core.into();
            assert_eq!(cat, back);
        }
    }

    // --- async path tests ---

    /// Hook that always returns a fixed category  -  used to verify the hook
    /// path takes priority over the heuristic.
    struct FixedHook(core_hooks::IntentCategory);

    #[async_trait]
    impl core_hooks::IntentDetectionHook for FixedHook {
        async fn detect(&self, _: &str) -> Option<core_hooks::IntentCategory> {
            Some(self.0)
        }
    }

    /// Hook that always returns `None`  -  used to verify fail-open falls
    /// through to the heuristic path.
    struct FailOpenHook;

    #[async_trait]
    impl core_hooks::IntentDetectionHook for FailOpenHook {
        async fn detect(&self, _: &str) -> Option<core_hooks::IntentCategory> {
            None
        }
    }

    #[tokio::test]
    async fn async_with_no_hook_uses_heuristic() {
        let got = detect_intent_async(None, "Summarize this").await;
        assert_eq!(got, core_hooks::IntentCategory::Summarization);
    }

    #[tokio::test]
    async fn async_fail_open_falls_back_to_heuristic() {
        let hook: Arc<dyn core_hooks::IntentDetectionHook> = Arc::new(FailOpenHook);
        let got = detect_intent_async(Some(&hook), "Summarize this").await;
        assert_eq!(got, core_hooks::IntentCategory::Summarization);
    }

    #[tokio::test]
    async fn async_uses_hook_when_some() {
        let hook: Arc<dyn core_hooks::IntentDetectionHook> =
            Arc::new(FixedHook(core_hooks::IntentCategory::Analysis));
        // Heuristic would say "Coding" here; hook overrides.
        let got = detect_intent_async(Some(&hook), "write code").await;
        assert_eq!(got, core_hooks::IntentCategory::Analysis);
    }

    // --- source-reporting path (WOR-2672) ---

    #[tokio::test]
    async fn source_is_heuristic_when_no_hook_registered() {
        let (cat, source) = detect_intent_with_source(None, "Summarize this").await;
        assert_eq!(cat, core_hooks::IntentCategory::Summarization);
        assert_eq!(source, IntentSource::HeuristicUnconfigured);
    }

    #[tokio::test]
    async fn source_is_heuristic_when_hook_declines() {
        // This is the case a naive `hook.is_some()` check gets wrong: a
        // hook IS registered, but it fails open, so the category that
        // comes back is still the heuristic's. The source has to say so.
        let hook: Arc<dyn core_hooks::IntentDetectionHook> = Arc::new(FailOpenHook);
        let (cat, source) = detect_intent_with_source(Some(&hook), "write code").await;
        assert_eq!(cat, core_hooks::IntentCategory::Coding);
        assert_eq!(source, IntentSource::HeuristicDegraded);
    }

    #[tokio::test]
    async fn source_is_hook_when_hook_answers() {
        let hook: Arc<dyn core_hooks::IntentDetectionHook> =
            Arc::new(FixedHook(core_hooks::IntentCategory::Analysis));
        let (cat, source) = detect_intent_with_source(Some(&hook), "write code").await;
        assert_eq!(cat, core_hooks::IntentCategory::Analysis);
        assert_eq!(source, IntentSource::Hook);
    }

    #[test]
    fn intent_source_display_matches_metric_label_convention() {
        assert_eq!(IntentSource::Hook.to_string(), "hook");
        assert_eq!(IntentSource::HeuristicUnconfigured.to_string(), "heuristic");
        assert_eq!(
            IntentSource::HeuristicDegraded.to_string(),
            "heuristic_degraded"
        );
    }
}
