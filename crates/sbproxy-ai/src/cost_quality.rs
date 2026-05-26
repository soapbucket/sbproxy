//! Cost/quality routing (WOR-797).
//!
//! Routes a request to a cheap model when its prompt looks simple and to
//! a frontier model when it looks hard, trading cost against quality on a
//! single `cost_threshold` dial (RouteLLM-style calibration). The default
//! difficulty scorer is a deterministic heuristic over prompt features;
//! a learned scorer (ONNX or embedding + matrix factorization, via
//! `sbproxy-classifiers`) is a planned follow-up that plugs in behind the
//! same `route_tier` decision.
//!
//! This complements the existing [`crate::routing::RoutingStrategy::Cascade`]
//! (FrugalGPT-style escalate-on-low-confidence): cascade reacts to the
//! response, cost/quality routing decides up front from the prompt.

use serde::Deserialize;

/// Configuration for the cost/quality routing strategy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CostQualityConfig {
    /// Provider name (in `AiHandlerConfig::providers`) used for prompts
    /// scored at or below `cost_threshold` (the cheap tier).
    pub cheap_provider: String,
    /// Provider name used for prompts scored above `cost_threshold` (the
    /// frontier tier).
    pub frontier_provider: String,
    /// Difficulty dial in `[0.0, 1.0]`. A prompt whose difficulty score
    /// strictly exceeds this value routes to `frontier_provider`;
    /// otherwise to `cheap_provider`. `0.0` sends almost everything to
    /// the frontier (max quality, max cost); `1.0` sends everything to
    /// the cheap model (max savings). Defaults to `0.5`.
    #[serde(default = "default_cost_threshold")]
    pub cost_threshold: f32,
}

fn default_cost_threshold() -> f32 {
    0.5
}

/// The tier a request is routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The cheap model (simple prompt).
    Cheap,
    /// The frontier model (hard prompt).
    Frontier,
}

impl Tier {
    /// Lowercase label used in metrics and the routing-decision header.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Cheap => "cheap",
            Tier::Frontier => "frontier",
        }
    }
}

/// Decide the tier for a difficulty score under a config. A score
/// strictly greater than `cost_threshold` escalates to the frontier.
pub fn route_tier(cfg: &CostQualityConfig, difficulty: f32) -> Tier {
    if difficulty > cfg.cost_threshold {
        Tier::Frontier
    } else {
        Tier::Cheap
    }
}

/// Deterministic heuristic prompt-difficulty score in `[0.0, 1.0]`.
///
/// Low scores mean "simple, route cheap"; high scores mean "hard, route
/// frontier". The score blends prompt length with three difficulty
/// signals (code, mathematical/proof content, multi-step reasoning).
/// It is intentionally cheap and dependency-free; a learned scorer is a
/// follow-up. The output is clamped to `[0.0, 1.0]`.
pub fn heuristic_difficulty(prompt: &str) -> f32 {
    let lower = prompt.to_lowercase();
    let words = prompt.split_whitespace().count();

    // Length: a 200-word prompt saturates the length contribution.
    let length_score = (words as f32 / 200.0).min(1.0);

    let has_code = prompt.contains("```")
        || [
            "fn ",
            "def ",
            "class ",
            "import ",
            "select ",
            "function ",
            "public ",
            "#include",
        ]
        .iter()
        .any(|kw| lower.contains(kw));

    let has_math = ['∫', '∑', '√', '∂', '≈', '≤', '≥']
        .iter()
        .any(|c| prompt.contains(*c))
        || [
            "theorem",
            "integral",
            "derivative",
            "equation",
            "prove that",
            "matrix",
        ]
        .iter()
        .any(|kw| lower.contains(kw));

    let has_reasoning = [
        "step by step",
        "step-by-step",
        "explain why",
        "analyze",
        "reason about",
        "prove",
        "derive",
        "compare and contrast",
        "trade-off",
        "tradeoff",
        "design a",
        "design an",
    ]
    .iter()
    .any(|kw| lower.contains(kw));

    let mut score = 0.5 * length_score;
    if has_code {
        score += 0.25;
    }
    if has_math {
        score += 0.15;
    }
    if has_reasoning {
        score += 0.2;
    }
    score.clamp(0.0, 1.0)
}

/// Best-effort extraction of the user-facing prompt text from a chat or
/// completion request body, for difficulty scoring. Concatenates string
/// message contents (and the `text` parts of array-shaped content);
/// falls back to a top-level `prompt` or `input` string.
pub fn prompt_text_for_scoring(body: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(msgs) = body.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            match m.get("content") {
                Some(serde_json::Value::String(s)) => {
                    out.push_str(s);
                    out.push(' ');
                }
                Some(serde_json::Value::Array(parts)) => {
                    for p in parts {
                        if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                            out.push_str(t);
                            out.push(' ');
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if out.trim().is_empty() {
        if let Some(s) = body.get("prompt").and_then(|v| v.as_str()) {
            out.push_str(s);
        } else if let Some(s) = body.get("input").and_then(|v| v.as_str()) {
            out.push_str(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: f32) -> CostQualityConfig {
        CostQualityConfig {
            cheap_provider: "cheap".to_string(),
            frontier_provider: "frontier".to_string(),
            cost_threshold: threshold,
        }
    }

    #[test]
    fn short_simple_prompt_scores_low() {
        let d = heuristic_difficulty("hi there");
        assert!(d < 0.3, "simple greeting should score low, got {d}");
        assert_eq!(route_tier(&cfg(0.5), d), Tier::Cheap);
    }

    #[test]
    fn long_reasoning_code_prompt_scores_high() {
        let prompt = format!(
            "Please analyze the following and explain why it is correct, step by step. \
             Prove that the approach terminates. ```rust\nfn solve() {{}}\n``` {}",
            "word ".repeat(200)
        );
        let d = heuristic_difficulty(&prompt);
        assert!(d > 0.5, "hard prompt should score high, got {d}");
        assert_eq!(route_tier(&cfg(0.5), d), Tier::Frontier);
    }

    #[test]
    fn threshold_one_always_routes_cheap() {
        // Even a maximally hard prompt stays cheap when the dial is 1.0.
        let d = 1.0;
        assert_eq!(route_tier(&cfg(1.0), d), Tier::Cheap);
    }

    #[test]
    fn threshold_zero_routes_any_nonzero_difficulty_to_frontier() {
        let d = heuristic_difficulty("import os"); // has_code -> > 0
        assert!(d > 0.0);
        assert_eq!(route_tier(&cfg(0.0), d), Tier::Frontier);
    }

    #[test]
    fn score_is_clamped_to_unit_interval() {
        let prompt = format!(
            "prove the theorem, derive the integral, step by step ```code``` {}",
            "w ".repeat(500)
        );
        let d = heuristic_difficulty(&prompt);
        assert!((0.0..=1.0).contains(&d), "score out of range: {d}");
    }

    #[test]
    fn default_threshold_is_half() {
        let parsed: CostQualityConfig = serde_json::from_value(serde_json::json!({
            "cheap_provider": "c",
            "frontier_provider": "f"
        }))
        .unwrap();
        assert_eq!(parsed.cost_threshold, 0.5);
    }

    #[test]
    fn prompt_extractor_handles_messages_and_fallbacks() {
        let chat = serde_json::json!({
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "what is 2+2"}
            ]
        });
        let t = prompt_text_for_scoring(&chat);
        assert!(t.contains("be terse") && t.contains("what is 2+2"));

        let parts = serde_json::json!({
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        });
        assert!(prompt_text_for_scoring(&parts).contains("hello"));

        let completion = serde_json::json!({"prompt": "legacy prompt"});
        assert_eq!(prompt_text_for_scoring(&completion).trim(), "legacy prompt");
    }
}
