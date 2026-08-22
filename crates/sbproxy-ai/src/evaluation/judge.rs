//! LLM-as-Judge evaluation framework.
//!
//! Builds structured judge prompts and parses numeric scores from a judge
//! model's JSON response. In production the prompt is submitted to the
//! configured `judge_model`; this module handles prompt construction and
//! response parsing only.

use std::collections::HashMap;

// --- Configuration ---

/// Configuration for the LLM judge.
#[derive(Debug, Clone)]
pub struct JudgeConfig {
    /// Model identifier to use as the judge (e.g. "gpt-4o", "claude-opus-4").
    pub judge_model: String,
    /// Criteria the judge should evaluate (e.g. "helpfulness", "accuracy").
    pub criteria: Vec<String>,
}

impl JudgeConfig {
    /// Create a new judge configuration.
    pub fn new(judge_model: impl Into<String>, criteria: Vec<String>) -> Self {
        Self {
            judge_model: judge_model.into(),
            criteria,
        }
    }
}

// --- Result types ---

/// Parsed output from a judge model evaluation.
#[derive(Debug, Clone)]
pub struct JudgeResult {
    /// Overall composite score (average of per-criterion scores).
    pub score: f64,
    /// Free-text reasoning provided by the judge.
    pub reasoning: String,
    /// Individual score for each evaluated criterion.
    pub criteria_scores: HashMap<String, f64>,
}

impl JudgeResult {
    /// Compute the composite score as the arithmetic mean of criteria scores.
    pub fn compute_composite(criteria_scores: HashMap<String, f64>, reasoning: String) -> Self {
        let score = if criteria_scores.is_empty() {
            0.0
        } else {
            criteria_scores.values().sum::<f64>() / criteria_scores.len() as f64
        };
        Self {
            score,
            reasoning,
            criteria_scores,
        }
    }
}

// --- Prompt building ---

/// Build a structured prompt asking the judge model to score `response` on
/// each of the provided `criteria`.
pub fn build_judge_prompt(response: &str, criteria: &[String]) -> String {
    format!(
        "Rate the following response on a scale of 1-10 for each criterion: {}.\n\n\
         Response:\n{}\n\n\
         Provide scores as JSON with the format: \
         {{\"scores\": {{\"<criterion>\": <number>}}, \"reasoning\": \"<text>\"}}.",
        criteria.join(", "),
        response
    )
}

// --- Response parsing ---

/// Parse a judge model's JSON response into a [`JudgeResult`].
///
/// Expected JSON shape:
/// ```json
/// {
///   "scores": { "helpfulness": 8, "accuracy": 7 },
///   "reasoning": "The response was clear but missed one detail."
/// }
/// ```
///
/// Returns `None` if the response cannot be parsed or contains no scores.
pub fn parse_judge_response(response: &str) -> Option<JudgeResult> {
    let value: serde_json::Value = serde_json::from_str(response.trim()).ok()?;
    let scores_map = value.get("scores")?.as_object()?;

    if scores_map.is_empty() {
        return None;
    }

    let mut criteria_scores = HashMap::new();
    for (key, val) in scores_map {
        let score = val.as_f64()?;
        criteria_scores.insert(key.clone(), score);
    }

    let reasoning = value
        .get("reasoning")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();

    Some(JudgeResult::compute_composite(criteria_scores, reasoning))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_judge_prompt_includes_response_and_criteria() {
        let criteria = vec!["helpfulness".to_string(), "accuracy".to_string()];
        let prompt = build_judge_prompt("Great answer!", &criteria);
        assert!(prompt.contains("helpfulness"));
        assert!(prompt.contains("accuracy"));
        assert!(prompt.contains("Great answer!"));
        assert!(prompt.contains("1-10"));
    }

    #[test]
    fn build_judge_prompt_with_empty_criteria() {
        let prompt = build_judge_prompt("Some response", &[]);
        assert!(prompt.contains("Some response"));
    }

    #[test]
    fn parse_judge_response_valid_json() {
        let json = r#"{"scores": {"helpfulness": 8, "accuracy": 7}, "reasoning": "Good overall."}"#;
        let result = parse_judge_response(json).expect("should parse");
        assert_eq!(result.criteria_scores["helpfulness"], 8.0);
        assert_eq!(result.criteria_scores["accuracy"], 7.0);
        assert_eq!(result.reasoning, "Good overall.");
        assert!((result.score - 7.5).abs() < 1e-9);
    }

    #[test]
    fn parse_judge_response_computes_average_score() {
        let json = r#"{"scores": {"a": 6, "b": 8, "c": 10}, "reasoning": ""}"#;
        let result = parse_judge_response(json).expect("should parse");
        assert!((result.score - 8.0).abs() < 1e-9);
    }

    #[test]
    fn parse_judge_response_missing_reasoning_defaults_to_empty() {
        let json = r#"{"scores": {"clarity": 9}}"#;
        let result = parse_judge_response(json).expect("should parse");
        assert_eq!(result.reasoning, "");
    }

    #[test]
    fn parse_judge_response_invalid_json_returns_none() {
        assert!(parse_judge_response("not json at all").is_none());
    }

    #[test]
    fn parse_judge_response_empty_scores_returns_none() {
        let json = r#"{"scores": {}, "reasoning": "nothing"}"#;
        assert!(parse_judge_response(json).is_none());
    }

    #[test]
    fn judge_config_stores_fields_correctly() {
        let cfg = JudgeConfig::new("gpt-4o", vec!["helpfulness".to_string()]);
        assert_eq!(cfg.judge_model, "gpt-4o");
        assert_eq!(cfg.criteria, vec!["helpfulness"]);
    }

    #[test]
    fn judge_result_compute_composite_single_criterion() {
        let mut scores = HashMap::new();
        scores.insert("quality".to_string(), 9.0);
        let result = JudgeResult::compute_composite(scores, "good".to_string());
        assert_eq!(result.score, 9.0);
    }
}
