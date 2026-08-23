//! Custom evaluation metrics for AI response quality.
//!
//! Each `MetricType` variant encapsulates a self-contained pass/fail check
//! that can be applied to a model response string.

// --- Metric types ---

/// Built-in evaluation metrics that can be composed in evaluation pipelines.
pub enum MetricType {
    /// Response must match the provided regular expression.
    RegexMatch(String),
    /// Response must be JSON that validates against the provided JSON Schema.
    JsonSchemaValid(serde_json::Value),
    /// Response length in bytes must fall within the inclusive `[min, max]` range.
    LengthRange(usize, usize),
    /// Response must contain every keyword in the list.
    ContainsKeywords(Vec<String>),
}

// --- Evaluation ---

/// Evaluate a response string against a single metric.
///
/// Returns `true` when the response passes the metric check.
pub fn evaluate_metric(response: &str, metric: &MetricType) -> bool {
    match metric {
        MetricType::RegexMatch(pattern) => regex::Regex::new(pattern)
            .map(|r| r.is_match(response))
            .unwrap_or(false),
        MetricType::JsonSchemaValid(schema) => serde_json::from_str::<serde_json::Value>(response)
            .ok()
            .and_then(|instance| {
                jsonschema::JSONSchema::options()
                    .compile(schema)
                    .ok()
                    .map(|compiled| compiled.is_valid(&instance))
            })
            .unwrap_or(false),
        MetricType::LengthRange(min, max) => response.len() >= *min && response.len() <= *max,
        MetricType::ContainsKeywords(keywords) => {
            keywords.iter().all(|kw| response.contains(kw.as_str()))
        }
    }
}

/// Evaluate a response against multiple metrics and return per-metric results.
///
/// The returned vector has the same length and order as `metrics`.
pub fn evaluate_all(response: &str, metrics: &[MetricType]) -> Vec<bool> {
    metrics
        .iter()
        .map(|m| evaluate_metric(response, m))
        .collect()
}

/// Return the fraction of metrics passed (0.0..=1.0).
pub fn pass_rate(response: &str, metrics: &[MetricType]) -> f64 {
    if metrics.is_empty() {
        return 1.0;
    }
    let passed = evaluate_all(response, metrics)
        .iter()
        .filter(|&&p| p)
        .count();
    passed as f64 / metrics.len() as f64
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- RegexMatch ---

    #[test]
    fn regex_match_passes_when_pattern_matches() {
        let metric = MetricType::RegexMatch(r"\d{4}".to_string());
        assert!(evaluate_metric("year 2026", &metric));
    }

    #[test]
    fn regex_match_fails_when_pattern_does_not_match() {
        let metric = MetricType::RegexMatch(r"\d{4}".to_string());
        assert!(!evaluate_metric("no digits here", &metric));
    }

    #[test]
    fn regex_match_returns_false_for_invalid_pattern() {
        let metric = MetricType::RegexMatch("[invalid".to_string());
        assert!(!evaluate_metric("any text", &metric));
    }

    // --- JsonSchemaValid ---

    #[test]
    fn json_schema_valid_passes_for_valid_json() {
        let metric = MetricType::JsonSchemaValid(json!({}));
        assert!(evaluate_metric(r#"{"key": "value"}"#, &metric));
    }

    #[test]
    fn json_schema_valid_fails_for_invalid_json() {
        let metric = MetricType::JsonSchemaValid(json!({}));
        assert!(!evaluate_metric("not json", &metric));
    }

    #[test]
    fn json_schema_valid_enforces_required_properties() {
        let metric = MetricType::JsonSchemaValid(json!({
            "type": "object",
            "required": ["answer"],
            "properties": {"answer": {"type": "string"}}
        }));
        assert!(!evaluate_metric(r#"{}"#, &metric));
        assert!(evaluate_metric(r#"{"answer":"yes"}"#, &metric));
    }

    #[test]
    fn json_schema_valid_passes_for_json_array() {
        let metric = MetricType::JsonSchemaValid(json!({"type": "array"}));
        assert!(evaluate_metric("[1, 2, 3]", &metric));
    }

    // --- LengthRange ---

    #[test]
    fn length_range_passes_within_bounds() {
        let metric = MetricType::LengthRange(5, 20);
        assert!(evaluate_metric("hello world", &metric)); // 11 chars
    }

    #[test]
    fn length_range_passes_at_exact_bounds() {
        let metric = MetricType::LengthRange(5, 5);
        assert!(evaluate_metric("abcde", &metric));
    }

    #[test]
    fn length_range_fails_below_minimum() {
        let metric = MetricType::LengthRange(10, 20);
        assert!(!evaluate_metric("short", &metric)); // 5 chars
    }

    #[test]
    fn length_range_fails_above_maximum() {
        let metric = MetricType::LengthRange(0, 3);
        assert!(!evaluate_metric("toolong", &metric));
    }

    // --- ContainsKeywords ---

    #[test]
    fn contains_keywords_passes_when_all_present() {
        let metric = MetricType::ContainsKeywords(vec!["foo".to_string(), "bar".to_string()]);
        assert!(evaluate_metric("foo and bar are here", &metric));
    }

    #[test]
    fn contains_keywords_fails_when_one_missing() {
        let metric = MetricType::ContainsKeywords(vec!["foo".to_string(), "baz".to_string()]);
        assert!(!evaluate_metric("foo is here but not the other", &metric));
    }

    #[test]
    fn contains_keywords_empty_list_always_passes() {
        let metric = MetricType::ContainsKeywords(vec![]);
        assert!(evaluate_metric("anything", &metric));
    }

    // --- Pass rate ---

    #[test]
    fn pass_rate_full_when_all_pass() {
        let metrics = vec![
            MetricType::LengthRange(0, 100),
            MetricType::ContainsKeywords(vec!["hello".to_string()]),
        ];
        assert!((pass_rate("hello world", &metrics) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn pass_rate_zero_when_all_fail() {
        let metrics = vec![
            MetricType::LengthRange(1000, 2000),
            MetricType::ContainsKeywords(vec!["absent".to_string()]),
        ];
        assert!((pass_rate("short", &metrics)).abs() < 1e-9);
    }

    #[test]
    fn pass_rate_one_when_no_metrics() {
        assert!((pass_rate("anything", &[]) - 1.0).abs() < 1e-9);
    }
}
