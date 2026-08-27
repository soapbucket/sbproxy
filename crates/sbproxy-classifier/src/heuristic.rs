//! Heuristic text classification: given input text and a top-k number,
//! return the most likely labels with scores.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `classify.rs`.
//! The enterprise crate also carries an ONNX backend behind this same
//! facade, built on `ort` (Microsoft ONNX Runtime). This port drops that
//! backend rather than porting it: the rest of this OSS workspace already
//! standardizes on the pure-Rust `tract-onnx` runtime via
//! `sbproxy_classifiers::OnnxClassifier` (used by the in-process detectors
//! and by the minimal classifier sidecar), and pulling in `ort` as a second
//! ONNX engine for one crate would leave two runtimes to patch, license, and
//! keep in sync. ONNX-backed classification in this sidecar is served
//! separately, over the shared `InferenceService` gRPC contract (see
//! `crate::grpc`), reusing `OnnxClassifier` directly. This module is the
//! heuristic, per-tenant path served over TCP.
//!
//! ## Regex safety
//!
//! All user-supplied patterns are validated with `RegexBuilder::size_limit`,
//! under the same per-pattern ceiling `crate::registry` charges to the
//! process-wide compiled-program budget. Rust's `regex` crate uses NFA
//! execution with no backtracking, so ReDoS CPU attacks are not possible; the
//! size limit prevents memory exhaustion from pathological patterns. Patterns
//! longer than `MAX_PATTERN_LENGTH` bytes are rejected outright.

#[cfg(test)]
use crate::config::LabelConfig;
use crate::protocol::Label;
use regex::Regex;
#[cfg(test)]
use regex::RegexBuilder;
#[cfg(test)]
use tracing::warn;

/// Max pattern string length before it is rejected outright.
#[cfg(test)]
const MAX_PATTERN_LENGTH: usize = 4096;

/// Compiled label with pre-built regex patterns.
pub(crate) struct CompiledLabel {
    name: String,
    weight: f64,
    regexes: Vec<Regex>,
}

impl CompiledLabel {
    /// Wrap already-compiled patterns. The only production constructor:
    /// `crate::registry::compile_enabled_regexes` compiles each pattern once,
    /// under the charged per-pattern ceiling, and hands the programs here.
    pub(crate) fn new(name: String, weight: f64, regexes: Vec<Regex>) -> Self {
        Self {
            name,
            weight,
            regexes,
        }
    }
}

/// A compiled, per-tenant heuristic classifier.
pub struct Classifier {
    labels: Vec<CompiledLabel>,
    confidence_threshold: f64,
    default_label: String,
    default_boost: f64,
}

impl Classifier {
    /// Assemble a classifier from already-compiled labels.
    pub(crate) fn from_compiled(
        labels: Vec<CompiledLabel>,
        confidence_threshold: f64,
        default_label: &str,
        default_boost: f64,
    ) -> Self {
        Self {
            labels,
            confidence_threshold,
            default_label: default_label.to_string(),
            default_boost,
        }
    }

    /// Create a heuristic classifier from label configs and classification
    /// params, compiling every pattern here.
    ///
    /// Test-only: production compiles once in `crate::registry` and calls
    /// [`Classifier::from_compiled`], so a registered tenant never pays for
    /// two compiles of the same pattern set. It compiles under the registry's
    /// charged per-pattern ceiling, not a larger test-only one, so a pattern
    /// a test here proves compiles is one registration would admit too.
    #[cfg(test)]
    fn from_labels(
        label_configs: &[LabelConfig],
        confidence_threshold: f64,
        default_label: &str,
        default_boost: f64,
    ) -> Self {
        let labels = label_configs
            .iter()
            .map(|lc| {
                let regexes = lc
                    .patterns
                    .iter()
                    .filter_map(|p| {
                        if p.len() > MAX_PATTERN_LENGTH {
                            warn!(label = %lc.name, len = p.len(), "regex pattern too long (max {}), skipping", MAX_PATTERN_LENGTH);
                            return None;
                        }
                        match RegexBuilder::new(p)
                            .size_limit(crate::registry::CLASSIFIER_PATTERN_SIZE_LIMIT)
                            .build()
                        {
                            Ok(r) => Some(r),
                            Err(e) => {
                                warn!(label = %lc.name, pattern = %p, error = %e, "invalid regex, skipping");
                                None
                            }
                        }
                    })
                    .collect();

                CompiledLabel {
                    name: lc.name.clone(),
                    weight: lc.weight,
                    regexes,
                }
            })
            .collect();

        Self::from_compiled(labels, confidence_threshold, default_label, default_boost)
    }

    /// Returns the label names this classifier knows about.
    pub fn label_names(&self) -> Vec<String> {
        self.labels.iter().map(|l| l.name.clone()).collect()
    }

    /// Classify a prompt, returning the top-k labels with scores.
    pub fn classify(&self, text: &str, top_k: usize) -> Vec<Label> {
        heuristic_classify(
            &self.labels,
            text,
            top_k,
            self.confidence_threshold,
            &self.default_label,
            self.default_boost,
        )
    }
}

fn heuristic_classify(
    labels: &[CompiledLabel],
    text: &str,
    top_k: usize,
    confidence_threshold: f64,
    default_label: &str,
    default_boost: f64,
) -> Vec<Label> {
    let mut scores: Vec<(&str, f64)> = labels
        .iter()
        .map(|cl| {
            let mut score = 0.0_f64;
            for (i, re) in cl.regexes.iter().enumerate() {
                if re.is_match(text) {
                    score += 0.4 / (i as f64 + 1.0);
                }
            }
            (cl.name.as_str(), (score * cl.weight).min(0.99))
        })
        .collect();

    // Normalize to probabilities.
    let total: f64 = scores.iter().map(|(_, s)| s).sum();
    if total > 0.0 {
        for s in &mut scores {
            s.1 /= total;
        }
    }

    // If nothing exceeded threshold, boost the default label.
    let max_score = scores.iter().map(|(_, s)| *s).fold(0.0_f64, f64::max);
    if max_score < confidence_threshold {
        for s in &mut scores {
            if s.0 == default_label {
                s.1 = default_boost;
            }
        }
        let total: f64 = scores.iter().map(|(_, s)| s).sum();
        if total > 0.0 {
            for s in &mut scores {
                s.1 /= total;
            }
        }
    }

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scores
        .into_iter()
        .take(top_k)
        .map(|(label, score)| Label {
            label: label.to_string(),
            score: (score * 10000.0).round() / 10000.0,
        })
        .collect()
}

/// Evaluate accumulated streaming text against a list of safety rules.
///
/// Returns `(safe, blocked, reason)`. Matching is case-insensitive substring
/// search. Shared by the TCP `streaming_safety` command and the gRPC
/// `StreamSafety` RPC so both use the same logic.
pub fn check_streaming_safety(text: &str, rules: &[String]) -> (bool, bool, String) {
    let lower = text.to_lowercase();
    for rule in rules {
        if lower.contains(&rule.to_lowercase()) {
            let reason = format!("matched rule: {rule}");
            return (false, true, reason);
        }
    }
    (true, false, String::new())
}

/// Detect a coarse intent category from a prompt's surface text.
///
/// Ported from the enterprise TCP handler's inline heuristic. Deliberately
/// simple: substring matching over a small fixed vocabulary, the same
/// approach as [`detect_content_type`]. Returns `(intent, confidence)`.
pub fn detect_intent(text: &str) -> (&'static str, f64) {
    let lower = text.to_lowercase();

    let category = if lower.contains("code")
        || lower.contains("function")
        || lower.contains("implement")
        || lower.contains("debug")
    {
        "coding"
    } else if lower.contains("image")
        || lower.contains("picture")
        || lower.contains("photo")
        || lower.contains("describe what you see")
    {
        "vision"
    } else if lower.contains("analyze") || lower.contains("compare") || lower.contains("evaluate") {
        "analysis"
    } else if lower.contains("summarize")
        || lower.contains("summary")
        || lower.contains("tldr")
        || lower.contains("brief")
    {
        "summarization"
    } else {
        "general"
    };

    let confidence = if category == "general" { 0.5 } else { 0.85 };
    (category, confidence)
}

/// Detect a coarse content-type category (image / audio / video / text)
/// from a content string, which may be a data URI, a filename, or raw text.
///
/// Ported from the enterprise TCP handler's inline heuristic. Returns
/// `(content_type, confidence)`.
pub fn detect_content_type(content: &str) -> (&'static str, f64) {
    let content_type = if content.starts_with("data:image")
        || content.contains("base64,/9j/")
        || content.contains("base64,iVBOR")
    {
        "image"
    } else if content.starts_with("data:audio")
        || content.contains(".mp3")
        || content.contains(".wav")
    {
        "audio"
    } else if content.starts_with("data:video")
        || content.contains(".mp4")
        || content.contains(".webm")
    {
        "video"
    } else {
        "text"
    };

    let confidence = if content_type == "text" { 0.7 } else { 0.9 };
    (content_type, confidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LabelConfig;

    fn test_labels() -> Vec<LabelConfig> {
        vec![
            LabelConfig {
                name: "code_generation".to_string(),
                weight: 1.0,
                patterns: vec![
                    r"(?i)\b(write|create|build|implement|generate)\b.{0,20}\b(code|function|class|api)\b".to_string(),
                    r"(?i)\b(python|javascript|golang|rust|java|typescript)\b".to_string(),
                ],
            },
            LabelConfig {
                name: "question_answering".to_string(),
                weight: 1.0,
                patterns: vec![
                    r"(?i)^(what|who|where|when|why|how|is|are|do|does|can|could)\b".to_string(),
                    r"\?$".to_string(),
                ],
            },
            LabelConfig {
                name: "summarization".to_string(),
                weight: 1.0,
                patterns: vec![
                    r"(?i)\b(summarize|summary|tldr|tl;dr|brief|overview)\b".to_string(),
                ],
            },
            LabelConfig {
                name: "math_reasoning".to_string(),
                weight: 1.0,
                patterns: vec![
                    r"(?i)\b(solve|calculate|compute|prove|integral|derivative)\b".to_string(),
                    r"(?i)\b(math|algebra|calculus|geometry)\b".to_string(),
                ],
            },
            LabelConfig {
                name: "conversation".to_string(),
                weight: 0.8,
                patterns: vec![
                    r"(?i)^(hi|hello|hey|sup|yo|thanks|how are you)\b".to_string(),
                    r"^.{0,30}$".to_string(),
                ],
            },
        ]
    }

    fn test_classifier() -> Classifier {
        Classifier::from_labels(&test_labels(), 0.15, "conversation", 0.5)
    }

    #[test]
    fn code_generation_scores_highest_for_a_code_prompt() {
        let c = test_classifier();
        let labels = c.classify("Write a Python function to sort a list", 3);
        assert_eq!(labels[0].label, "code_generation");
    }

    #[test]
    fn question_answering_scores_highest_for_a_question() {
        let c = test_classifier();
        let labels = c.classify("What is the capital of France?", 3);
        assert_eq!(labels[0].label, "question_answering");
    }

    #[test]
    fn conversation_scores_highest_for_a_greeting() {
        let c = test_classifier();
        let labels = c.classify("Hey how are you?", 3);
        assert_eq!(labels[0].label, "conversation");
    }

    #[test]
    fn math_reasoning_scores_highest_for_a_math_prompt() {
        let c = test_classifier();
        let labels = c.classify("Solve the integral of x^2 dx", 3);
        assert_eq!(labels[0].label, "math_reasoning");
    }

    #[test]
    fn summarization_scores_highest_for_a_summarize_prompt() {
        let c = test_classifier();
        let labels = c.classify("Summarize this article about climate change", 3);
        assert_eq!(labels[0].label, "summarization");
    }

    #[test]
    fn empty_text_still_returns_a_label() {
        let c = test_classifier();
        let labels = c.classify("", 3);
        assert!(!labels.is_empty(), "should return at least one label");
    }

    #[test]
    fn top_k_bounds_the_result_length() {
        let c = test_classifier();
        let labels = c.classify("Write Python code to solve math", 1);
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn scores_sum_to_approximately_one() {
        let c = test_classifier();
        let labels = c.classify("Write a function in Python", 5);
        let total: f64 = labels.iter().map(|l| l.score).sum();
        assert!(
            (total - 1.0).abs() < 0.01,
            "scores should sum to ~1.0, got {total}"
        );
    }

    #[test]
    fn oversized_pattern_is_skipped_not_fatal() {
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        let labels = vec![LabelConfig {
            name: "bad".to_string(),
            weight: 1.0,
            patterns: vec![long_pattern],
        }];
        let c = Classifier::from_labels(&labels, 0.15, "bad", 0.5);
        let result = c.classify("anything", 1);
        assert!(!result.is_empty());
    }

    #[test]
    fn invalid_regex_is_skipped_leaving_other_labels_intact() {
        let labels = vec![
            LabelConfig {
                name: "bad_regex".to_string(),
                weight: 1.0,
                patterns: vec!["[invalid".to_string()],
            },
            LabelConfig {
                name: "good".to_string(),
                weight: 1.0,
                patterns: vec![r"(?i)\bhello\b".to_string()],
            },
        ];
        let c = Classifier::from_labels(&labels, 0.15, "bad_regex", 0.5);
        let result = c.classify("hello world", 2);
        assert_eq!(result[0].label, "good");
    }

    #[test]
    fn streaming_safety_flags_a_matched_rule() {
        let (safe, blocked, reason) =
            check_streaming_safety("this text mentions a Secret Key", &["secret key".into()]);
        assert!(!safe);
        assert!(blocked);
        assert!(reason.contains("secret key"));
    }

    #[test]
    fn streaming_safety_is_safe_with_no_match() {
        let (safe, blocked, reason) = check_streaming_safety("hello world", &["forbidden".into()]);
        assert!(safe);
        assert!(!blocked);
        assert!(reason.is_empty());
    }

    #[test]
    fn detect_intent_recognizes_coding_prompts() {
        assert_eq!(detect_intent("please implement a function").0, "coding");
    }

    #[test]
    fn detect_intent_falls_back_to_general() {
        assert_eq!(detect_intent("nice weather today").0, "general");
    }

    #[test]
    fn detect_content_type_recognizes_a_data_uri() {
        assert_eq!(detect_content_type("data:image/png;base64,abc").0, "image");
    }

    #[test]
    fn detect_content_type_defaults_to_text() {
        assert_eq!(detect_content_type("just some words").0, "text");
    }
}
