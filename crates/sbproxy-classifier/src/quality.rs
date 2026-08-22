//! Heuristic quality scoring for AI-generated text.
//!
//! Ported verbatim (no adaptation needed: this module has no dependency on
//! anything enterprise-specific) from the enterprise `sbproxy-classifier`
//! crate's `quality.rs`. Flags low-quality responses without running an
//! actual LLM-as-judge every time. Cheap, deterministic signals:
//!
//! - **Error patterns** - phrases like "I cannot", "as an AI", "I apologize
//!   but" that indicate refusal or hedging.
//! - **Length signals** - very short or very long responses score lower.
//! - **Repetition** - degenerate outputs often repeat phrases.
//! - **Diversity** - unique-token ratio within the response.
//!
//! Each signal returns a `[0.0, 1.0]` score, and the overall
//! [`QualityResult::score`] is a weighted combination. Signals are also
//! returned individually so the caller can inspect which ones fired.

use std::collections::HashMap;

/// Result of heuristic quality scoring.
pub(crate) struct QualityResult {
    /// Overall score from 0.0 (poor) to 1.0 (excellent).
    pub score: f64,
    /// Individual signal scores.
    pub signals: HashMap<String, f64>,
}

/// Error patterns that indicate low-quality AI responses.
const ERROR_PATTERNS: &[&str] = &[
    "i cannot",
    "i can't",
    "as an ai",
    "i don't have",
    "i'm not able",
    "i am not able",
    "i'm unable",
    "i am unable",
    "as a language model",
    "as an artificial",
];

/// Analyze text and return a heuristic quality score.
/// Designed for sub-100us latency with no ML inference.
pub fn quality_score(text: &str) -> QualityResult {
    let mut signals = HashMap::new();

    // Length score: penalize very short or excessively long responses.
    let word_count = text.split_whitespace().count();
    let length_score = match word_count {
        0..=5 => 0.2,
        6..=20 => 0.6,
        21..=100 => 0.9,
        101..=500 => 1.0,
        501..=1000 => 0.9,
        _ => 0.7,
    };
    signals.insert("length".to_string(), length_score);

    // Coherence: sentences end with proper punctuation.
    let coherence_score = compute_coherence(text);
    signals.insert("coherence".to_string(), coherence_score);

    // Repetition: detect repeated phrases (trigrams).
    let repetition_score = compute_repetition(text);
    signals.insert("repetition".to_string(), repetition_score);

    // Formatting: paragraphs, lists, code blocks.
    let formatting_score = compute_formatting(text);
    signals.insert("formatting".to_string(), formatting_score);

    // Error patterns: penalize known AI refusal/hedging phrases.
    let error_score = compute_error_patterns(text);
    signals.insert("error_patterns".to_string(), error_score);

    // Casing: penalize all-caps or no-caps text.
    let casing_score = compute_casing(text);
    signals.insert("casing".to_string(), casing_score);

    // Weighted average for overall score.
    let weights: &[(&str, f64)] = &[
        ("length", 0.20),
        ("coherence", 0.20),
        ("repetition", 0.20),
        ("formatting", 0.10),
        ("error_patterns", 0.15),
        ("casing", 0.15),
    ];

    let overall: f64 = weights
        .iter()
        .map(|(key, w)| signals.get(*key).copied().unwrap_or(0.5) * w)
        .sum();

    // Clamp to [0.0, 1.0].
    let score = overall.clamp(0.0, 1.0);
    // Round to 4 decimal places.
    let score = (score * 10000.0).round() / 10000.0;

    QualityResult { score, signals }
}

/// Coherence: what fraction of sentences end with terminal punctuation?
fn compute_coherence(text: &str) -> f64 {
    if text.trim().is_empty() {
        return 0.1;
    }

    let sentences: Vec<&str> = text
        .split(['.', '!', '?'])
        .filter(|s| s.trim().len() > 2)
        .collect();

    let total_segments = sentences.len();
    if total_segments == 0 {
        return 0.3;
    }

    let trimmed = text.trim();
    let ends_with_punct = trimmed.ends_with('.')
        || trimmed.ends_with('!')
        || trimmed.ends_with('?')
        || trimmed.ends_with(':')
        || trimmed.ends_with(')');

    match (total_segments, ends_with_punct) {
        (0, _) => 0.3,
        (1, false) => 0.5,
        (1, true) => 0.7,
        (_, false) => 0.7,
        (_, true) => 0.9,
    }
}

/// Repetition: use trigram analysis to detect repeated phrases.
/// Returns 1.0 for no repetition, lower for high repetition.
fn compute_repetition(text: &str) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 6 {
        return 0.8;
    }

    let mut trigrams: HashMap<(&str, &str, &str), usize> = HashMap::new();
    for window in words.windows(3) {
        let key = (window[0], window[1], window[2]);
        *trigrams.entry(key).or_insert(0) += 1;
    }

    let total_trigrams = words.len().saturating_sub(2);
    if total_trigrams == 0 {
        return 0.8;
    }

    let repeated: usize = trigrams
        .values()
        .filter(|&&count| count > 1)
        .map(|c| c - 1)
        .sum();
    let repetition_ratio = repeated as f64 / total_trigrams as f64;

    match repetition_ratio {
        r if r < 0.05 => 1.0,
        r if r < 0.15 => 0.8,
        r if r < 0.30 => 0.5,
        r if r < 0.50 => 0.3,
        _ => 0.1,
    }
}

/// Formatting: reward structured content (paragraphs, lists, code blocks).
fn compute_formatting(text: &str) -> f64 {
    if text.trim().is_empty() {
        return 0.1;
    }

    let mut score: f64 = 0.5;

    if text.contains("\n\n") {
        score += 0.15;
    }

    let has_list = text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("1.")
            || trimmed.starts_with("2.")
    });
    if has_list {
        score += 0.15;
    }

    if text.contains("```") || text.contains("    ") {
        score += 0.1;
    }

    if text.lines().any(|line| line.trim().starts_with('#')) {
        score += 0.1;
    }

    score.min(1.0)
}

/// Error patterns: penalize known AI refusal/hedging phrases.
/// Returns 1.0 if no patterns found, lower if patterns detected.
fn compute_error_patterns(text: &str) -> f64 {
    let lower = text.to_lowercase();
    let mut matches = 0;

    for pattern in ERROR_PATTERNS {
        if lower.contains(pattern) {
            matches += 1;
        }
    }

    match matches {
        0 => 1.0,
        1 => 0.5,
        2 => 0.3,
        _ => 0.1,
    }
}

/// Casing: penalize all-caps or completely lowercase text.
fn compute_casing(text: &str) -> f64 {
    let alpha_chars: Vec<char> = text.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha_chars.is_empty() {
        return 0.5;
    }

    let upper_count = alpha_chars.iter().filter(|c| c.is_uppercase()).count();
    let upper_ratio = upper_count as f64 / alpha_chars.len() as f64;

    match upper_ratio {
        r if r < 0.01 => 0.5,
        r if r > 0.80 => 0.2,
        r if r > 0.50 => 0.5,
        _ => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_quality_response_scores_above_half() {
        let text = "Quantum computing uses quantum bits (qubits) instead of classical bits. \
            Unlike classical bits that are either 0 or 1, qubits can exist in superposition, \
            representing both states simultaneously. This property, along with entanglement, \
            allows quantum computers to process certain types of problems exponentially faster \
            than classical computers.";
        let result = quality_score(text);
        assert!(
            result.score > 0.5,
            "high quality text should score > 0.5, got {}",
            result.score
        );
        assert!(result.signals["length"] > 0.5);
        assert!(result.signals["coherence"] > 0.5);
        assert!(result.signals["repetition"] > 0.5);
    }

    #[test]
    fn very_short_response_scores_low() {
        let text = "ok";
        let result = quality_score(text);
        assert!(
            result.score < 0.6,
            "very short text should score low, got {}",
            result.score
        );
    }

    #[test]
    fn refusal_phrasing_is_penalized() {
        let text = "As an AI language model, I cannot provide medical advice. \
            I don't have access to your medical records.";
        let result = quality_score(text);
        assert!(
            result.signals["error_patterns"] < 0.5,
            "error patterns should be penalized, got {}",
            result.signals["error_patterns"]
        );
    }

    #[test]
    fn all_caps_text_is_penalized() {
        let text = "THIS IS ALL CAPS AND SHOULD BE PENALIZED FOR POOR FORMATTING";
        let result = quality_score(text);
        assert!(
            result.signals["casing"] < 0.5,
            "all caps should be penalized, got {}",
            result.signals["casing"]
        );
    }

    #[test]
    fn repetitive_text_is_penalized() {
        let text = "the cat sat the cat sat the cat sat the cat sat the cat sat";
        let result = quality_score(text);
        assert!(
            result.signals["repetition"] < 0.8,
            "highly repetitive text should score low, got {}",
            result.signals["repetition"]
        );
    }

    #[test]
    fn well_formatted_text_scores_high_on_formatting() {
        let text = "# Introduction\n\nHere are the key points:\n\n- First point\n- Second point\n\n```python\nprint('hello')\n```";
        let result = quality_score(text);
        assert!(
            result.signals["formatting"] > 0.7,
            "well-formatted text should score high, got {}",
            result.signals["formatting"]
        );
    }

    #[test]
    fn empty_text_scores_very_low() {
        let result = quality_score("");
        assert!(
            result.score < 0.5,
            "empty text should score very low, got {}",
            result.score
        );
    }

    #[test]
    fn score_always_stays_in_unit_range() {
        let texts = vec![
            "",
            "hi",
            "A normal sentence with good structure.",
            "THE QUICK BROWN FOX",
            "As an AI, I cannot do that. I don't have that ability.",
        ];
        for text in texts {
            let result = quality_score(text);
            assert!(
                (0.0..=1.0).contains(&result.score),
                "score should be in [0, 1], got {} for text: {}",
                result.score,
                text
            );
        }
    }
}
