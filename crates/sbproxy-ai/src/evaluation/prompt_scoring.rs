//! Prompt scoring and ranking for A/B evaluation.
//!
//! Records quality scores for individual prompts across models and exposes
//! aggregate statistics useful for selecting the best-performing variants.

use parking_lot::Mutex;

// --- Types ---

/// A recorded quality score for a specific prompt and model combination.
#[derive(Debug, Clone)]
pub struct PromptScore {
    /// The prompt text that was evaluated.
    pub prompt: String,
    /// Model used when the score was recorded.
    pub model: String,
    /// Overall score assigned to the response (e.g. 0.0..=1.0 or 1..10).
    pub score: f64,
    /// Separate quality dimension for the response content.
    pub response_quality: f64,
}

impl PromptScore {
    /// Create a new prompt score entry.
    pub fn new(
        prompt: impl Into<String>,
        model: impl Into<String>,
        score: f64,
        response_quality: f64,
    ) -> Self {
        Self {
            prompt: prompt.into(),
            model: model.into(),
            score,
            response_quality,
        }
    }
}

// --- Scorer ---

/// Thread-safe store that accumulates prompt scores and computes aggregates.
///
/// # Unbounded: not for live traffic
///
/// This is an offline primitive. It never evicts, has no cap, and
/// [`PromptScore::prompt`] holds the prompt text verbatim, so wiring
/// [`PromptScorer::record`] to live requests grows the process by the full
/// text of every prompt and makes [`PromptScorer::rank_prompts`] quadratic
/// under the lock. Use it against a recorded dataset, and reach for the
/// bounded, scope-keyed [`crate::toolkit::AiToolkitRuntime`] when the
/// caller is a request rather than an operator.
pub struct PromptScorer {
    scores: Mutex<Vec<PromptScore>>,
}

impl PromptScorer {
    /// Create a new, empty scorer.
    pub fn new() -> Self {
        Self {
            scores: Mutex::new(Vec::new()),
        }
    }

    /// Record a score observation.
    pub fn record(&self, score: PromptScore) {
        self.scores.lock().push(score);
    }

    /// Compute the average score for the given prompt text across all models
    /// and observations. Returns `None` if no observations exist for the prompt.
    pub fn average_score(&self, prompt: &str) -> Option<f64> {
        let guard = self.scores.lock();
        let matching: Vec<f64> = guard
            .iter()
            .filter(|s| s.prompt == prompt)
            .map(|s| s.score)
            .collect();

        if matching.is_empty() {
            return None;
        }

        Some(matching.iter().sum::<f64>() / matching.len() as f64)
    }

    /// Return all unique prompts with their average score, sorted from highest
    /// to lowest average score.
    pub fn rank_prompts(&self) -> Vec<(String, f64)> {
        let guard = self.scores.lock();

        // Collect unique prompts.
        let mut prompt_set: Vec<String> = guard
            .iter()
            .map(|s| s.prompt.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // For each prompt compute the average.
        let mut ranked: Vec<(String, f64)> = prompt_set
            .drain(..)
            .map(|prompt| {
                let scores: Vec<f64> = guard
                    .iter()
                    .filter(|s| s.prompt == prompt)
                    .map(|s| s.score)
                    .collect();
                let avg = scores.iter().sum::<f64>() / scores.len() as f64;
                (prompt, avg)
            })
            .collect();

        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Return the total number of recorded score observations.
    pub fn observation_count(&self) -> usize {
        self.scores.lock().len()
    }
}

impl Default for PromptScorer {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_average_score() {
        let scorer = PromptScorer::new();
        scorer.record(PromptScore::new("summarize this", "gpt-4o", 0.8, 0.85));
        scorer.record(PromptScore::new("summarize this", "claude-3", 0.9, 0.90));
        let avg = scorer
            .average_score("summarize this")
            .expect("should have avg");
        assert!((avg - 0.85).abs() < 1e-9);
    }

    #[test]
    fn average_score_returns_none_for_unknown_prompt() {
        let scorer = PromptScorer::new();
        assert!(scorer.average_score("unknown prompt").is_none());
    }

    #[test]
    fn rank_prompts_returns_sorted_descending() {
        let scorer = PromptScorer::new();
        scorer.record(PromptScore::new("low prompt", "m1", 0.4, 0.4));
        scorer.record(PromptScore::new("high prompt", "m1", 0.9, 0.9));
        scorer.record(PromptScore::new("mid prompt", "m1", 0.6, 0.6));
        let ranked = scorer.rank_prompts();
        assert_eq!(ranked[0].0, "high prompt");
        assert_eq!(ranked[2].0, "low prompt");
    }

    #[test]
    fn rank_prompts_empty_when_no_records() {
        let scorer = PromptScorer::new();
        assert!(scorer.rank_prompts().is_empty());
    }

    #[test]
    fn observation_count_tracks_records() {
        let scorer = PromptScorer::new();
        assert_eq!(scorer.observation_count(), 0);
        scorer.record(PromptScore::new("p1", "m1", 0.5, 0.5));
        scorer.record(PromptScore::new("p2", "m1", 0.7, 0.7));
        assert_eq!(scorer.observation_count(), 2);
    }

    #[test]
    fn prompt_score_single_observation() {
        let scorer = PromptScorer::new();
        scorer.record(PromptScore::new("only one", "gpt-4", 0.75, 0.80));
        assert!((scorer.average_score("only one").unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn rank_prompts_includes_all_unique_prompts() {
        let scorer = PromptScorer::new();
        scorer.record(PromptScore::new("p1", "m", 1.0, 1.0));
        scorer.record(PromptScore::new("p2", "m", 0.5, 0.5));
        scorer.record(PromptScore::new("p3", "m", 0.3, 0.3));
        let ranked = scorer.rank_prompts();
        assert_eq!(ranked.len(), 3);
    }

    #[test]
    fn prompt_scorer_default_is_empty() {
        let scorer = PromptScorer::default();
        assert_eq!(scorer.observation_count(), 0);
    }
}
