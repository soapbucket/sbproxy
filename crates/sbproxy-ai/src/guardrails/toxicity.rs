//! Toxicity detection guardrail - keyword-based content filtering.

use serde::Deserialize;

use super::GuardrailBlock;

/// Detects toxic or harmful content via keyword matching.
#[derive(Debug, Deserialize)]
pub struct ToxicityGuardrail {
    /// Custom keywords to flag as toxic.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Score threshold for future ML-based scoring. Currently unused.
    #[serde(default)]
    pub threshold: Option<f64>,
}

impl ToxicityGuardrail {
    /// Check content for toxic keywords.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        let lower = content.to_lowercase();

        for keyword in &self.keywords {
            let keyword_lower = keyword.to_lowercase();
            if lower.contains(&keyword_lower) {
                return Some(GuardrailBlock {
                    name: "toxicity".to_string(),
                    reason: format!("Toxic content detected: matched keyword \"{keyword}\""),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_keyword() {
        let guard = ToxicityGuardrail {
            keywords: vec!["harmful_term".to_string()],
            threshold: None,
        };
        assert!(guard.check("This contains harmful_term in it").is_some());
    }

    #[test]
    fn case_insensitive() {
        let guard = ToxicityGuardrail {
            keywords: vec!["badword".to_string()],
            threshold: None,
        };
        assert!(guard.check("This has BADWORD").is_some());
    }

    #[test]
    fn clean_text_passes() {
        let guard = ToxicityGuardrail {
            keywords: vec!["harmful_term".to_string()],
            threshold: None,
        };
        assert!(guard.check("This is a perfectly normal message").is_none());
    }

    #[test]
    fn empty_keywords_passes_all() {
        let guard = ToxicityGuardrail {
            keywords: Vec::new(),
            threshold: None,
        };
        assert!(guard.check("anything goes").is_none());
    }

    #[test]
    fn multiple_keywords() {
        let guard = ToxicityGuardrail {
            keywords: vec!["bad_one".to_string(), "bad_two".to_string()],
            threshold: None,
        };
        assert!(guard.check("This has bad_one").is_some());
        assert!(guard.check("This has bad_two").is_some());
        assert!(guard.check("This is clean").is_none());
    }
}
