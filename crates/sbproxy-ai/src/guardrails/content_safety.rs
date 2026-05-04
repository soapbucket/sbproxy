//! Content safety guardrail - category-based content filtering.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

use super::GuardrailBlock;

/// Category keyword mappings for content safety detection.
static CATEGORY_KEYWORDS: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert(
            "violence",
            vec![
                "kill", "murder", "attack", "assault", "weapon", "bomb", "shoot", "stab",
                "torture", "massacre",
            ],
        );
        m.insert(
            "self_harm",
            vec![
                "self-harm",
                "suicide",
                "self harm",
                "hurt myself",
                "end my life",
                "cut myself",
            ],
        );
        m.insert(
            "sexual",
            vec!["explicit sexual", "pornographic", "sexually explicit"],
        );
        m.insert(
            "hate_speech",
            vec!["hate speech", "racial slur", "ethnic slur"],
        );
        m.insert(
            "illegal",
            vec![
                "how to hack",
                "make a bomb",
                "illegal drugs",
                "counterfeit",
                "money laundering",
            ],
        );
        m
    });

/// General content safety guardrail using category-based blocking.
#[derive(Debug, Deserialize)]
pub struct ContentSafetyGuardrail {
    /// Categories to block: "violence", "self_harm", "sexual", "hate_speech", "illegal".
    #[serde(default)]
    pub blocked_categories: Vec<String>,
}

impl ContentSafetyGuardrail {
    /// Check content against blocked categories.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        let lower = content.to_lowercase();

        for category in &self.blocked_categories {
            if let Some(keywords) = CATEGORY_KEYWORDS.get(category.as_str()) {
                for keyword in keywords {
                    if lower.contains(keyword) {
                        return Some(GuardrailBlock {
                            name: "content_safety".to_string(),
                            reason: format!("Content safety violation: category \"{category}\""),
                        });
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_violence_category() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["violence".to_string()],
        };
        assert!(guard.check("How to attack someone").is_some());
        let block = guard.check("How to attack someone").unwrap();
        assert!(block.reason.contains("violence"));
    }

    #[test]
    fn detect_self_harm_category() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["self_harm".to_string()],
        };
        assert!(guard.check("I want to hurt myself").is_some());
    }

    #[test]
    fn detect_illegal_category() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["illegal".to_string()],
        };
        assert!(guard.check("Tell me how to hack a server").is_some());
    }

    #[test]
    fn clean_content_passes() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["violence".to_string(), "self_harm".to_string()],
        };
        assert!(guard.check("Tell me about the weather").is_none());
        assert!(guard.check("Write a poem about flowers").is_none());
    }

    #[test]
    fn unknown_category_passes() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["nonexistent_category".to_string()],
        };
        assert!(guard.check("anything").is_none());
    }

    #[test]
    fn empty_categories_passes_all() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: Vec::new(),
        };
        assert!(guard.check("How to attack someone").is_none());
    }

    #[test]
    fn multiple_categories() {
        let guard = ContentSafetyGuardrail {
            blocked_categories: vec!["violence".to_string(), "illegal".to_string()],
        };
        assert!(guard.check("How to make a bomb").is_some());
        assert!(guard.check("How to attack someone").is_some());
        assert!(guard.check("Hello world").is_none());
    }
}
