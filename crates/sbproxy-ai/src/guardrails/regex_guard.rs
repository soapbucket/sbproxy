//! Regex-based content filtering guardrail.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

use super::GuardrailBlock;

/// Action for regex matches.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegexAction {
    /// Block content if any pattern matches.
    #[default]
    Block,
    /// Only allow content if at least one pattern matches.
    Allow,
}

/// Custom regex-based content filtering.
#[derive(Debug)]
pub struct RegexGuardrail {
    /// Compiled regex patterns.
    pub patterns: Vec<Regex>,
    /// Whether to block on match or only allow on match.
    pub action: RegexAction,
}

/// Intermediate struct for deserialization before regex compilation.
#[derive(Deserialize)]
struct RegexGuardrailRaw {
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    action: RegexAction,
}

impl RegexGuardrail {
    /// Build from a guardrail config value, compiling regex patterns.
    pub fn from_config(config: &serde_json::Value) -> Result<Self> {
        let raw: RegexGuardrailRaw = serde_json::from_value(config.clone())?;
        let patterns = raw
            .patterns
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Regex::new(p)
                    .with_context(|| format!("invalid regex pattern at index {i}: \"{p}\""))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            patterns,
            action: raw.action,
        })
    }

    /// Check content against regex patterns.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        match self.action {
            RegexAction::Block => {
                // Block if any pattern matches.
                for pattern in &self.patterns {
                    if pattern.is_match(content) {
                        return Some(GuardrailBlock {
                            name: "regex".to_string(),
                            reason: format!(
                                "Content blocked: matched regex pattern \"{}\"",
                                pattern.as_str()
                            ),
                        });
                    }
                }
                None
            }
            RegexAction::Allow => {
                // Block if NO pattern matches (content must match at least one).
                if self.patterns.is_empty() {
                    return None;
                }
                let any_match = self.patterns.iter().any(|p| p.is_match(content));
                if any_match {
                    None
                } else {
                    Some(GuardrailBlock {
                        name: "regex".to_string(),
                        reason: "Content blocked: did not match any allowed pattern".to_string(),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_matching_pattern() {
        let guard = RegexGuardrail {
            patterns: vec![Regex::new(r"secret_key_\w+").unwrap()],
            action: RegexAction::Block,
        };
        assert!(guard.check("Here is secret_key_abc123").is_some());
        assert!(guard.check("Normal text without secrets").is_none());
    }

    #[test]
    fn block_multiple_patterns() {
        let guard = RegexGuardrail {
            patterns: vec![
                Regex::new(r"password:\s*\S+").unwrap(),
                Regex::new(r"api_key=\w+").unwrap(),
            ],
            action: RegexAction::Block,
        };
        assert!(guard.check("password: hunter2").is_some());
        assert!(guard.check("api_key=abcd1234").is_some());
        assert!(guard.check("nothing sensitive here").is_none());
    }

    #[test]
    fn allow_mode_passes_matching() {
        let guard = RegexGuardrail {
            patterns: vec![Regex::new(r"^\{.*\}$").unwrap()],
            action: RegexAction::Allow,
        };
        assert!(guard.check(r#"{"valid": true}"#).is_none());
    }

    #[test]
    fn allow_mode_blocks_non_matching() {
        let guard = RegexGuardrail {
            patterns: vec![Regex::new(r"^\{.*\}$").unwrap()],
            action: RegexAction::Allow,
        };
        let block = guard.check("not json at all");
        assert!(block.is_some());
        assert!(block.unwrap().reason.contains("did not match"));
    }

    #[test]
    fn allow_mode_empty_patterns_passes() {
        let guard = RegexGuardrail {
            patterns: Vec::new(),
            action: RegexAction::Allow,
        };
        assert!(guard.check("anything").is_none());
    }

    #[test]
    fn from_config_valid() {
        let config = serde_json::json!({
            "type": "regex",
            "patterns": [r"\bSSN\b", r"\d{3}-\d{2}-\d{4}"],
            "action": "block"
        });
        let guard = RegexGuardrail::from_config(&config).unwrap();
        assert_eq!(guard.patterns.len(), 2);
    }

    #[test]
    fn from_config_invalid_regex() {
        let config = serde_json::json!({
            "type": "regex",
            "patterns": ["valid", "[invalid"]
        });
        assert!(RegexGuardrail::from_config(&config).is_err());
    }

    #[test]
    fn from_config_allow_action() {
        let config = serde_json::json!({
            "type": "regex",
            "patterns": [r"^\d+$"],
            "action": "allow"
        });
        let guard = RegexGuardrail::from_config(&config).unwrap();
        assert!(guard.check("12345").is_none());
        assert!(guard.check("not a number").is_some());
    }
}
