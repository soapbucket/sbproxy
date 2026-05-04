//! PII detection guardrail - email, phone, SSN, credit card patterns.

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use super::GuardrailBlock;

/// Action to take when PII is detected.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Reject the request with an error response (default).
    #[default]
    Block,
    /// Replace detected PII with mask characters and continue.
    Mask,
    /// Log the detection event but allow the request through unchanged.
    Log,
}

/// Detects PII patterns in content.
#[derive(Debug, Deserialize)]
pub struct PiiGuardrail {
    /// Which PII types to detect: "email", "phone", "ssn", "credit_card".
    #[serde(default = "default_pii_patterns")]
    pub patterns: Vec<String>,
    /// What to do when PII is detected.
    #[serde(default)]
    pub action: PiiAction,
}

fn default_pii_patterns() -> Vec<String> {
    vec![
        "email".to_string(),
        "phone".to_string(),
        "ssn".to_string(),
        "credit_card".to_string(),
    ]
}

// --- Compiled regex patterns ---

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static PHONE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}").unwrap());

static SSN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap());

static CREDIT_CARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap());

/// Matches common API key patterns: sk-..., ghp_..., gho_..., glpat-..., AKIA..., xoxb-..., etc.
static API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|glpat-[a-zA-Z0-9\-]{20,}|AKIA[0-9A-Z]{16}|xoxb-[0-9]{10,}-[a-zA-Z0-9-]+)").unwrap()
});

impl PiiGuardrail {
    /// Check content for PII. Returns Some(block) if PII detected and action is Block.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        for pattern_type in &self.patterns {
            let detected = match pattern_type.as_str() {
                "email" => EMAIL_RE.is_match(content),
                "phone" => PHONE_RE.is_match(content),
                "ssn" => SSN_RE.is_match(content),
                "credit_card" => CREDIT_CARD_RE.is_match(content),
                "api_key" => API_KEY_RE.is_match(content),
                _ => false,
            };
            if detected {
                return match self.action {
                    PiiAction::Block => Some(GuardrailBlock {
                        name: "pii".to_string(),
                        reason: format!("PII detected: {pattern_type}"),
                    }),
                    // Mask and Log actions do not block the request.
                    PiiAction::Mask | PiiAction::Log => None,
                };
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocking_guard(patterns: Vec<&str>) -> PiiGuardrail {
        PiiGuardrail {
            patterns: patterns.into_iter().map(String::from).collect(),
            action: PiiAction::Block,
        }
    }

    #[test]
    fn detect_email() {
        let guard = blocking_guard(vec!["email"]);
        let block = guard.check("Send to user@example.com please");
        assert!(block.is_some());
        assert!(block.unwrap().reason.contains("email"));
    }

    #[test]
    fn detect_phone() {
        let guard = blocking_guard(vec!["phone"]);
        assert!(guard.check("Call me at (555) 123-4567").is_some());
        assert!(guard.check("Call me at 555-123-4567").is_some());
        assert!(guard.check("Call me at +1 555 123 4567").is_some());
    }

    #[test]
    fn detect_ssn() {
        let guard = blocking_guard(vec!["ssn"]);
        assert!(guard.check("My SSN is 123-45-6789").is_some());
        assert!(guard.check("SSN: 123 45 6789").is_some());
    }

    #[test]
    fn detect_credit_card() {
        let guard = blocking_guard(vec!["credit_card"]);
        assert!(guard.check("Card: 4111 1111 1111 1111").is_some());
        assert!(guard.check("Card: 4111-1111-1111-1111").is_some());
    }

    #[test]
    fn no_false_positive_clean_text() {
        let guard = blocking_guard(vec!["email", "phone", "ssn", "credit_card"]);
        assert!(guard.check("Hello, how are you today?").is_none());
        assert!(guard.check("The temperature is 72 degrees").is_none());
        assert!(guard.check("Please summarize this document").is_none());
    }

    #[test]
    fn mask_action_does_not_block() {
        let guard = PiiGuardrail {
            patterns: vec!["email".to_string()],
            action: PiiAction::Mask,
        };
        assert!(guard.check("user@example.com").is_none());
    }

    #[test]
    fn log_action_does_not_block() {
        let guard = PiiGuardrail {
            patterns: vec!["email".to_string()],
            action: PiiAction::Log,
        };
        assert!(guard.check("user@example.com").is_none());
    }

    #[test]
    fn detect_api_key_sk_format() {
        let guard = blocking_guard(vec!["api_key"]);
        assert!(guard
            .check("Use this key sk-abc123def456ghi789jkl012mno345pqr678stu901vwx to call the API")
            .is_some());
    }

    #[test]
    fn detect_api_key_ghp_format() {
        let guard = blocking_guard(vec!["api_key"]);
        assert!(guard
            .check("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234")
            .is_some());
    }

    #[test]
    fn no_false_positive_api_key() {
        let guard = blocking_guard(vec!["api_key"]);
        assert!(guard.check("The sky is blue").is_none());
        assert!(guard.check("sk-short").is_none()); // too short
    }

    #[test]
    fn default_patterns_include_all() {
        let patterns = default_pii_patterns();
        assert!(patterns.contains(&"email".to_string()));
        assert!(patterns.contains(&"phone".to_string()));
        assert!(patterns.contains(&"ssn".to_string()));
        assert!(patterns.contains(&"credit_card".to_string()));
    }

    #[test]
    fn deserialization_defaults() {
        let json = serde_json::json!({"type": "pii"});
        let guard: PiiGuardrail = serde_json::from_value(json).unwrap();
        assert_eq!(guard.patterns.len(), 4);
    }
}
