//! PII detection guardrail - email, phone, SSN, credit card patterns.

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

use sbproxy_security::span::{cap_spans, DetectionSpan};

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

    /// Bounded detection spans (WOR-2492 item 6): entity type, byte
    /// offset, and byte length for every match of every configured
    /// pattern, over the SCANNED (pre-redaction) `content` -- never the
    /// matched text itself, so a decision record built from this cannot
    /// carry the value it flagged. Capped at
    /// [`sbproxy_security::span::MAX_DETECTION_SPANS`]; call sites that
    /// need the drop count read the second element of the returned pair.
    ///
    /// Independent of [`Self::check`]'s action/threshold logic: this
    /// scans every configured pattern rather than stopping at the first
    /// one that matches, because a caller building an audit record wants
    /// the full picture a block reason alone does not carry.
    pub fn detect_spans(&self, content: &str) -> (Vec<DetectionSpan>, usize) {
        let mut found = Vec::new();
        for pattern_type in &self.patterns {
            let re: &Regex = match pattern_type.as_str() {
                "email" => &EMAIL_RE,
                "phone" => &PHONE_RE,
                "ssn" => &SSN_RE,
                "credit_card" => &CREDIT_CARD_RE,
                "api_key" => &API_KEY_RE,
                _ => continue,
            };
            for m in re.find_iter(content) {
                found.push(DetectionSpan::new(pattern_type.clone(), m.start(), m.len()));
            }
        }
        cap_spans(found)
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

    // --- detect_spans (WOR-2492 item 6) ---

    #[test]
    fn detect_spans_reports_type_offset_and_len() {
        let guard = blocking_guard(vec!["email"]);
        let content = "Send to user@example.com please";
        let (spans, dropped) = guard.detect_spans(content);
        assert_eq!(dropped, 0);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, "email");
        let matched = &content[spans[0].offset..spans[0].offset + spans[0].len];
        assert_eq!(matched, "user@example.com");
    }

    #[test]
    fn detect_spans_covers_every_configured_pattern_not_just_the_first_match() {
        let guard = blocking_guard(vec!["email", "phone"]);
        let content = "Email user@example.com or call 555-123-4567";
        let (spans, dropped) = guard.detect_spans(content);
        assert_eq!(dropped, 0);
        let types: Vec<&str> = spans.iter().map(|s| s.entity_type.as_str()).collect();
        assert!(types.contains(&"email"));
        assert!(types.contains(&"phone"));
    }

    /// Red-first: the 33rd span is dropped, and the drop is a count,
    /// not silence.
    #[test]
    fn spans_past_the_cap_are_dropped_with_a_count() {
        let guard = blocking_guard(vec!["email"]);
        let mut content = String::new();
        for i in 0..40 {
            content.push_str(&format!("user{i}@example.com "));
        }
        let (spans, dropped) = guard.detect_spans(&content);
        assert_eq!(spans.len(), 32);
        assert_eq!(dropped, 8);
    }

    /// Privacy rule: a span is a position, never the matched value.
    /// Plant a distinctive secret and assert it never appears in the
    /// spans' debug output.
    #[test]
    fn spans_never_carry_the_matched_text() {
        let guard = blocking_guard(vec!["email"]);
        let planted = "definitely-not-a-real-address@example.com";
        let content = format!("leak check: {planted}");
        let (spans, _dropped) = guard.detect_spans(&content);
        assert!(!spans.is_empty());
        let debug = format!("{spans:?}");
        assert!(
            !debug.contains(planted),
            "detection spans must never carry the matched text, got: {debug}"
        );
    }

    #[test]
    fn detect_spans_on_clean_text_is_empty() {
        let guard = blocking_guard(vec!["email", "phone", "ssn", "credit_card"]);
        let (spans, dropped) = guard.detect_spans("Hello, how are you today?");
        assert!(spans.is_empty());
        assert_eq!(dropped, 0);
    }
}
