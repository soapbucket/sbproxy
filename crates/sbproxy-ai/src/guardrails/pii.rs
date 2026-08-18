//! PII detection guardrail - email, phone, SSN, credit card patterns.

use regex::Regex;
use serde::{de, Deserialize};
use std::sync::LazyLock;

use super::GuardrailBlock;

/// Action to take when PII is detected.
///
/// `check` (below) is the only entry point every caller uses, and its
/// signature is `fn check(&self, content: &str) -> Option<GuardrailBlock>`:
/// allow or block, nothing else. That is why `Mask` cannot be
/// deserialized from config (see the `Deserialize` impl) - there is no
/// return path for rewritten content, so accepting `action: mask`
/// would silently behave like an unlogged allow, which is exactly the
/// dead-knob trap this type used to set. `Log` does not have that
/// problem: allow-and-log needs no return value beyond `None`.
#[derive(Debug, Clone, Default)]
pub enum PiiAction {
    /// Reject the request with an error response (default).
    #[default]
    Block,
    /// Replace detected PII with mask characters and continue.
    ///
    /// Reachable only by constructing a [`PiiGuardrail`] directly in
    /// Rust (tests do this); config deserialization refuses it. See
    /// the type-level doc comment.
    Mask,
    /// Log the detection event, structured and bounded (the pattern
    /// type only, never the matched text or the surrounding content),
    /// and allow the request through unchanged.
    Log,
}

impl<'de> Deserialize<'de> for PiiAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "block" => Ok(PiiAction::Block),
            "log" => Ok(PiiAction::Log),
            "mask" => Err(de::Error::custom(
                "pii guardrail action \"mask\" is refused at config load: `PiiGuardrail::check` \
                 can only allow or block, it has no path to return rewritten content, so \
                 `action: mask` has always silently behaved like an unlogged allow rather than \
                 masking anything. Use `action: block` to refuse the request, or `action: log` \
                 to allow it while emitting a structured, bounded detection event. Body-level \
                 masking exists today via the AI guardrail mesh's `redact_on_flag` \
                 (docs/ai-guardrail-mesh.md) or the `pii:` JSON-body redactor's \
                 `redact_request`, neither of which goes through this per-pattern action.",
            )),
            other => Err(de::Error::unknown_variant(other, &["block", "log"])),
        }
    }
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
                    PiiAction::Log => {
                        // Structured and bounded: the pattern type only,
                        // never `content` (which carries the match itself
                        // and, in the common case, a great deal of
                        // surrounding prompt/response text besides).
                        tracing::info!(
                            target: "sbproxy::pii_guardrail::audit",
                            guardrail = "pii",
                            action = "log",
                            pattern_type = pattern_type.as_str(),
                            "pii guardrail: detected {pattern_type}; action=log, request allowed"
                        );
                        None
                    }
                    // Unreachable via config (see the `Deserialize` impl);
                    // a directly constructed `Mask` guardrail still has no
                    // way to return rewritten content through this
                    // signature, so it remains a no-op, same as today.
                    PiiAction::Mask => None,
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

    // --- WOR-2489: dead-knob wiring ---

    #[test]
    fn mask_action_is_refused_at_config_load() {
        let err = serde_json::from_value::<PiiGuardrail>(serde_json::json!({
            "patterns": ["email"],
            "action": "mask",
        }))
        .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("mask"),
            "error should name the refused action: {message}"
        );
        assert!(
            message.contains("no path to return rewritten content"),
            "error should explain why, not just reject the value: {message}"
        );
    }

    #[test]
    fn block_and_log_still_deserialize() {
        let block: PiiGuardrail = serde_json::from_value(serde_json::json!({
            "patterns": ["email"],
            "action": "block",
        }))
        .unwrap();
        assert!(matches!(block.action, PiiAction::Block));

        let log: PiiGuardrail = serde_json::from_value(serde_json::json!({
            "patterns": ["email"],
            "action": "log",
        }))
        .unwrap();
        assert!(matches!(log.action, PiiAction::Log));
    }

    #[test]
    fn unrecognised_action_is_a_plain_unknown_variant_error() {
        let err = serde_json::from_value::<PiiGuardrail>(serde_json::json!({
            "patterns": ["email"],
            "action": "redact",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("redact"));
    }

    // --- Log action: structured, bounded logging ---

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Debug, Default, Clone)]
    struct CapturedEvent {
        fields: HashMap<String, String>,
    }

    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    struct MapVisitor<'a> {
        out: &'a mut HashMap<String, String>,
    }

    impl Visit for MapVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.out
                .insert(field.name().to_string(), format!("{:?}", value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.out.insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = HashMap::new();
            event.record(&mut MapVisitor { out: &mut fields });
            self.events
                .lock()
                .expect("capture mutex poisoned")
                .push(CapturedEvent { fields });
        }
    }

    #[test]
    fn log_action_emits_one_structured_event_and_never_the_matched_text() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        let guard = PiiGuardrail {
            patterns: vec!["email".to_string()],
            action: PiiAction::Log,
        };
        let content = "reach me at alice@example.com please";
        let result = tracing::subscriber::with_default(subscriber, || guard.check(content));

        assert!(result.is_none(), "log action must allow the request");

        let events = layer.events.lock().expect("capture mutex poisoned").clone();
        assert_eq!(
            events.len(),
            1,
            "expected exactly one detection event, got {events:?}"
        );
        let fields = &events[0].fields;
        assert_eq!(
            fields.get("pattern_type").map(String::as_str),
            Some("email")
        );
        assert_eq!(fields.get("guardrail").map(String::as_str), Some("pii"));
        assert_eq!(fields.get("action").map(String::as_str), Some("log"));
        for (name, value) in fields {
            assert!(
                !value.contains("alice@example.com"),
                "logged event must never carry the matched PII value; field {name:?} held {value:?}"
            );
        }
    }

    #[test]
    fn log_action_emits_nothing_on_clean_content() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        let guard = PiiGuardrail {
            patterns: vec!["email".to_string()],
            action: PiiAction::Log,
        };
        let result =
            tracing::subscriber::with_default(subscriber, || guard.check("nothing sensitive"));
        assert!(result.is_none());
        assert!(layer
            .events
            .lock()
            .expect("capture mutex poisoned")
            .is_empty());
    }
}
