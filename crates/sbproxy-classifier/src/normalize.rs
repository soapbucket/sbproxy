//! Text normalization pipeline, applied before classification.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `normalize.rs`.
//! Every registered tenant has its own [`Normalizer`] compiled from its
//! config. Normalization runs in two stages:
//!
//! 1. **Unicode NFKC** (if enabled) - collapses compatibility forms so
//!    visual look-alikes match the same label (e.g., full-width Latin ->
//!    ASCII).
//! 2. **Regex substitutions** - a list of `(pattern, replacement)` rules
//!    applied in order. Used for things like redacting tokens (the PII
//!    redaction the ticket calls out is configured this way: an operator
//!    registers an `email` / `phone` / etc. rule with a `<REDACTED>`
//!    replacement), collapsing whitespace, and lowercasing domain-specific
//!    markers.
//!
//! The same regex-safety rules as [`crate::heuristic`] apply here:
//! [`RegexBuilder::size_limit`] caps compilation memory, and patterns over
//! `MAX_PATTERN_LENGTH` are rejected. Rust's `regex` crate has no
//! backtracking, so ReDoS is not a concern.

use crate::config::NormalizationConfig;
use regex::{Regex, RegexBuilder};
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

/// Max compiled regex size in bytes.
const REGEX_SIZE_LIMIT: usize = 10 * 1024 * 1024;

/// Max pattern string length.
const MAX_PATTERN_LENGTH: usize = 4096;

/// Compiled normalization rule ready for fast execution.
struct CompiledRule {
    regex: Regex,
    replace: String,
}

/// Pre-compiled normalization pipeline. Built once from config, reused per
/// request.
pub struct Normalizer {
    unicode_nfkc: bool,
    trim: bool,
    rules: Vec<CompiledRule>,
}

impl Normalizer {
    /// Build a normalizer from config, compiling all regex patterns upfront.
    pub fn from_config(config: &NormalizationConfig) -> Self {
        let rules = config
            .rules
            .iter()
            .filter(|r| r.enabled)
            .filter_map(|r| {
                if r.pattern.len() > MAX_PATTERN_LENGTH {
                    warn!(rule = %r.name, len = r.pattern.len(), "regex pattern too long (max {}), skipping", MAX_PATTERN_LENGTH);
                    return None;
                }
                match RegexBuilder::new(&r.pattern).size_limit(REGEX_SIZE_LIMIT).build() {
                    Ok(regex) => Some(CompiledRule {
                        regex,
                        replace: r.replace.clone(),
                    }),
                    Err(e) => {
                        warn!(
                            rule = %r.name,
                            pattern = %r.pattern,
                            error = %e,
                            "invalid normalization regex, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        Self {
            unicode_nfkc: config.unicode_nfkc,
            trim: config.trim,
            rules,
        }
    }

    /// Apply the full normalization pipeline to input text.
    pub fn normalize(&self, text: &str) -> String {
        let mut result = if self.unicode_nfkc {
            text.nfkc().collect::<String>()
        } else {
            text.to_string()
        };

        for rule in &self.rules {
            result = rule
                .regex
                .replace_all(&result, rule.replace.as_str())
                .into_owned();
        }

        if self.trim {
            result = result.trim().to_string();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NormalizationConfig, NormalizationRule};

    fn test_normalizer() -> Normalizer {
        let config = NormalizationConfig {
            unicode_nfkc: true,
            trim: true,
            rules: vec![
                NormalizationRule {
                    name: "urls".into(),
                    pattern: r"https?://\S+".into(),
                    replace: "<URL>".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "emails".into(),
                    pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into(),
                    replace: "<EMAIL>".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "repeated_punct".into(),
                    pattern: r"([!?.]){2,}".into(),
                    replace: "$1".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "whitespace".into(),
                    pattern: r"\s+".into(),
                    replace: " ".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "disabled_rule".into(),
                    pattern: r"foo".into(),
                    replace: "bar".into(),
                    enabled: false,
                },
            ],
        };
        Normalizer::from_config(&config)
    }

    #[test]
    fn url_is_replaced() {
        let n = test_normalizer();
        assert_eq!(
            n.normalize("check https://example.com/foo please"),
            "check <URL> please"
        );
    }

    #[test]
    fn email_is_replaced() {
        let n = test_normalizer();
        assert_eq!(
            n.normalize("contact user@example.com for info"),
            "contact <EMAIL> for info"
        );
    }

    #[test]
    fn whitespace_collapses() {
        let n = test_normalizer();
        assert_eq!(n.normalize("hello    world\n\nfoo"), "hello world foo");
    }

    #[test]
    fn repeated_punctuation_collapses() {
        let n = test_normalizer();
        assert_eq!(n.normalize("what???!!!"), "what!");
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let n = test_normalizer();
        assert_eq!(n.normalize("foo bar"), "foo bar");
    }

    #[test]
    fn oversized_pattern_is_rejected_at_compile_time() {
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        let config = NormalizationConfig {
            unicode_nfkc: false,
            trim: false,
            rules: vec![NormalizationRule {
                name: "too_long".into(),
                pattern: long_pattern,
                replace: "x".into(),
                enabled: true,
            }],
        };
        let n = Normalizer::from_config(&config);
        assert_eq!(n.rules.len(), 0);
    }

    #[test]
    fn invalid_regex_is_skipped() {
        let config = NormalizationConfig {
            unicode_nfkc: false,
            trim: false,
            rules: vec![NormalizationRule {
                name: "bad_regex".into(),
                pattern: r"[invalid".into(),
                replace: "x".into(),
                enabled: true,
            }],
        };
        let n = Normalizer::from_config(&config);
        assert_eq!(n.rules.len(), 0);
    }

    /// Demonstrates the PII-redaction capability the ticket names: an
    /// operator registers rules like these three (over the wire, in a
    /// tenant's `normalization.rules`) to redact email addresses, phone
    /// numbers, and credit-card-shaped digit runs before classification
    /// sees the text. `credit_card` runs before `phone`: a 13-16 digit
    /// card number with space or dash separators also syntactically
    /// matches the looser phone pattern, so the more specific rule claims
    /// the digits first.
    #[test]
    fn operator_configured_pii_rules_redact_email_card_and_phone() {
        let config = NormalizationConfig {
            unicode_nfkc: false,
            trim: true,
            rules: vec![
                NormalizationRule {
                    name: "email".into(),
                    pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into(),
                    replace: "<EMAIL>".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "credit_card".into(),
                    pattern: r"\b(?:\d[ -]?){13,16}\b".into(),
                    replace: "<CARD>".into(),
                    enabled: true,
                },
                NormalizationRule {
                    name: "phone".into(),
                    pattern: r"\+?\d[\d\-. ]{7,14}\d".into(),
                    replace: "<PHONE>".into(),
                    enabled: true,
                },
            ],
        };
        let n = Normalizer::from_config(&config);
        let out = n.normalize("email me at a@b.com, card 4111 1111 1111 1111, call 555-123-4567");
        assert!(out.contains("<EMAIL>"));
        assert!(out.contains("<CARD>"));
        assert!(out.contains("<PHONE>"));
        assert!(!out.contains("a@b.com"));
    }
}
