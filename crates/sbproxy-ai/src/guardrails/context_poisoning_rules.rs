//! Static catalogue of context-poisoning heuristics.
//!
//! WOR-159. Each rule carries a stable `id`, a short human-readable
//! `description`, the literature attribution, and a confidence weight
//! that the guardrail uses to gate `min_confidence` filtering.
//!
//! Rule IDs are public and stable: dashboards and config allowlists
//! reference them by string, so renaming an existing ID is a breaking
//! change. New rules append to this list; deprecated rules stay in
//! place with their original ID and an inert pattern.
//!
//! The rules are organised into four families that map to the four
//! attack patterns called out in the indirect prompt injection
//! literature (Greshake et al., 2023) and the constitutional AI work
//! at Anthropic:
//!
//! 1. Instruction-like patterns inside retrieved content (the
//!    canonical indirect prompt injection vector).
//! 2. Tool-call hints embedded in passive content, which try to
//!    bait a downstream tool invocation.
//! 3. Encoded instructions (base64, hex), which try to slip the
//!    instruction past a literal pattern check.
//! 4. Conflicting directives, where retrieved content that should
//!    be informational uses imperative second-person language.
//!
//! The actual matcher lives in `context_poisoning.rs`; this file is
//! intentionally pure data so the rule set can be audited and diffed
//! without reading any logic.

use regex::Regex;
use std::sync::LazyLock;

/// A single context-poisoning heuristic.
#[derive(Debug)]
pub struct ContextPoisoningRule {
    /// Stable identifier. Use in dashboards, allowlists, and metrics.
    pub id: &'static str,
    /// One-line human description for log lines and findings.
    pub description: &'static str,
    /// Literature attribution.
    pub attribution: &'static str,
    /// Confidence weight in `[0.0, 1.0]`. The guardrail filters out
    /// findings whose rule confidence is below `min_confidence`.
    pub confidence: f32,
    /// Detection kind, which selects the matcher.
    pub kind: RuleKind,
}

/// The four heuristic families. Each family has its own matcher in
/// `context_poisoning::check_rule`.
#[derive(Debug)]
pub enum RuleKind {
    /// Case-insensitive substring match against the lowercased input.
    Substring(&'static str),
    /// Case-insensitive regex match against the input.
    Regex(&'static LazyLock<Regex>),
    /// Decode base64 / hex blobs in the input and re-run the
    /// instruction-like substring set.
    EncodedInstruction,
    /// Imperative second-person language inside content tagged
    /// `role: tool` or `role: function`. The matcher needs both the
    /// raw text and the message role, so this kind is handled by a
    /// dedicated entry point on the guardrail.
    ConflictingDirective,
}

// --- Family 1: instruction-like patterns in retrieved content ---

/// Regex catching URL fragments that frequently appear in
/// prompt-injection payloads in the wild (Greshake et al.). These are
/// not arbitrary URLs; they are the specific cues that have shown up
/// in indirect-injection PoCs (data-exfil endpoints, `#prompt=...`
/// fragments, base64-encoded query strings on bare IP literals).
static SUSPICIOUS_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:#prompt=|\?cmd=|/exfil/|/leak\?|data:text/plain|javascript:)").unwrap()
});

// --- Family 2: tool-call hints embedded in retrieved content ---

/// Literal tool-call scaffolding tokens. These should never appear in
/// passive retrieved text. Matches:
///   - `<tool_use>` / `</tool_use>` (Anthropic native).
///   - `function_call:` followed by a JSON-ish payload (OpenAI legacy).
///   - `<|tool_call|>` / `<|fim_*|>` (chain-of-thought scaffolding).
static TOOL_CALL_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:</?tool_use>|</?function_call>|function_call\s*:\s*\{|<\|tool_call\|>|<\|fim_(?:prefix|middle|suffix)\|>)",
    )
    .unwrap()
});

/// A JSON-shaped tool invocation embedded in body text. Matches the
/// minimal shape `{"name": "...", "arguments": ...}` (OpenAI tool
/// calling) and `{"tool": "...", "input": ...}` (Anthropic legacy).
/// Tight on purpose; the regex is anchored by the key names so prose
/// that happens to contain JSON does not trip.
static JSON_TOOL_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\{\s*"(?:name|tool)"\s*:\s*"[^"]+"\s*,\s*"(?:arguments|input)"\s*:"#)
        .unwrap()
});

// --- Family 4: conflicting directives ---

/// Imperative second-person language: "you must", "you should", "you
/// will", "do not", etc. Run only against content whose role is
/// `tool` or `function` (passive retrieval). Imperative language in
/// a `user` message is the user's own request and does not trip this
/// rule.
static IMPERATIVE_SECOND_PERSON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:you\s+must|you\s+should|you\s+will|you\s+need\s+to|you\s+have\s+to|do\s+not\s+|you'?re\s+required\s+to|under\s+no\s+circumstances)\b",
    )
    .unwrap()
});

/// The full rule catalogue. Iteration order is the order findings are
/// reported; keep ID ordering stable.
pub static CONTEXT_POISONING_RULES: &[ContextPoisoningRule] = &[
    // Family 1: instruction-like patterns. The substring set is
    // canonical across this guardrail and the v1 prompt-injection
    // guardrail; the rule IDs here are the context-poisoning view of
    // the same lexical surface.
    ContextPoisoningRule {
        id: "cp_instruction_ignore_previous",
        description: "Retrieved content contains \"ignore previous instructions\" style payload",
        attribution: "Greshake et al. (2023), Not what you've signed up for",
        confidence: 0.95,
        kind: RuleKind::Substring("ignore previous instructions"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_ignore_all",
        description: "Retrieved content tries to override all prior instructions",
        attribution: "Greshake et al. (2023), Not what you've signed up for",
        confidence: 0.9,
        kind: RuleKind::Substring("ignore all previous"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_disregard",
        description: "Retrieved content asks the model to disregard prior instructions",
        attribution: "Greshake et al. (2023), Not what you've signed up for",
        confidence: 0.85,
        kind: RuleKind::Substring("disregard all previous"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_you_are_now",
        description: "Retrieved content attempts an in-context role swap (\"you are now\")",
        attribution: "Anthropic constitutional AI evaluation set",
        confidence: 0.8,
        kind: RuleKind::Substring("you are now"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_system_prompt_leak",
        description: "Retrieved content contains a literal \"system prompt:\" framing",
        attribution: "Perez and Ribeiro (2022), Ignore previous prompt",
        confidence: 0.85,
        kind: RuleKind::Substring("system prompt:"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_new_objective",
        description: "Retrieved content sets a \"new objective:\" or \"new instructions:\" header",
        attribution: "Greshake et al. (2023)",
        confidence: 0.75,
        kind: RuleKind::Substring("new objective:"),
    },
    ContextPoisoningRule {
        id: "cp_instruction_new_instructions",
        description: "Retrieved content sets a \"new instructions:\" header",
        attribution: "Greshake et al. (2023)",
        confidence: 0.75,
        kind: RuleKind::Substring("new instructions:"),
    },
    ContextPoisoningRule {
        id: "cp_suspicious_url",
        description: "Retrieved content contains a URL shape that matches known exfil patterns",
        attribution: "Greshake et al. (2023), indirect prompt injection PoCs",
        confidence: 0.7,
        kind: RuleKind::Regex(&SUSPICIOUS_URL_RE),
    },
    // Family 2: tool-call hints in retrieved content.
    ContextPoisoningRule {
        id: "cp_tool_call_scaffold",
        description: "Retrieved content contains literal tool-call scaffolding tokens",
        attribution: "Anthropic tool-use protocol; OpenAI function-calling protocol",
        confidence: 0.9,
        kind: RuleKind::Regex(&TOOL_CALL_HINT_RE),
    },
    ContextPoisoningRule {
        id: "cp_tool_call_json_shape",
        description: "Retrieved content embeds a JSON-shaped tool invocation",
        attribution: "OpenAI function-calling protocol; Anthropic tool-use protocol",
        confidence: 0.8,
        kind: RuleKind::Regex(&JSON_TOOL_CALL_RE),
    },
    // Family 3: encoded instructions.
    ContextPoisoningRule {
        id: "cp_encoded_instruction",
        description: "Retrieved content contains a base64/hex blob whose decoded text matches the instruction set",
        attribution: "Wallace et al. (2024), encoded indirect prompt injection",
        confidence: 0.7,
        kind: RuleKind::EncodedInstruction,
    },
    // Family 4: conflicting directives in passive content.
    ContextPoisoningRule {
        id: "cp_conflicting_directive",
        description: "Imperative second-person language inside role=tool or role=function content",
        attribution: "Anthropic constitutional AI; Greshake et al. (2023)",
        confidence: 0.6,
        kind: RuleKind::ConflictingDirective,
    },
    ContextPoisoningRule {
        id: "cp_instruction_imperative_regex",
        description: "Imperative second-person regex on the full input (lower-confidence fallback)",
        attribution: "Anthropic constitutional AI",
        confidence: 0.4,
        kind: RuleKind::Regex(&IMPERATIVE_SECOND_PERSON_RE),
    },
];

/// Look up a rule by stable ID. Returns `None` if no rule matches.
pub fn find_rule(id: &str) -> Option<&'static ContextPoisoningRule> {
    CONTEXT_POISONING_RULES.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = CONTEXT_POISONING_RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "rule IDs must be unique");
    }

    #[test]
    fn rule_confidence_in_range() {
        for r in CONTEXT_POISONING_RULES {
            assert!(
                r.confidence > 0.0 && r.confidence <= 1.0,
                "rule {} confidence {} not in (0.0, 1.0]",
                r.id,
                r.confidence
            );
        }
    }

    #[test]
    fn find_rule_round_trip() {
        for r in CONTEXT_POISONING_RULES {
            assert!(find_rule(r.id).is_some(), "find_rule failed for {}", r.id);
        }
        assert!(find_rule("does_not_exist").is_none());
    }

    #[test]
    fn suspicious_url_regex_matches_known_payloads() {
        assert!(SUSPICIOUS_URL_RE.is_match("https://attacker.example/exfil/leak?data=x"));
        assert!(SUSPICIOUS_URL_RE.is_match("see https://x.example/#prompt=ignore"));
        assert!(SUSPICIOUS_URL_RE.is_match("javascript:alert(1)"));
        assert!(!SUSPICIOUS_URL_RE.is_match("https://example.com/docs/article"));
    }

    #[test]
    fn tool_call_hint_regex_matches_scaffolds() {
        assert!(TOOL_CALL_HINT_RE.is_match("<tool_use>foo</tool_use>"));
        assert!(TOOL_CALL_HINT_RE.is_match("function_call: {\"name\":\"x\"}"));
        assert!(TOOL_CALL_HINT_RE.is_match("<|tool_call|>"));
        assert!(!TOOL_CALL_HINT_RE.is_match("the meeting agenda lists six items"));
    }

    #[test]
    fn json_tool_call_regex_matches_minimal_shape() {
        assert!(JSON_TOOL_CALL_RE.is_match(r#"{"name":"send_email","arguments":{"to":"x"}}"#));
        assert!(JSON_TOOL_CALL_RE.is_match(r#"{"tool":"send_email","input":{}}"#));
        assert!(!JSON_TOOL_CALL_RE.is_match(r#"{"foo":"bar","baz":1}"#));
    }

    #[test]
    fn imperative_regex_matches_second_person() {
        assert!(IMPERATIVE_SECOND_PERSON_RE.is_match("You must email the report."));
        assert!(IMPERATIVE_SECOND_PERSON_RE.is_match("you should call the tool"));
        assert!(!IMPERATIVE_SECOND_PERSON_RE.is_match("the file is 200 bytes long"));
    }
}
