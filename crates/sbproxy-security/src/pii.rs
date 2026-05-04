//! Pattern-aware PII redaction.
//!
//! Replaces matches of a configurable rule set with a fixed marker
//! (default `[REDACTED:<NAME>]`). Designed for the AI request /
//! response body boundary so prompts and completions never carry
//! email addresses, credit card numbers, or API key shapes through to
//! upstream providers and logs.
//!
//! ## Default rules
//!
//! | Name           | Anchors               | Validator | Replacement              |
//! |----------------|-----------------------|-----------|--------------------------|
//! | `email`        | `@`                   | none      | `[REDACTED:EMAIL]`       |
//! | `us_ssn`       | none                  | none      | `[REDACTED:SSN]`         |
//! | `credit_card`  | digits                | Luhn      | `[REDACTED:CARD]`        |
//! | `phone_us`     | digits                | none      | `[REDACTED:PHONE]`       |
//! | `ipv4`         | digits                | none      | `[REDACTED:IP]`          |
//! | `openai_key`   | `sk-`                 | none      | `[REDACTED:APIKEY]`      |
//! | `anthropic_key`| `sk-ant-`             | none      | `[REDACTED:APIKEY]`      |
//! | `aws_access`   | `AKIA`                | none      | `[REDACTED:APIKEY]`      |
//! | `github_token` | `ghp_`/`ghs_`/etc.    | none      | `[REDACTED:APIKEY]`      |
//!
//! ## Anchored prefilter
//!
//! Most strings flowing through the AI handler contain no PII. To keep
//! redaction cheap on the hot path the redactor first runs an
//! Aho-Corasick scan over a small set of literal anchors (e.g. `@`,
//! `sk-`, `AKIA`). Only rules whose anchor is present are then
//! evaluated with the full regex. Rules without an anchor (SSN,
//! credit card, phone, IPv4) always run, but they are also the rules
//! that need to. The combined cost on a clean payload is one linear
//! pass over the body.
//!
//! ## Custom rules
//!
//! Operators add custom rules via [`PiiRule`] entries decoded from
//! sb.yml. Each custom rule supplies a regex pattern and an optional
//! replacement; when the replacement is omitted the redactor uses
//! `[REDACTED:<NAME>]` keyed on the rule's name.

use std::borrow::Cow;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Deserialize;

// --- Public API: legacy log-time helpers ---
//
// These are kept as thin shims around the new redactor so callers in
// the access-log path do not break. New callers should prefer
// `PiiRedactor`.

/// Mask an email address: `"user@example.com"` -> `"u***@example.com"`.
///
/// Retained for log-time call sites; new code should use
/// [`PiiRedactor`] which redacts every PII shape in one pass.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            if local.is_empty() {
                return format!("***@{}", domain);
            }
            let first = &local[..local.chars().next().unwrap().len_utf8()];
            format!("{}***@{}", first, domain)
        }
        None => "***".to_string(),
    }
}

/// Mask a credit card number: `"4111111111111111"` -> `"****1111"`.
///
/// Strips non-digits before applying. Retained for log-time call
/// sites; new code should use [`PiiRedactor`].
pub fn mask_credit_card(cc: &str) -> String {
    let digits: String = cc.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "****".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("****{}", last4)
}

/// Mask an IPv4 address: `"192.168.1.100"` -> `"192.168.x.x"`.
///
/// Non-IPv4 input is replaced with the placeholder `"x.x.x.x"`.
/// Retained for log-time call sites; new code should use
/// [`PiiRedactor`].
pub fn mask_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.x.x", parts[0], parts[1])
    } else {
        "x.x.x.x".to_string()
    }
}

// --- Configuration ---

/// User-supplied PII rule entry.
///
/// Decoded from sb.yml under `pii: { rules: [...] }`. The `name`
/// drives the default replacement (`[REDACTED:NAME]`) when no
/// explicit `replacement` is set.
#[derive(Debug, Clone, Deserialize)]
pub struct PiiRule {
    /// Stable rule identifier, used in the default replacement and
    /// in metrics labels.
    pub name: String,
    /// Regex pattern. Compiled once at config load.
    pub pattern: String,
    /// Optional explicit replacement string. Defaults to
    /// `[REDACTED:<NAME>]` (uppercased name) when absent.
    #[serde(default)]
    pub replacement: Option<String>,
    /// Optional validator name. Currently supported: `"luhn"` for
    /// credit card sanity checking.
    #[serde(default)]
    pub validator: Option<String>,
    /// Optional anchor literal used to short-circuit evaluation when
    /// the input does not contain any anchor. Skipped when absent.
    #[serde(default)]
    pub anchor: Option<String>,
}

/// Top-level PII redactor configuration as it appears in sb.yml.
///
/// ```yaml
/// pii:
///   enabled: true
///   defaults: true
///   redact_request: true
///   redact_response: false
///   rules:
///     - name: internal_ticket
///       pattern: '\bTICKET-[0-9]{6}\b'
///       replacement: '[REDACTED:TICKET]'
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct PiiConfig {
    /// Master switch. When `false` the redactor is a no-op and
    /// `request_body` / `response_body` flow through unchanged.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Include the built-in default rule set (email, SSN, credit
    /// card, phone, IPv4, common API key shapes). Defaults to true
    /// so a bare `pii: { enabled: true }` block does the right
    /// thing.
    #[serde(default = "default_enabled")]
    pub defaults: bool,
    /// Apply redaction to inbound request bodies. Defaults true.
    #[serde(default = "default_enabled")]
    pub redact_request: bool,
    /// Apply redaction to outbound response bodies. Defaults false
    /// because response bodies are usually generated content that
    /// callers want to see verbatim; opt in when streaming logs out.
    #[serde(default)]
    pub redact_response: bool,
    /// User-supplied custom rules, applied after defaults.
    #[serde(default)]
    pub rules: Vec<PiiRule>,
}

fn default_enabled() -> bool {
    true
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            defaults: true,
            redact_request: true,
            redact_response: false,
            rules: Vec::new(),
        }
    }
}

// --- Compiled rule + redactor ---

/// Validators that can post-filter a regex match. Used to suppress
/// false positives (e.g. random 16-digit sequences that fail the
/// credit-card Luhn check).
#[derive(Debug, Clone, Copy)]
pub enum RuleValidator {
    /// Mod-10 / Luhn sum check, applied to credit card matches.
    Luhn,
}

/// One compiled rule. Built once at startup and shared across
/// requests via `Arc<PiiRedactor>`.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule name (drives metrics labels and default replacement).
    pub name: String,
    /// Compiled regex.
    pub regex: Regex,
    /// Replacement string. Pre-rendered from `replacement` or
    /// `[REDACTED:<NAME>]`.
    pub replacement: String,
    /// Optional validator.
    pub validator: Option<RuleValidator>,
    /// Optional anchor literal. Used by the prefilter.
    pub anchor: Option<String>,
}

/// Compiled redactor: rule set + Aho-Corasick prefilter.
///
/// Cheap to clone: the rules and prefilter live behind an `Arc` so
/// the request-path can take a lightweight handle.
#[derive(Debug, Clone)]
pub struct PiiRedactor {
    inner: Arc<RedactorInner>,
}

#[derive(Debug)]
struct RedactorInner {
    /// Rules that always run (no anchor, or anchor evaluated lazily).
    unanchored_rules: Vec<CompiledRule>,
    /// Rules that only run when their anchor literal is present in
    /// the input. Indexed parallel to `prefilter_patterns`.
    anchored_rules: Vec<CompiledRule>,
    /// Aho-Corasick over the anchor literals. Drives the prefilter.
    prefilter: Option<AhoCorasick>,
    /// Patterns that the prefilter knows about, in the same order as
    /// the AC automaton matched them. We do not actually need this
    /// for matching but keep it for debug visibility.
    #[allow(dead_code)]
    prefilter_patterns: Vec<String>,
}

impl PiiRedactor {
    /// Build a redactor from a config block. Defaults are appended
    /// first when `config.defaults` is true; user rules follow so
    /// they can override default replacements by re-declaring the
    /// same `name` with a custom pattern.
    pub fn from_config(config: &PiiConfig) -> anyhow::Result<Self> {
        let mut rules: Vec<CompiledRule> = Vec::new();
        if config.defaults {
            for rule in default_rules() {
                rules.push(compile_rule(&rule)?);
            }
        }
        for rule in &config.rules {
            rules.push(compile_rule(rule)?);
        }
        Ok(Self::from_compiled(rules))
    }

    /// Build a redactor with the built-in default rule set only.
    pub fn defaults() -> Self {
        let rules = default_rules()
            .into_iter()
            .map(|r| compile_rule(&r).expect("default rule compiles"))
            .collect();
        Self::from_compiled(rules)
    }

    fn from_compiled(rules: Vec<CompiledRule>) -> Self {
        let mut unanchored_rules = Vec::new();
        let mut anchored_rules = Vec::new();
        let mut prefilter_patterns = Vec::new();
        for r in rules {
            match &r.anchor {
                Some(a) if !a.is_empty() => {
                    prefilter_patterns.push(a.clone());
                    anchored_rules.push(r);
                }
                _ => unanchored_rules.push(r),
            }
        }
        let prefilter = if prefilter_patterns.is_empty() {
            None
        } else {
            // Case-insensitive AC keeps the prefilter from missing
            // mixed-case keys (e.g. `Sk-...`). Rules' regex layer
            // still enforces the canonical case.
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&prefilter_patterns)
                .ok()
        };
        Self {
            inner: Arc::new(RedactorInner {
                unanchored_rules,
                anchored_rules,
                prefilter,
                prefilter_patterns,
            }),
        }
    }

    /// Returns true when the redactor has no rules. Acts as a fast
    /// short-circuit for callers that wrap an Option.
    pub fn is_empty(&self) -> bool {
        self.inner.unanchored_rules.is_empty() && self.inner.anchored_rules.is_empty()
    }

    /// Redact a single string. Returns `Cow::Borrowed` when the
    /// input contained no PII so the caller pays no allocation cost
    /// on the (common) clean path.
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if self.is_empty() {
            return Cow::Borrowed(input);
        }
        let mut current = Cow::Borrowed(input);

        // Unanchored rules: always run.
        for rule in &self.inner.unanchored_rules {
            current = apply_rule(rule, current);
        }

        // Anchored rules: prefilter to skip rules whose anchor is
        // not present. We use overlapping iteration because anchors
        // can overlap (e.g. `sk-` is a prefix of `sk-ant-`); a
        // non-overlapping pass would miss the longer pattern when
        // both are present at the same offset.
        if let Some(prefilter) = &self.inner.prefilter {
            let mut hits = vec![false; self.inner.anchored_rules.len()];
            let mut any_hit = false;
            for m in prefilter.find_overlapping_iter(current.as_ref()) {
                hits[m.pattern().as_usize()] = true;
                any_hit = true;
            }
            if any_hit {
                for (i, rule) in self.inner.anchored_rules.iter().enumerate() {
                    if hits[i] {
                        current = apply_rule(rule, current);
                    }
                }
            }
        } else {
            // Misconfigured prefilter (zero patterns): fall back to
            // running every anchored rule.
            for rule in &self.inner.anchored_rules {
                current = apply_rule(rule, current);
            }
        }

        current
    }

    /// Recursively walk a [`serde_json::Value`] and redact every
    /// string leaf in place. Object keys are not redacted (they are
    /// schema-defined names like `prompt`/`messages`).
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        if self.is_empty() {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                let redacted = self.redact(s);
                if let Cow::Owned(new_s) = redacted {
                    *s = new_s;
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter_mut() {
                    self.redact_json(v);
                }
            }
            serde_json::Value::Object(obj) => {
                for (_k, v) in obj.iter_mut() {
                    self.redact_json(v);
                }
            }
            _ => {}
        }
    }

    /// Redact a request/response body. Tries JSON first; on parse
    /// failure falls back to treating the body as opaque text and
    /// redacting in place.
    pub fn redact_body(&self, body: &[u8]) -> Vec<u8> {
        if self.is_empty() || body.is_empty() {
            return body.to_vec();
        }
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) {
            self.redact_json(&mut value);
            // JSON re-serialisation may reorder keys (BTreeMap) but
            // serde_json::Map preserves insertion order via
            // preserve_order feature when enabled. Either way the
            // result is semantically equivalent.
            return serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec());
        }
        // Non-JSON: treat the bytes as UTF-8 text. Bytes that are
        // not valid UTF-8 pass through unchanged - we never produce
        // partially-redacted invalid UTF-8 because that would break
        // downstream parsers.
        match std::str::from_utf8(body) {
            Ok(s) => self.redact(s).into_owned().into_bytes(),
            Err(_) => body.to_vec(),
        }
    }
}

fn apply_rule<'a>(rule: &CompiledRule, input: Cow<'a, str>) -> Cow<'a, str> {
    let replacement = rule.replacement.as_str();
    let validator = rule.validator;
    // We only allocate when `replace_all` actually returns Owned
    // because the regex matched at least once.
    let result = rule
        .regex
        .replace_all(input.as_ref(), |caps: &regex::Captures| {
            let matched = &caps[0];
            if let Some(v) = validator {
                if !run_validator(v, matched) {
                    return matched.to_string();
                }
            }
            replacement.to_string()
        });
    match result {
        Cow::Borrowed(_) => input,
        Cow::Owned(s) => Cow::Owned(s),
    }
}

fn run_validator(v: RuleValidator, matched: &str) -> bool {
    match v {
        RuleValidator::Luhn => luhn_valid(matched),
    }
}

/// Standard Luhn / mod-10 checksum.
///
/// Strips non-digit separators (spaces, dashes) before computing
/// the sum so common credit-card formatting like `4111-1111-1111-1111`
/// validates the same way as `4111111111111111`.
fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 12 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

fn compile_rule(rule: &PiiRule) -> anyhow::Result<CompiledRule> {
    let regex = Regex::new(&rule.pattern)
        .map_err(|e| anyhow::anyhow!("PII rule '{}' regex compile failed: {}", rule.name, e))?;
    let replacement = rule
        .replacement
        .clone()
        .unwrap_or_else(|| format!("[REDACTED:{}]", rule.name.to_ascii_uppercase()));
    let validator = match rule.validator.as_deref() {
        None | Some("") => None,
        Some("luhn") => Some(RuleValidator::Luhn),
        Some(other) => {
            anyhow::bail!("PII rule '{}' has unknown validator '{}'", rule.name, other)
        }
    };
    Ok(CompiledRule {
        name: rule.name.clone(),
        regex,
        replacement,
        validator,
        anchor: rule.anchor.clone(),
    })
}

/// Default detector catalogue: returns the built-in PII / secrets
/// regex rules. Useful for downstream policies (DLP) that want to
/// reuse the catalogue without going through the full Redactor
/// pipeline.
pub fn default_rules() -> Vec<PiiRule> {
    vec![
        PiiRule {
            name: "email".to_string(),
            // RFC 5322 simplified: local@domain with a TLD of 2+
            // alphabetic characters. We do not try to match every
            // valid email; we match every shape an operator would
            // call PII.
            pattern: r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b".to_string(),
            replacement: Some("[REDACTED:EMAIL]".to_string()),
            validator: None,
            anchor: Some("@".to_string()),
        },
        PiiRule {
            name: "us_ssn".to_string(),
            // Three-two-four format with explicit separators. The
            // bare "9 digits" form is intentionally excluded
            // because it generates massive false-positive rates on
            // tokenised content. We accept the entire 3-2-4 shape
            // even when the leading area-code byte is in a
            // technically-unassigned range (000, 666, 9xx); a
            // permissive redactor is the safer default.
            pattern: r"\b\d{3}[- ]\d{2}[- ]\d{4}\b".to_string(),
            replacement: Some("[REDACTED:SSN]".to_string()),
            validator: None,
            anchor: None,
        },
        PiiRule {
            name: "credit_card".to_string(),
            // 13-19 digits with optional separators, validated via
            // Luhn so we do not redact arbitrary ID numbers that
            // happen to look like card shapes.
            pattern: r"\b(?:\d[ -]?){12,18}\d\b".to_string(),
            replacement: Some("[REDACTED:CARD]".to_string()),
            validator: Some("luhn".to_string()),
            anchor: None,
        },
        PiiRule {
            name: "phone_us".to_string(),
            // North-American Numbering Plan: optional +1, then
            // (NXX) NXX-XXXX where N is 2-9. Excluding leading-1
            // area codes keeps fake-looking numbers like
            // 111-111-1111 from matching. We do not anchor with
            // `\b` at the front because the phone may begin with
            // `+` which is itself a non-word character; the regex
            // engine would refuse to enter the match at that
            // position. The trailing `\b` plus the strict 2-9
            // leading digit on the area code is enough to keep us
            // out of arbitrary digit runs.
            pattern: r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b"
                .to_string(),
            replacement: Some("[REDACTED:PHONE]".to_string()),
            validator: None,
            anchor: None,
        },
        PiiRule {
            name: "ipv4".to_string(),
            pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
                .to_string(),
            replacement: Some("[REDACTED:IP]".to_string()),
            validator: None,
            anchor: None,
        },
        PiiRule {
            name: "openai_key".to_string(),
            pattern: r"\bsk-[A-Za-z0-9]{20,}\b".to_string(),
            replacement: Some("[REDACTED:APIKEY]".to_string()),
            validator: None,
            anchor: Some("sk-".to_string()),
        },
        PiiRule {
            name: "anthropic_key".to_string(),
            pattern: r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b".to_string(),
            replacement: Some("[REDACTED:APIKEY]".to_string()),
            validator: None,
            anchor: Some("sk-ant-".to_string()),
        },
        PiiRule {
            name: "aws_access".to_string(),
            pattern: r"\bAKIA[0-9A-Z]{16}\b".to_string(),
            replacement: Some("[REDACTED:APIKEY]".to_string()),
            validator: None,
            anchor: Some("AKIA".to_string()),
        },
        PiiRule {
            name: "github_token".to_string(),
            pattern: r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b".to_string(),
            replacement: Some("[REDACTED:APIKEY]".to_string()),
            validator: None,
            anchor: Some("gh".to_string()),
        },
        PiiRule {
            name: "slack_token".to_string(),
            // Slack issues five token-class prefixes: xoxb (bot),
            // xoxp (user), xoxa (workspace), xoxr (refresh),
            // xoxs (legacy). The body is variable-length but always
            // dot-separated in current formats.
            pattern: r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b".to_string(),
            replacement: Some("[REDACTED:APIKEY]".to_string()),
            validator: None,
            anchor: Some("xox".to_string()),
        },
        PiiRule {
            name: "iban".to_string(),
            // Two-letter country code + two check digits + 11-30
            // alphanumerics. We accept both contiguous and
            // space-separated forms (banking interfaces routinely
            // print them in groups of four).
            pattern: r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b"
                .to_string(),
            replacement: Some("[REDACTED:IBAN]".to_string()),
            validator: None,
            anchor: None,
        },
    ]
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> PiiRedactor {
        PiiRedactor::defaults()
    }

    // --- Legacy log-time helper tests (preserve old behaviour) ---

    #[test]
    fn legacy_mask_email_keeps_first_char() {
        assert_eq!(mask_email("user@example.com"), "u***@example.com");
        assert_eq!(mask_email("a@test.org"), "a***@test.org");
        assert_eq!(mask_email("invalid"), "***");
        assert_eq!(mask_email("@example.com"), "***@example.com");
    }

    #[test]
    fn legacy_mask_credit_card_returns_last_four() {
        assert_eq!(mask_credit_card("4111111111111111"), "****1111");
        assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****1111");
        assert_eq!(mask_credit_card("12"), "****");
    }

    #[test]
    fn legacy_mask_ip_v4_keeps_first_two_octets() {
        assert_eq!(mask_ip("192.168.1.100"), "192.168.x.x");
        assert_eq!(mask_ip("10.0.0.1"), "10.0.x.x");
        assert_eq!(mask_ip("::1"), "x.x.x.x");
    }

    // --- Default rule coverage ---

    #[test]
    fn redact_email_default() {
        let r = defaults();
        let out = r.redact("Email me at alice@example.com please.");
        assert_eq!(out, "Email me at [REDACTED:EMAIL] please.");
    }

    #[test]
    fn redact_us_ssn_default() {
        let r = defaults();
        let out = r.redact("My SSN is 123-45-6789.");
        assert_eq!(out, "My SSN is [REDACTED:SSN].");
    }

    #[test]
    fn redact_credit_card_default_with_luhn() {
        let r = defaults();
        // Stripe test card 4242-4242-4242-4242 passes Luhn.
        let out = r.redact("Card 4242-4242-4242-4242 stored.");
        assert_eq!(out, "Card [REDACTED:CARD] stored.");
    }

    #[test]
    fn credit_card_rule_skips_luhn_failure() {
        let r = defaults();
        // 16 digits but invalid Luhn -> not redacted.
        let out = r.redact("Order id 1234-5678-1234-5677 incoming.");
        assert!(
            out.contains("1234-5678-1234-5677"),
            "non-Luhn 16-digit string should NOT be redacted, got: {out}"
        );
    }

    #[test]
    fn redact_phone_default() {
        let r = defaults();
        let out = r.redact("Call me at +1 (555) 234-5678 tonight.");
        assert_eq!(out, "Call me at [REDACTED:PHONE] tonight.");
    }

    #[test]
    fn redact_ipv4_default() {
        let r = defaults();
        let out = r.redact("Server 192.168.1.100 is offline.");
        assert_eq!(out, "Server [REDACTED:IP] is offline.");
    }

    #[test]
    fn redact_openai_key_default() {
        let r = defaults();
        let out = r.redact("Use sk-1234567890abcdefghij1234 for testing.");
        assert!(out.contains("[REDACTED:APIKEY]"), "got {out}");
        assert!(!out.contains("sk-1234567890"));
    }

    #[test]
    fn redact_anthropic_key_default() {
        let r = defaults();
        let out = r.redact("Header set to sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz_-Ab and beyond.");
        assert!(out.contains("[REDACTED:APIKEY]"), "got {out}");
    }

    #[test]
    fn redact_aws_access_key_default() {
        let r = defaults();
        let out = r.redact("AWS credentials AKIAIOSFODNN7EXAMPLE in env.");
        assert_eq!(out, "AWS credentials [REDACTED:APIKEY] in env.");
    }

    #[test]
    fn redact_github_token_default() {
        let r = defaults();
        let out = r.redact("Token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa stored.");
        assert!(out.contains("[REDACTED:APIKEY]"), "got {out}");
    }

    #[test]
    fn clean_text_passes_through_unchanged() {
        let r = defaults();
        let input = "The quick brown fox jumps over the lazy dog.";
        let out = r.redact(input);
        // Borrowed: zero allocation when no PII matches.
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, input);
    }

    #[test]
    fn redact_combined_email_and_card_in_one_pass() {
        let r = defaults();
        let out = r.redact("Email me at alice@example.com about card 4111-1111-1111-1111");
        assert_eq!(
            out,
            "Email me at [REDACTED:EMAIL] about card [REDACTED:CARD]"
        );
    }

    #[test]
    fn redact_json_recurses_into_nested_strings() {
        let r = defaults();
        let mut value = serde_json::json!({
            "messages": [
                { "role": "user", "content": "Email me at alice@example.com" }
            ],
            "metadata": { "ip": "10.0.0.1" }
        });
        r.redact_json(&mut value);
        assert_eq!(
            value["messages"][0]["content"],
            serde_json::Value::String("Email me at [REDACTED:EMAIL]".to_string())
        );
        assert_eq!(
            value["metadata"]["ip"],
            serde_json::Value::String("[REDACTED:IP]".to_string())
        );
    }

    #[test]
    fn redact_json_keeps_object_keys_intact() {
        // Keys are schema-defined identifiers; the redactor must not
        // touch them even when they happen to look like PII.
        let r = defaults();
        let mut value = serde_json::json!({
            "alice@example.com": "value"
        });
        r.redact_json(&mut value);
        // Key preserved; only the leaf value would be redacted.
        assert!(value.as_object().unwrap().contains_key("alice@example.com"));
    }

    #[test]
    fn redact_body_round_trips_json() {
        let r = defaults();
        let body = br#"{"prompt": "Email me at alice@example.com about card 4111-1111-1111-1111"}"#;
        let redacted = r.redact_body(body);
        let parsed: serde_json::Value = serde_json::from_slice(&redacted).unwrap();
        assert_eq!(
            parsed["prompt"],
            serde_json::Value::String(
                "Email me at [REDACTED:EMAIL] about card [REDACTED:CARD]".to_string()
            )
        );
    }

    #[test]
    fn redact_body_falls_back_to_text_for_non_json() {
        let r = defaults();
        let body = b"plaintext: contact alice@example.com";
        let out = r.redact_body(body);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "plaintext: contact [REDACTED:EMAIL]"
        );
    }

    // --- Custom rules + config ---

    #[test]
    fn custom_rule_appends_to_defaults() {
        let cfg = PiiConfig {
            enabled: true,
            defaults: true,
            redact_request: true,
            redact_response: false,
            rules: vec![PiiRule {
                name: "ticket".to_string(),
                pattern: r"\bTICKET-\d{6}\b".to_string(),
                replacement: Some("[REDACTED:TICKET]".to_string()),
                validator: None,
                anchor: Some("TICKET".to_string()),
            }],
        };
        let r = PiiRedactor::from_config(&cfg).unwrap();
        let out = r.redact("Reference TICKET-123456 and alice@example.com.");
        assert_eq!(out, "Reference [REDACTED:TICKET] and [REDACTED:EMAIL].");
    }

    #[test]
    fn defaults_can_be_disabled() {
        let cfg = PiiConfig {
            enabled: true,
            defaults: false,
            redact_request: true,
            redact_response: false,
            rules: vec![PiiRule {
                name: "only".to_string(),
                pattern: r"secret".to_string(),
                replacement: None,
                validator: None,
                anchor: None,
            }],
        };
        let r = PiiRedactor::from_config(&cfg).unwrap();
        let out = r.redact("alice@example.com sent a secret message");
        // Email should NOT be redacted because defaults are off.
        assert!(out.contains("alice@example.com"));
        // Custom rule still fires; default name-derived replacement
        // handles missing replacement field.
        assert!(out.contains("[REDACTED:ONLY]"));
    }

    #[test]
    fn invalid_custom_regex_fails_at_construction() {
        let cfg = PiiConfig {
            enabled: true,
            defaults: false,
            redact_request: true,
            redact_response: false,
            rules: vec![PiiRule {
                name: "bad".to_string(),
                pattern: r"(unbalanced".to_string(),
                replacement: None,
                validator: None,
                anchor: None,
            }],
        };
        assert!(PiiRedactor::from_config(&cfg).is_err());
    }

    #[test]
    fn unknown_validator_fails_at_construction() {
        let cfg = PiiConfig {
            enabled: true,
            defaults: false,
            redact_request: true,
            redact_response: false,
            rules: vec![PiiRule {
                name: "bad".to_string(),
                pattern: r"x".to_string(),
                replacement: None,
                validator: Some("not-a-validator".to_string()),
                anchor: None,
            }],
        };
        let err = PiiRedactor::from_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("unknown validator"));
    }

    // --- Luhn validator unit ---

    #[test]
    fn luhn_validator_accepts_known_test_cards() {
        assert!(luhn_valid("4242424242424242")); // Stripe
        assert!(luhn_valid("4111-1111-1111-1111")); // Visa test
        assert!(luhn_valid("5555555555554444")); // Mastercard test
    }

    #[test]
    fn luhn_validator_rejects_random_digits() {
        // 1234... is a common smoke-test value that fails Luhn.
        assert!(!luhn_valid("1234567812345678"));
        // A second non-card 16-digit shape that fails Luhn.
        assert!(!luhn_valid("9999999999999990"));
        // Note: 16 zeros (`0000000000000000`) is a degenerate
        // Luhn-valid value (digit sum = 0). It will be redacted as a
        // "card", which is the safe direction; real attackers do not
        // hide PII behind 16-zero strings.
    }

    #[test]
    fn luhn_rejects_too_short_inputs() {
        assert!(!luhn_valid("12345678901")); // 11 digits, below 12
        assert!(!luhn_valid("1"));
    }

    #[test]
    fn ipv4_rule_requires_valid_octets() {
        let r = defaults();
        // 999.999.999.999 is not a valid IPv4 -> not redacted.
        let out = r.redact("not an ip: 999.999.999.999");
        assert!(out.contains("999.999.999.999"));
    }
}
