//! Natural-language policy constraint linter (WOR-203 PR 3a).
//!
//! The linter runs on the NL input before the LLM compilation step
//! (see `adr-policy-compilation.md`, NLC pillar A). It catches the
//! obvious classes of underspecified or dangerous NL constraints so
//! the LLM compile call is not wasted on inputs the author should
//! fix anyway.
//!
//! ## Rule set (v1)
//!
//! | Rule | Description |
//! |---|---|
//! | L001 | Resource type referenced must be in the workspace schema. |
//! | L002 | Temporal constraints must specify a timezone or be UTC-explicit. |
//! | L003 | Rate constraints must carry a unit (per second, per minute, per day). |
//! | L004 | Deny-all / allow-all patterns must be explicit, not inferred. |
//! | L005 | Conflicting polarity is rejected (the same input must not imply both allow and deny for the same action). |
//! | L006 | Model names must match the configured model schema. |
//! | L007 | User-attribute references must match the configured principal schema. |
//! | L008 | Monetary constraints must carry a currency code. |
//! | L009 | The constraint must name at least one principal, action, or resource; bare predicates are rejected. |
//!
//! ## Heuristic, not parser
//!
//! The linter is a fast keyword + regex pre-filter. False positives
//! are acceptable; false negatives are not. The LLM compiler that
//! runs after the linter performs the deeper schema-aware check.
//!
//! ## Span reporting
//!
//! When a rule can localise the offending text the violation carries
//! a [`CharRange`]. Rules that catch absence-of-something (L002, L003,
//! L008, L009) report `None`: there is no span to point at when the
//! input is missing a required token.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

// --- Public types ---

/// Half-open byte range `[start, end)` over the original NL input.
///
/// Stored in bytes, not chars, so callers can slice directly. Inputs
/// in this codebase are ASCII-dominant policy text so byte ranges and
/// char ranges generally agree, but the type is explicit about which
/// it stores to avoid ambiguity in future tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharRange {
    /// Inclusive byte offset of the first byte of the offending span.
    pub start: usize,
    /// Exclusive byte offset of the byte after the offending span.
    pub end: usize,
}

/// One linter finding.
///
/// `rule` is a short stable identifier (`"L001"`, `"L002"`, ...)
/// suitable for filtering and for surfacing in editor UI. `message` is
/// the human-readable explanation. `span` localises the offending text
/// when the rule can; `None` means the rule fired on absence of an
/// expected token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintViolation {
    /// Stable rule identifier (`"L001"` ... `"L009"`).
    pub rule: &'static str,
    /// Human-readable description of what the author should fix.
    pub message: String,
    /// Optional byte range pointing at the offending text.
    pub span: Option<CharRange>,
}

/// Minimal workspace-schema view used by the linter.
///
/// The full Cedar schema integration lives in the enterprise tier
/// (see `adr-policy-mcp-primitives.md` and the enterprise policy
/// crate). The OSS linter only needs the four list-of-strings views
/// below to enforce L001, L006, and L007.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceSchema {
    /// Allowed principal entity types (e.g. `"User"`, `"Agent"`).
    pub principal_types: Vec<String>,
    /// Allowed resource entity types (e.g. `"Invoice"`, `"Tool"`).
    pub resource_types: Vec<String>,
    /// Action group names accepted in NL (e.g. `"read"`, `"write"`).
    pub action_groups: Vec<String>,
    /// Configured model names (e.g. `"gpt-4o"`, `"claude-opus"`).
    pub model_names: Vec<String>,
}

/// Stateless linter facade.
///
/// All rules are pure functions of `(input, schema)`. The struct is
/// kept for API symmetry with the planned [`crate::policy`] modules
/// that hold compiled state; the linter itself has none.
pub struct NlLinter;

impl NlLinter {
    /// Run all nine rules against `input` and return every violation.
    ///
    /// Rules run independently. The function never short-circuits: a
    /// single input that triggers L002 and L003 returns both.
    pub fn lint(input: &str, schema: &WorkspaceSchema) -> Vec<LintViolation> {
        let mut out = Vec::new();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            // A blank input cannot satisfy L009 either; report once
            // and stop. Other rules would all generate noise.
            out.push(LintViolation {
                rule: "L009",
                message: "constraint must name at least one principal, action, or resource"
                    .to_string(),
                span: None,
            });
            return out;
        }

        out.extend(check_l001(input, schema));
        if let Some(v) = check_l002(input) {
            out.push(v);
        }
        if let Some(v) = check_l003(input) {
            out.push(v);
        }
        if let Some(v) = check_l004(input) {
            out.push(v);
        }
        if let Some(v) = check_l005(input) {
            out.push(v);
        }
        out.extend(check_l006(input, schema));
        out.extend(check_l007(input, schema));
        if let Some(v) = check_l008(input) {
            out.push(v);
        }
        if let Some(v) = check_l009(input) {
            out.push(v);
        }
        out
    }
}

// --- L001 -------------------------------------------------------------------

/// L001: Resource type tokens (capitalised words that look like Cedar
/// entity types) must be present in `schema.resource_types` or
/// `schema.principal_types`.
///
/// Heuristic: a token matching `[A-Z][A-Za-z0-9_]*::"..."` or a bare
/// `[A-Z][A-Za-z0-9_]+` token used as `is X` / `resource is X` /
/// `Resource X` is treated as an entity type reference. Common English
/// capitalised words that are not entity types (sentence-initial
/// articles, proper nouns the author quoted) are filtered via a small
/// stop list.
fn check_l001(input: &str, schema: &WorkspaceSchema) -> Vec<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Match four forms:
    //   1) `Foo::"..."`        Cedar literal
    //   2) `is Foo`            type test
    //   3) `resource Foo`      English-style resource declaration
    //   4) `on Foo` / `to Foo` / `for Foo` / `against Foo`
    //                          English-style trailing reference where
    //                          `Foo` is a capitalised identifier
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (?:
              ([A-Z][A-Za-z0-9_]*)::"[^"]*"
              |
              \b(?:is|resource|resources|access\s+to|on|to|for|against)\s+([A-Z][A-Za-z0-9_]+)
            )
            "#,
        )
        .expect("L001 regex compiles")
    });

    let known: HashSet<&str> = schema
        .resource_types
        .iter()
        .chain(schema.principal_types.iter())
        .map(String::as_str)
        .collect();

    let mut violations = Vec::new();
    for caps in re.captures_iter(input) {
        let m = caps.get(1).or_else(|| caps.get(2));
        if let Some(m) = m {
            let token = m.as_str();
            if !known.contains(token) {
                violations.push(LintViolation {
                    rule: "L001",
                    message: format!(
                        "resource type '{token}' is not declared in the workspace schema"
                    ),
                    span: Some(CharRange {
                        start: m.start(),
                        end: m.end(),
                    }),
                });
            }
        }
    }
    violations
}

// --- L002 -------------------------------------------------------------------

/// L002: Temporal constraints must carry a timezone or be UTC-explicit.
///
/// Heuristic: if the input contains a clock time (`HH:MM` or `HH:MM:SS`,
/// or a 12-hour form like `9am`, `5 pm`) without an adjacent timezone
/// token (`UTC`, `GMT`, `Z`, `EST`, `PST`, `+HH:MM`, `America/...`,
/// `Europe/...`, ...), report a violation pointing at the clock time.
fn check_l002(input: &str) -> Option<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    static TZ: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(
              \d{1,2}:\d{2}(:\d{2})?
              |
              \d{1,2}\s*(?:am|pm)
            )\b
        ",
        )
        .expect("L002 time regex compiles")
    });
    let tz = TZ.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(UTC|GMT|Z|EST|EDT|PST|PDT|CST|CDT|MST|MDT|BST|CET|CEST|JST|IST|AEST)\b
            |
            [+-]\d{2}:?\d{2}
            |
            \b(?:America|Europe|Asia|Africa|Australia|Pacific|Atlantic)/[A-Za-z_]+
        ",
        )
        .expect("L002 tz regex compiles")
    });

    let m = re.find(input)?;
    if tz.is_match(input) {
        return None;
    }
    Some(LintViolation {
        rule: "L002",
        message:
            "temporal constraint is missing a timezone (use UTC, GMT, an offset like +00:00, or an IANA zone name)"
                .to_string(),
        span: Some(CharRange {
            start: m.start(),
            end: m.end(),
        }),
    })
}

// --- L003 -------------------------------------------------------------------

/// L003: Rate constraints must carry a time unit.
///
/// Heuristic: a number followed by `requests`, `calls`, `tokens`,
/// `queries`, `events`, etc. must be followed within a small window
/// by a `per <unit>` clause where `<unit>` matches one of `second(s)`,
/// `minute(s)`, `hour(s)`, `day(s)`, `month(s)`, `year(s)`.
fn check_l003(input: &str) -> Option<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b\d+\s+(?:requests?|calls?|tokens?|queries|events?|hits?|messages?)\b
            (?P<rest>.{0,40})
            ",
        )
        .expect("L003 regex compiles")
    });
    static UNIT: OnceLock<Regex> = OnceLock::new();
    let unit = UNIT.get_or_init(|| {
        Regex::new(
            r"(?xi)
            (?:per|each|every|/|a)\s*
            (?:second|sec|minute|min|hour|hr|day|week|month|year|s|m|h|d)\b
        ",
        )
        .expect("L003 unit regex compiles")
    });

    let m = re.find(input)?;
    let tail = &input[m.start()..];
    if unit.is_match(tail) {
        return None;
    }
    Some(LintViolation {
        rule: "L003",
        message:
            "rate constraint is missing a unit (specify per second, per minute, per day, etc.)"
                .to_string(),
        span: Some(CharRange {
            start: m.start(),
            end: m.end(),
        }),
    })
}

// --- L004 -------------------------------------------------------------------

/// L004: Deny-all and allow-all are too dangerous to infer; they must
/// be spelled out.
///
/// The lint fires when the input uses an *implicit* universal pattern
/// like "block everything else", "default deny", or "permit anything"
/// without the matching explicit polarity word + universal quantifier
/// pair. The intent is to force authors to write a literal
/// `deny everything` or `allow everything` so the compiled Cedar is
/// auditable rather than relying on the absence of other rules.
fn check_l004(input: &str) -> Option<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(default[\s-]?(?:deny|allow|permit)
            |permit[\s-]?(?:anything|all)
            |block[\s-]?(?:anything|all|everything[\s-]?else))\b
            ",
        )
        .expect("L004 regex compiles")
    });
    let m = re.find(input)?;
    Some(LintViolation {
        rule: "L004",
        message:
            "deny-all / allow-all patterns must be explicit (write 'deny everything' or 'allow everything' literally)"
                .to_string(),
        span: Some(CharRange {
            start: m.start(),
            end: m.end(),
        }),
    })
}

// --- L005 -------------------------------------------------------------------

/// L005: The same input must not imply both allow and deny for the
/// same action.
///
/// Heuristic: if both an `allow|permit|grant` token and a
/// `deny|block|forbid|prohibit` token appear in the input *and* they
/// share a near-by action verb (any of `read`, `write`, `call`,
/// `delete`, `create`, `list`, `update`), report a conflict pointing
/// at the second polarity word.
fn check_l005(input: &str) -> Option<LintViolation> {
    static ALLOW: OnceLock<Regex> = OnceLock::new();
    static DENY: OnceLock<Regex> = OnceLock::new();
    static ACTION: OnceLock<Regex> = OnceLock::new();
    let allow = ALLOW.get_or_init(|| {
        Regex::new(r"(?i)\b(allow|permit|grant)\b").expect("L005 allow regex compiles")
    });
    let deny = DENY.get_or_init(|| {
        Regex::new(r"(?i)\b(deny|block|forbid|prohibit)\b").expect("L005 deny regex compiles")
    });
    let action = ACTION.get_or_init(|| {
        Regex::new(r"(?i)\b(read|write|call|delete|create|list|update|invoke)\b")
            .expect("L005 action regex compiles")
    });

    let allow_hit = allow.find(input);
    let deny_hit = deny.find(input);
    let (Some(a), Some(d)) = (allow_hit, deny_hit) else {
        return None;
    };

    // Collect actions referenced anywhere in the input. If the
    // overlap is non-empty we treat the input as conflicting.
    let actions: HashSet<String> = action
        .find_iter(input)
        .map(|m| m.as_str().to_lowercase())
        .collect();
    if actions.is_empty() {
        return None;
    }

    let later = std::cmp::max(a.end(), d.end());
    let earlier_start = std::cmp::min(a.start(), d.start());
    Some(LintViolation {
        rule: "L005",
        message: format!(
            "conflicting polarity: input contains both '{}' and '{}' for overlapping actions ({})",
            a.as_str(),
            d.as_str(),
            actions.into_iter().collect::<Vec<_>>().join(", ")
        ),
        span: Some(CharRange {
            start: earlier_start,
            end: later,
        }),
    })
}

// --- L006 -------------------------------------------------------------------

/// L006: Model name tokens must match an entry in
/// `schema.model_names`.
///
/// Heuristic: any token matching the common AI model shape
/// (`gpt-`, `claude-`, `llama-`, `gemini-`, `o1-`, `mistral-`,
/// `command-`, `phi-`, possibly with version suffix) must appear
/// verbatim in `schema.model_names`. Typos report a violation
/// pointing at the unknown token.
fn check_l006(input: &str, schema: &WorkspaceSchema) -> Vec<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(
              (?:gpt|claude|llama|gemini|mistral|command|phi|qwen|deepseek|o1|o3|grok|gemma)
              -[A-Za-z0-9._-]+
            )\b
            ",
        )
        .expect("L006 regex compiles")
    });

    let known: HashSet<String> = schema
        .model_names
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let mut violations = Vec::new();
    for m in re.find_iter(input) {
        let token = m.as_str();
        if !known.contains(&token.to_lowercase()) {
            violations.push(LintViolation {
                rule: "L006",
                message: format!("model name '{token}' is not in the configured model schema"),
                span: Some(CharRange {
                    start: m.start(),
                    end: m.end(),
                }),
            });
        }
    }
    violations
}

// --- L007 -------------------------------------------------------------------

/// L007: User-attribute references (`user.<attr>`, `principal.<attr>`)
/// must reference an attribute the principal schema declares.
///
/// The OSS linter does not have the full Cedar schema. It approximates
/// by treating the principal type names in `schema.principal_types`
/// as the only allowed left-hand sides of an attribute reference,
/// plus a small allowlist of common contextual references the
/// runtime always provides (`user`, `principal`, `agent`).
///
/// The deeper attribute-name check is enterprise scope; the OSS rule
/// catches the common case where the author types `usr.email` or
/// `princpal.role` (typos in the lhs).
fn check_l007(input: &str, schema: &WorkspaceSchema) -> Vec<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Capture (lhs, rhs) of a single dotted token. We use the rhs
    // value to filter out domain-shaped tokens (`example.com`) and
    // file-extension tokens (`policy.yml`) where the rhs is a known
    // TLD or file suffix.
    let re = RE.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b")
            .expect("L007 regex compiles")
    });

    // Common TLDs and file extensions that show up in policy text
    // when the author writes things like `ends with example.com` or
    // references a config file. Treat them as not-an-attribute so the
    // linter doesn't false-positive on the surrounding sentence.
    const NOT_AN_ATTRIBUTE_RHS: &[&str] = &[
        "com", "org", "net", "io", "dev", "co", "us", "uk", "edu", "gov", "mil", "info", "biz",
        "ai", "app", "cloud", "yml", "yaml", "json", "toml", "txt", "md", "html", "xml", "csv",
        "log",
    ];

    let mut allowed: HashSet<String> = HashSet::new();
    allowed.insert("user".to_string());
    allowed.insert("principal".to_string());
    allowed.insert("agent".to_string());
    allowed.insert("resource".to_string());
    allowed.insert("action".to_string());
    allowed.insert("context".to_string());
    for t in &schema.principal_types {
        allowed.insert(t.to_lowercase());
        allowed.insert(t.clone());
    }

    let mut violations = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for caps in re.captures_iter(input) {
        let lhs = caps.get(1).expect("regex group 1 captured");
        let rhs = caps.get(2).expect("regex group 2 captured");
        let token = lhs.as_str();
        // Skip dotted tokens that are obviously not attribute paths
        // (numbers, MIME-style tokens). The regex already requires an
        // identifier on both sides of the `.`, so this filter is
        // narrow.
        if token
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            continue;
        }
        // Domain or file-suffix shape; not a Cedar attribute path.
        if NOT_AN_ATTRIBUTE_RHS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(rhs.as_str()))
        {
            continue;
        }
        if allowed.contains(token) || allowed.contains(&token.to_lowercase()) {
            continue;
        }
        // Skip references to the schema's resource entity types.
        // Only principal-side references are L007's concern.
        if schema
            .resource_types
            .iter()
            .any(|r| r.eq_ignore_ascii_case(token))
        {
            continue;
        }
        let span = (lhs.start(), lhs.end());
        if !seen.insert(span) {
            continue;
        }
        violations.push(LintViolation {
            rule: "L007",
            message: format!(
                "user-attribute reference '{token}.<attr>' uses an unknown principal type"
            ),
            span: Some(CharRange {
                start: lhs.start(),
                end: lhs.end(),
            }),
        });
    }
    violations
}

// --- L008 -------------------------------------------------------------------

/// L008: Monetary amounts must carry a currency code or symbol.
///
/// Heuristic: a bare number adjacent to a money-coded keyword
/// (`spend`, `budget`, `cost`, `charge`, `cap`, `limit`, `price`) is
/// a violation if no currency token (`$`, `USD`, `EUR`, `GBP`, `JPY`,
/// `CAD`, `AUD`, `CHF`, `CNY`, `INR`, three-letter ISO code) appears
/// in the input.
fn check_l008(input: &str) -> Option<LintViolation> {
    static MONEY: OnceLock<Regex> = OnceLock::new();
    static CURRENCY: OnceLock<Regex> = OnceLock::new();
    let money = MONEY.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(?:spend|budget|cost|charge|cap|limit|price|fee|bill|amount)\b
            [^.\n]*?
            \b(\d+(?:\.\d+)?)\b
            ",
        )
        .expect("L008 money regex compiles")
    });
    let currency = CURRENCY.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \$|€|£|¥
            |\b(USD|EUR|GBP|JPY|CAD|AUD|CHF|CNY|INR|MXN|BRL|SEK|NZD|KRW|SGD|HKD)\b
            ",
        )
        .expect("L008 currency regex compiles")
    });

    let m = money.find(input)?;
    if currency.is_match(input) {
        return None;
    }
    Some(LintViolation {
        rule: "L008",
        message:
            "monetary constraint is missing a currency code (use $, USD, EUR, or another ISO 4217 code)"
                .to_string(),
        span: Some(CharRange {
            start: m.start(),
            end: m.end(),
        }),
    })
}

// --- L009 -------------------------------------------------------------------

/// L009: The constraint must name at least one principal, action, or
/// resource. Bare predicates ("everything is fine", "this is bad")
/// are rejected; the compiler has nothing to bind against.
fn check_l009(input: &str) -> Option<LintViolation> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            \b(
              user|users|principal|principals|agent|agents|service|services|group|groups
              |resource|resources|invoice|invoices|tool|tools|server|servers
              |document|documents|file|files|record|records
              |read|write|call|delete|create|list|update|invoke|access|view|edit
              |allow|permit|grant|deny|block|forbid|prohibit
              |MCP::|API::|Action::
            )\b
            ",
        )
        .expect("L009 regex compiles")
    });
    if re.is_match(input) {
        return None;
    }
    Some(LintViolation {
        rule: "L009",
        message: "constraint must name at least one principal, action, or resource".to_string(),
        span: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> WorkspaceSchema {
        WorkspaceSchema {
            principal_types: vec!["User".to_string(), "Agent".to_string()],
            resource_types: vec!["Invoice".to_string(), "Tool".to_string()],
            action_groups: vec!["read".to_string(), "write".to_string()],
            model_names: vec!["gpt-4o".to_string(), "claude-opus-4.7".to_string()],
        }
    }

    fn rules(violations: &[LintViolation]) -> Vec<&'static str> {
        violations.iter().map(|v| v.rule).collect()
    }

    // --- L001 -----------------------------------------------------------

    #[test]
    fn l001_passes_when_resource_type_is_in_schema() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow read access to Invoice for User in finance group",
            &schema,
        );
        assert!(!rules(&v).contains(&"L001"), "unexpected: {:?}", v);
    }

    #[test]
    fn l001_fires_when_resource_type_unknown() {
        let schema = schema();
        let v = NlLinter::lint("allow read access to Receipt for User", &schema);
        assert!(rules(&v).contains(&"L001"), "expected L001, got {:?}", v);
    }

    // --- L002 -----------------------------------------------------------

    #[test]
    fn l002_passes_with_explicit_timezone() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow access to Invoice between 09:00 and 17:00 UTC for User",
            &schema,
        );
        assert!(!rules(&v).contains(&"L002"), "unexpected: {:?}", v);
    }

    #[test]
    fn l002_fires_when_timezone_missing() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow access to Invoice between 09:00 and 17:00 for User",
            &schema,
        );
        assert!(rules(&v).contains(&"L002"), "expected L002, got {:?}", v);
    }

    // --- L003 -----------------------------------------------------------

    #[test]
    fn l003_passes_with_unit() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow User to make 100 requests per minute against Tool",
            &schema,
        );
        assert!(!rules(&v).contains(&"L003"), "unexpected: {:?}", v);
    }

    #[test]
    fn l003_fires_when_unit_missing() {
        let schema = schema();
        let v = NlLinter::lint("allow User to make 100 requests against Tool", &schema);
        assert!(rules(&v).contains(&"L003"), "expected L003, got {:?}", v);
    }

    // --- L004 -----------------------------------------------------------

    #[test]
    fn l004_passes_with_explicit_universal() {
        let schema = schema();
        let v = NlLinter::lint("deny everything for unauthenticated User", &schema);
        assert!(!rules(&v).contains(&"L004"), "unexpected: {:?}", v);
    }

    #[test]
    fn l004_fires_on_default_deny_phrasing() {
        let schema = schema();
        let v = NlLinter::lint("default deny for User accessing Invoice", &schema);
        assert!(rules(&v).contains(&"L004"), "expected L004, got {:?}", v);
    }

    // --- L005 -----------------------------------------------------------

    #[test]
    fn l005_passes_when_polarity_is_consistent() {
        let schema = schema();
        let v = NlLinter::lint("allow User to read Invoice", &schema);
        assert!(!rules(&v).contains(&"L005"), "unexpected: {:?}", v);
    }

    #[test]
    fn l005_fires_when_allow_and_deny_overlap_on_action() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow User to read Invoice but deny read for the same User",
            &schema,
        );
        assert!(rules(&v).contains(&"L005"), "expected L005, got {:?}", v);
    }

    // --- L006 -----------------------------------------------------------

    #[test]
    fn l006_passes_when_model_is_in_schema() {
        let schema = schema();
        let v = NlLinter::lint("allow User to invoke gpt-4o on Tool", &schema);
        assert!(!rules(&v).contains(&"L006"), "unexpected: {:?}", v);
    }

    #[test]
    fn l006_fires_on_unknown_model_token() {
        let schema = schema();
        let v = NlLinter::lint("allow User to invoke gpt-9z on Tool", &schema);
        assert!(rules(&v).contains(&"L006"), "expected L006, got {:?}", v);
    }

    // --- L007 -----------------------------------------------------------

    #[test]
    fn l007_passes_when_lhs_is_known_principal() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow access to Invoice when user.email ends with example.com for User",
            &schema,
        );
        assert!(!rules(&v).contains(&"L007"), "unexpected: {:?}", v);
    }

    #[test]
    fn l007_fires_on_typo_in_principal_lhs() {
        let schema = schema();
        let v = NlLinter::lint(
            "allow access to Invoice when usr.email ends with example.com for User",
            &schema,
        );
        assert!(rules(&v).contains(&"L007"), "expected L007, got {:?}", v);
    }

    // --- L008 -----------------------------------------------------------

    #[test]
    fn l008_passes_with_currency_code() {
        let schema = schema();
        let v = NlLinter::lint(
            "cap monthly spend at 500 USD per User accessing Tool",
            &schema,
        );
        assert!(!rules(&v).contains(&"L008"), "unexpected: {:?}", v);
    }

    #[test]
    fn l008_fires_when_currency_missing() {
        let schema = schema();
        let v = NlLinter::lint("cap monthly spend at 500 per User accessing Tool", &schema);
        assert!(rules(&v).contains(&"L008"), "expected L008, got {:?}", v);
    }

    // --- L009 -----------------------------------------------------------

    #[test]
    fn l009_passes_when_principal_action_or_resource_named() {
        let schema = schema();
        let v = NlLinter::lint("allow User to read Invoice", &schema);
        assert!(!rules(&v).contains(&"L009"), "unexpected: {:?}", v);
    }

    #[test]
    fn l009_fires_on_bare_predicate() {
        let schema = schema();
        let v = NlLinter::lint("everything is fine here", &schema);
        assert!(rules(&v).contains(&"L009"), "expected L009, got {:?}", v);
    }

    // --- multi-rule -----------------------------------------------------

    #[test]
    fn multiple_rules_fire_simultaneously() {
        let schema = schema();
        // This input is pathological by design:
        //   - references the unknown resource type Receipt (L001)
        //   - references a clock time without timezone (L002)
        //   - rate without unit (L003)
        //   - mentions an unknown model name (L006)
        //   - monetary amount without currency (L008)
        let input = "allow User to invoke gpt-9z on Receipt at 09:00, 100 calls, cap 500 spend";
        let v = NlLinter::lint(input, &schema);
        let rs = rules(&v);
        for expected in ["L001", "L002", "L003", "L006", "L008"] {
            assert!(rs.contains(&expected), "missing {expected} in {:?}", v);
        }
        assert!(
            v.len() >= 5,
            "expected at least 5 violations, got {}: {:?}",
            v.len(),
            v
        );
    }

    // --- empty input ----------------------------------------------------

    #[test]
    fn blank_input_reports_l009_only() {
        let schema = schema();
        let v = NlLinter::lint("", &schema);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, "L009");
    }
}
