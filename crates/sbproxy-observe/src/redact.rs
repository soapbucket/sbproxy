//! Secrets redaction for log output.
//!
//! Scans strings for known secret patterns and replaces them with `[REDACTED]`.
//! Prevents accidental leakage of API keys, tokens, and passwords in logs.

use regex::Regex;
use std::sync::LazyLock;

// --- Pattern definitions ---

/// Anthropic keys must be matched before the generic OpenAI `sk-` pattern.
/// Anthropic key format: `sk-ant-<segment>-<segment>` where segments are
/// alphanumeric, so we allow hyphens between alphanumeric runs.
static RE_ANTHROPIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-ant-[a-zA-Z0-9][a-zA-Z0-9\-]{19,}").expect("valid regex"));

/// OpenAI / generic `sk-` API keys (alphanumeric body, no hyphens).
static RE_OPENAI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-[a-zA-Z0-9]{20,}").expect("valid regex"));

/// Stripe secret keys (`sk_live_<...>`, `sk_test_<...>`, `rk_live_<...>`,
/// `rk_test_<...>`) and the publishable variants (`pk_live_`, `pk_test_`).
/// Stripe keys use underscores rather than hyphens, which is why the
/// OpenAI `sk-` pattern misses them. Body is alphanumeric, length 24+.
static RE_STRIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}").expect("valid regex")
});

/// GitHub personal access tokens and OAuth/server/refresh variants.
static RE_GITHUB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh[pors]_[a-zA-Z0-9]{36}").expect("valid regex"));

/// AWS access key IDs.
static RE_AWS_ACCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AKIA[A-Z0-9]{16}").expect("valid regex"));

/// AWS secret access keys: 40-char base64 string preceded by a label containing
/// the word "secret" (any case), followed by any non-alphanumeric separator chars.
/// The label can be up to 30 chars (e.g. `SECRET_ACCESS_KEY`).
static RE_AWS_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)secret[a-zA-Z0-9_]{0,20}[^a-zA-Z0-9]{1,5}[a-zA-Z0-9/+=]{40}")
        .expect("valid regex")
});

/// HTTP Authorization: Bearer tokens.
static RE_BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Bearer [a-zA-Z0-9._\-]{20,}").expect("valid regex"));

/// HTTP Authorization: Basic credentials.
static RE_BASIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Basic [a-zA-Z0-9+/=]{10,}").expect("valid regex"));

/// Generic `api_key = "..."` / `api-key: ...` patterns.
static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)api[_\-]?key["'\s:=]+[a-zA-Z0-9_\-]{16,}"#).expect("valid regex")
});

/// Generic `password = "..."` / `password: ...` patterns.
static RE_PASSWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)password["'\s:=]+\S{8,}"#).expect("valid regex"));

// --- Public API ---

/// Redact secrets from a string. Returns a new string with secrets replaced.
///
/// Applies all known patterns in priority order. The result is suitable for
/// safe emission in log lines or error messages.
pub fn redact_secrets(input: &str) -> String {
    // Work through a scratch buffer so each replacement sees the previous output.
    // Ordering matters: more-specific patterns (Anthropic) come before more-general
    // ones (OpenAI `sk-`) to avoid double-redaction artifacts.
    let s = RE_ANTHROPIC.replace_all(input, "sk-ant-[REDACTED]");
    let s = RE_STRIPE.replace_all(&s, "stripe_[REDACTED]");
    let s = RE_OPENAI.replace_all(&s, "sk-[REDACTED]");
    let s = RE_GITHUB.replace_all(&s, "gh_[REDACTED]");
    let s = RE_AWS_ACCESS.replace_all(&s, "AKIA[REDACTED]");
    let s = RE_AWS_SECRET.replace_all(&s, "secret=[REDACTED]");
    let s = RE_BEARER.replace_all(&s, "Bearer [REDACTED]");
    let s = RE_BASIC.replace_all(&s, "Basic [REDACTED]");
    let s = RE_API_KEY.replace_all(&s, "api_key=[REDACTED]");
    let s = RE_PASSWORD.replace_all(&s, "password=[REDACTED]");
    s.into_owned()
}

/// Check if a string contains any known secret patterns.
///
/// Cheaper than a full `redact_secrets` call when you only need a boolean
/// answer (e.g. for metrics or alerting).
pub fn contains_secret(input: &str) -> bool {
    RE_ANTHROPIC.is_match(input)
        || RE_STRIPE.is_match(input)
        || RE_OPENAI.is_match(input)
        || RE_GITHUB.is_match(input)
        || RE_AWS_ACCESS.is_match(input)
        || RE_AWS_SECRET.is_match(input)
        || RE_BEARER.is_match(input)
        || RE_BASIC.is_match(input)
        || RE_API_KEY.is_match(input)
        || RE_PASSWORD.is_match(input)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Individual pattern tests ---

    #[test]
    fn test_openai_key_redacted() {
        let input = "Using key sk-abcdefghijklmnopqrstu1234567890 for request";
        let output = redact_secrets(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstu1234567890"));
        assert!(output.contains("sk-[REDACTED]"));
    }

    #[test]
    fn test_anthropic_key_redacted() {
        let input = "key=sk-ant-api03-ABCDEFGHIJKLMNOPQRST1234567890";
        let output = redact_secrets(input);
        assert!(!output.contains("sk-ant-api03-ABCDEFGHIJKLMNOPQRST1234567890"));
        assert!(output.contains("sk-ant-[REDACTED]"));
        // Must NOT also emit the generic sk-[REDACTED] for the same token.
        assert!(!output.contains("sk-[REDACTED]"));
    }

    #[test]
    fn test_stripe_secret_keys_redacted() {
        let live =
            "Authorization: Basic c2tfbGl2ZV9hYmM= sk_live_abcdefghijklmnopqrstuvwx1234 trailing";
        let out = redact_secrets(live);
        assert!(!out.contains("sk_live_abcdefghijklmnopqrstuvwx1234"));
        assert!(out.contains("stripe_[REDACTED]"));

        let test = "Stripe-Signature secret = sk_test_ABCDEFGHIJKLMNOPQRSTUVWX9876";
        let out = redact_secrets(test);
        assert!(!out.contains("sk_test_ABCDEFGHIJKLMNOPQRSTUVWX9876"));
        assert!(out.contains("stripe_[REDACTED]"));

        let restricted = "rk_live_abcdefghijklmnopqrstuvwx5555 should not survive";
        let out = redact_secrets(restricted);
        assert!(!out.contains("rk_live_abcdefghijklmnopqrstuvwx5555"));
        assert!(out.contains("stripe_[REDACTED]"));

        // sk- with a hyphen (OpenAI shape) must still match its own
        // pattern, not the Stripe one. The two patterns do not overlap.
        let openai = "sk-abcdefghijklmnopqrstu1234567890";
        let out = redact_secrets(openai);
        assert!(out.contains("sk-[REDACTED]"));
        assert!(!out.contains("stripe_[REDACTED]"));
    }

    #[test]
    fn test_github_pat_redacted() {
        let input = "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        let output = redact_secrets(input);
        assert!(!output.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(output.contains("gh_[REDACTED]"));
    }

    #[test]
    fn test_github_oauth_token_redacted() {
        let input = "gho_abcdefghijklmnopqrstuvwxyz1234567890 was used";
        let output = redact_secrets(input);
        assert!(!output.contains("gho_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(output.contains("gh_[REDACTED]"));
    }

    #[test]
    fn test_github_server_token_redacted() {
        let input = "ghs_abcdefghijklmnopqrstuvwxyz1234567890 was used";
        let output = redact_secrets(input);
        assert!(!output.contains("ghs_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(output.contains("gh_[REDACTED]"));
    }

    #[test]
    fn test_aws_access_key_redacted() {
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE123";
        let output = redact_secrets(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE123"));
        assert!(output.contains("AKIA[REDACTED]"));
    }

    #[test]
    fn test_aws_secret_key_redacted() {
        // 40-char base64 string following the word "secret"
        let input = "secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let output = redact_secrets(input);
        assert!(!output.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert!(output.contains("secret=[REDACTED]"));
    }

    #[test]
    fn test_aws_secret_key_uppercase_label_redacted() {
        let input = "SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let output = redact_secrets(input);
        assert!(!output.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert!(output.contains("secret=[REDACTED]"));
    }

    #[test]
    fn test_bearer_token_redacted() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc";
        let output = redact_secrets(input);
        assert!(!output.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(output.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn test_basic_auth_redacted() {
        let input = "Authorization: Basic dXNlcjpwYXNzd29yZA==";
        let output = redact_secrets(input);
        assert!(!output.contains("dXNlcjpwYXNzd29yZA=="));
        assert!(output.contains("Basic [REDACTED]"));
    }

    #[test]
    fn test_api_key_redacted() {
        let input = r#"{"api_key": "my_secret_api_key_1234567890abcdef"}"#;
        let output = redact_secrets(input);
        assert!(!output.contains("my_secret_api_key_1234567890abcdef"));
        assert!(output.contains("api_key=[REDACTED]"));
    }

    #[test]
    fn test_api_key_dash_form_redacted() {
        let input = "api-key=my_secret_api_key_1234567890abcdef";
        let output = redact_secrets(input);
        assert!(!output.contains("my_secret_api_key_1234567890abcdef"));
        assert!(output.contains("api_key=[REDACTED]"));
    }

    #[test]
    fn test_password_redacted() {
        let input = "password: supersecretpassword123";
        let output = redact_secrets(input);
        assert!(!output.contains("supersecretpassword123"));
        assert!(output.contains("password=[REDACTED]"));
    }

    #[test]
    fn test_password_equals_redacted() {
        let input = "password=S3cur3P@ssw0rd!";
        let output = redact_secrets(input);
        assert!(!output.contains("S3cur3P@ssw0rd!"));
        assert!(output.contains("password=[REDACTED]"));
    }

    // --- Non-secret passthrough ---

    #[test]
    fn test_non_secret_unchanged() {
        let input = "GET /api/v1/users HTTP/1.1 200 OK latency=12ms";
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn test_empty_string_unchanged() {
        assert_eq!(redact_secrets(""), "");
    }

    #[test]
    fn test_short_api_key_not_redacted() {
        // Fewer than 16 chars after the separator - should not match generic api_key pattern.
        let input = "api_key=shortkey";
        assert_eq!(redact_secrets(input), input);
    }

    // --- Multiple secrets in one string ---

    #[test]
    fn test_multiple_secrets_all_redacted() {
        let input = "key=sk-abcdefghijklmnopqrstu1234567890 token=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc";
        let output = redact_secrets(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstu1234567890"));
        assert!(!output.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(output.contains("sk-[REDACTED]"));
        assert!(output.contains("Bearer [REDACTED]"));
    }

    // --- JSON with embedded secrets ---

    #[test]
    fn test_json_with_secret_redacted() {
        let input = r#"{"api_key": "abcdefghijklmnopqrstuvwxyz123456", "user": "alice"}"#;
        let output = redact_secrets(input);
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyz123456"));
        assert!(output.contains("api_key=[REDACTED]"));
        // Non-secret fields preserved.
        assert!(output.contains("alice"));
    }

    #[test]
    fn test_json_openai_key_redacted() {
        let input = r#"{"key": "sk-abcdefghijklmnopqrstu12345", "model": "gpt-4"}"#;
        let output = redact_secrets(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstu12345"));
        assert!(output.contains("sk-[REDACTED]"));
        assert!(output.contains("gpt-4"));
    }

    // --- URL with embedded credentials ---

    #[test]
    fn test_bearer_in_url_query_redacted() {
        let input = "GET https://api.example.com/data?Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc";
        let output = redact_secrets(input);
        assert!(!output.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(output.contains("Bearer [REDACTED]"));
        // Non-secret path components preserved.
        assert!(output.contains("https://api.example.com/data"));
    }

    // --- contains_secret ---

    #[test]
    fn test_contains_secret_true() {
        assert!(contains_secret("sk-abcdefghijklmnopqrstu1234567890"));
    }

    #[test]
    fn test_contains_secret_false() {
        assert!(!contains_secret("GET /health HTTP/1.1 200 OK"));
    }
}
