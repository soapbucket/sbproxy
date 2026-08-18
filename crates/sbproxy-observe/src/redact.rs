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

/// Credential-bearing keys this product's own schema defines
/// (`master_key`, `signing_key`, `shared_key`, `virtual_key`,
/// `challenge_binding_key`, `signing_secret`, `client_secret`,
/// `session_token`) whose values have no vendor-recognizable shape of
/// their own: a 32-hex Slack signing secret, a Google `GOCSPX-...`
/// client secret (its hyphen breaks `RE_AWS_SECRET`'s base64 run), and
/// a raw cluster master key all sail past the shape patterns above.
/// Matched by key, like `api_key` and `password`. Groups: key,
/// separator, value; see [`keyed_credential_replacement`].
static RE_CREDENTIAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(session[_-]?token|master[_-]?key|signing[_-]?key|shared[_-]?key|virtual[_-]?key|challenge[_-]?binding[_-]?key|signing[_-]?secret|client[_-]?secret)(["'\s:=]+)(\S{4,})"#,
    )
    .expect("valid regex")
});

/// A bare `token` key (`token: eyJ...`), which `RE_BEARER` misses
/// because it requires the literal `Bearer ` prefix. Split from
/// [`RE_CREDENTIAL_KEY`] because prose uses the word constantly
/// ("token count", "token budget"), so this one requires an explicit
/// `:` or `=` separator rather than matching across a bare space.
static RE_BARE_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(token)(["'\s]*[:=]["'\s]*)(\S{4,})"#).expect("valid regex")
});

/// Generic `password = "..."` / `password: ...` patterns.
///
/// Split into the label-plus-separator run and the value so the value can
/// be inspected before anything is replaced: see [`is_secret_reference`].
/// Sibling patterns get away with a single group because their value
/// character classes happen to exclude the reference syntax; this one
/// matches `\S`, so it has to check.
/// The value run is `\S{4,}`: short real passwords (`hunter2`) must
/// still be masked, while staying above YAML's one-character block
/// and quote indicators (`|`, `>`, `-`, `"`) so structure survives.
static RE_PASSWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(password["'\s:=]+)(\S{4,})"#).expect("valid regex"));

/// Whether `value` names a secret rather than being one.
///
/// A reference is a pointer the resolver dereferences at boot: an env
/// var, a file path, or a provider URI. Redacting one destroys
/// information without protecting anything, because the reference is
/// already safe to print. That is exactly why an operator is told to use
/// them.
///
/// WOR-2333: `RE_PASSWORD` matched `\S{8,}`, so it swallowed
/// `${SB_ADMIN_PASSWORD}` whole and the replacement text took the `:`
/// with it. `GET /admin/config` redacts server-side, so the Config page
/// handed the operator YAML whose `admin:` block read
/// `password=[REDACTED]`, and Validate+Save wrote that back. The config
/// was lost with only a generic `failed to parse config YAML` to explain
/// it, and the drift indicator still read "in sync" because it compares
/// hashes of the redacted content.
///
/// `RE_API_KEY` was unaffected only by luck: its value class is
/// `[a-zA-Z0-9_\-]`, which cannot match `$`, `{`, or `}`.
///
/// The check is deliberately whole-value. `${VAR}suffix` is not a
/// reference, the resolver passes it through literally (and warns), so it
/// stays redactable.
fn is_secret_reference(value: &str) -> bool {
    // Trailing YAML/JSON punctuation the `\S` run may have absorbed, so
    // `password: "${VAR}",` is recognised as the reference it is.
    let value = value.trim_end_matches([',', '"', '\'', ';']);
    if value.starts_with("${") && value.ends_with('}') {
        return true;
    }
    // The resolver's non-URI forms, and every provider-URI scheme it
    // parses. Kept in sync with `sbproxy_vault::SecretResolver::resolve`.
    const PREFIXES: &[&str] = &[
        "env:",
        "file:",
        "vault://",
        "awssm://",
        "gcpsm://",
        "azurekv://",
        "k8ssecret://",
        "secretfile://",
        "secret://",
    ];
    PREFIXES.iter().any(|prefix| {
        value.len() > prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

/// Replacement for the keyed credential patterns: mask an inline
/// value, keep a resolver reference, and keep anything an earlier
/// pattern already masked (`master_key: sk-ant-[REDACTED]` must not
/// double-mask, and `token: Bearer [REDACTED]` is already done).
fn keyed_credential_replacement(caps: &regex::Captures<'_>) -> String {
    let value = &caps[3];
    if is_secret_reference(value)
        || value.contains("[REDACTED]")
        || value.eq_ignore_ascii_case("bearer")
        || value.eq_ignore_ascii_case("basic")
    {
        caps[0].to_string()
    } else {
        // Same normalization and same deliberate separator consumption
        // as the password path: an inline credential is not meant to
        // survive a GET-edit-PUT round trip.
        format!(
            "{}=[REDACTED]",
            caps[1].to_ascii_lowercase().replace('-', "_")
        )
    }
}

/// Apply the password redaction, leaving secret references intact.
fn redact_passwords(input: &str) -> String {
    RE_PASSWORD
        .replace_all(input, |caps: &regex::Captures<'_>| {
            let value = &caps[2];
            if is_secret_reference(value) {
                // Whole match back verbatim, separator included.
                caps[0].to_string()
            } else {
                // Unchanged output for an actual inline secret. The
                // separator is deliberately still consumed: a config
                // carrying an inline secret is not meant to survive a
                // GET-edit-PUT round trip, and the resulting parse
                // failure is the loud signal WOR-2316 chose over
                // silently writing `[REDACTED]` back as the password.
                "password=[REDACTED]".to_string()
            }
        })
        .into_owned()
}

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
    let s = RE_CREDENTIAL_KEY.replace_all(&s, keyed_credential_replacement);
    let s = RE_BARE_TOKEN.replace_all(&s, keyed_credential_replacement);
    redact_passwords(&s)
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
        // A reference is not a secret, so it must not count as one here
        // either. Reusing the capture keeps this in step with
        // `redact_passwords` rather than letting the two drift.
        || RE_PASSWORD
            .captures_iter(input)
            .any(|caps| !is_secret_reference(&caps[2]))
        || RE_CREDENTIAL_KEY
            .captures_iter(input)
            .any(|caps| !is_secret_reference(&caps[3]))
        || RE_BARE_TOKEN
            .captures_iter(input)
            .any(|caps| !is_secret_reference(&caps[3]))
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

    // --- WOR-2333: a reference is not a secret ---

    #[test]
    fn an_interpolated_admin_password_survives_redaction() {
        // The bug that motivated all of this. `GET /admin/config` redacts
        // server-side, so the Config page handed the operator YAML whose
        // `admin:` block read `password=[REDACTED]`, colon and all, and
        // Validate+Save wrote that straight back. The config was lost
        // behind a generic `failed to parse config YAML`.
        let input = "admin:\n  password: ${SB_ADMIN_PASSWORD}\n  port: 9901\n";
        let output = redact_secrets(input);
        assert_eq!(
            output, input,
            "an interpolation reference names a secret, it is not one"
        );
    }

    #[test]
    fn the_redacted_config_still_parses_as_yaml() {
        // The property the operator actually depends on: whatever comes
        // back from a redacted round trip is still a config. Asserting on
        // the substring alone would not have caught the eaten colon.
        let input = "admin:\n  password: ${SB_ADMIN_PASSWORD}\n  port: 9901\n";
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&redact_secrets(input)).expect("redacted config still parses");
        assert_eq!(
            parsed["admin"]["password"].as_str(),
            Some("${SB_ADMIN_PASSWORD}")
        );
        assert_eq!(parsed["admin"]["port"].as_u64(), Some(9901));
    }

    #[test]
    fn every_resolver_reference_form_survives() {
        // `${VAR}` was the reported one, but `\S{8,}` swallowed all of
        // these equally. Each is a pointer the resolver dereferences at
        // boot and each is safe to print.
        for reference in [
            "${SB_ADMIN_PASSWORD}",
            "env:SB_ADMIN_PASSWORD",
            "file:/run/secrets/admin-password",
            "vault://primary/admin?key=password",
            "awssm://prod/admin-password",
            "gcpsm://prod/admin-password",
            "azurekv://prod/admin-password",
            "k8ssecret://ns/admin-password",
            "secretfile://local/admin-password",
            "secret://local/admin-password",
        ] {
            let input = format!("password: {reference}");
            assert_eq!(
                redact_secrets(&input),
                input,
                "{reference} is a reference and must be preserved"
            );
            assert!(
                !contains_secret(&input),
                "{reference} must not be reported as a secret"
            );
        }
    }

    #[test]
    fn an_inline_password_is_still_redacted() {
        // The other half of the contract. Loosening the pattern must not
        // stop it catching a real secret.
        let input = "password: hunter2-actual-secret";
        let output = redact_secrets(input);
        assert!(!output.contains("hunter2-actual-secret"));
        assert!(output.contains("password=[REDACTED]"));
        assert!(contains_secret(input));
    }

    #[test]
    fn a_password_containing_a_dollar_sign_is_still_redacted() {
        // The reason this is a value check rather than a narrower
        // character class. Excluding `$` from the pattern would have
        // fixed the reported bug and silently stopped redacting any
        // password containing one.
        let input = "password: p$ssw0rd-with-braces{}";
        let output = redact_secrets(input);
        assert!(!output.contains("p$ssw0rd-with-braces"));
        assert!(output.contains("password=[REDACTED]"));
    }

    #[test]
    fn a_partial_interpolation_is_not_treated_as_a_reference() {
        // `${VAR}suffix` is not a reference: the resolver passes it
        // through literally and warns. Whole-value only, so this stays
        // redactable.
        let input = "password: ${SB_ADMIN_PASSWORD}-suffix";
        assert!(redact_secrets(input).contains("password=[REDACTED]"));
    }

    // --- Phase-2 review: the product's own credential keys ---
    //
    // docs/configuration.md and the config-history routes promise that
    // "a literal secret an operator typed directly into the file (an
    // inline API key, a password field) is masked as [REDACTED]".
    // These pin that promise for the credential keys this product's
    // own schema defines, not just vendor-shaped tokens. Each test was
    // red against the pre-widening pattern set.

    #[test]
    fn a_raw_token_value_is_redacted() {
        // RE_BEARER requires the literal `Bearer ` prefix, so a raw
        // JWT under `token:` used to pass through verbatim.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMifQ.c2lnbmF0dXJl";
        let input = format!("token: {jwt}");
        let output = redact_secrets(&input);
        assert!(
            !output.contains(jwt),
            "raw token value must be masked: {output}"
        );
        assert!(contains_secret(&input));
    }

    #[test]
    fn a_session_token_is_redacted() {
        let input = "session_token: 5d41402abc4b2a76b9719d911017c592";
        let output = redact_secrets(input);
        assert!(
            !output.contains("5d41402abc4b2a76b9719d911017c592"),
            "session token must be masked: {output}"
        );
        assert!(contains_secret(input));
    }

    #[test]
    fn product_key_names_are_redacted() {
        // RE_API_KEY requires the literal `api` before `key`, so every
        // one of the schema's own *_key credentials escaped it.
        for key in [
            "master_key",
            "signing_key",
            "shared_key",
            "virtual_key",
            "challenge_binding_key",
        ] {
            let input = format!("{key}: 6fa459eaee8a3ca4894edb77e160355e");
            let output = redact_secrets(&input);
            assert!(
                !output.contains("6fa459ea"),
                "{key} value must be masked: {output}"
            );
            assert!(contains_secret(&input), "{key} must count as a secret");
        }
    }

    #[test]
    fn short_signing_and_client_secrets_are_redacted() {
        // RE_AWS_SECRET wants an exactly-40-char base64 run, so a
        // 32-hex Slack signing secret and a Google `GOCSPX-...` client
        // secret (its hyphen breaks the run) both escaped.
        let slack = "signing_secret: 8f742231b10e8888abcd99aaabbb85a5";
        let output = redact_secrets(slack);
        assert!(
            !output.contains("8f742231b10e8888abcd99aaabbb85a5"),
            "a 32-hex signing secret must be masked: {output}"
        );
        let google = "client_secret: GOCSPX-abcDEFghiJKLmnoPQRstu";
        let output = redact_secrets(google);
        assert!(
            !output.contains("GOCSPX-abcDEFghiJKLmnoPQRstu"),
            "a GOCSPX client secret must be masked: {output}"
        );
    }

    #[test]
    fn a_short_password_is_still_redacted() {
        // `\S{8,}` let `password: hunter2` through as typed.
        let input = "password: hunter2";
        let output = redact_secrets(input);
        assert!(!output.contains("hunter2"), "{output}");
        assert!(output.contains("password=[REDACTED]"));
    }

    #[test]
    fn credential_key_references_survive_redaction() {
        // The WOR-2333 rule extends to every widened key: a resolver
        // reference names a secret, it is not one.
        for input in [
            "master_key: vault://primary/cluster?key=master",
            "client_secret: ${OIDC_CLIENT_SECRET}",
            "token: env:SB_UPSTREAM_TOKEN",
            "session_token: file:/run/secrets/session-token",
        ] {
            assert_eq!(
                redact_secrets(input),
                input,
                "a reference under a credential key must be preserved"
            );
            assert!(
                !contains_secret(input),
                "a reference must not be reported as a secret: {input}"
            );
        }
    }

    #[test]
    fn prose_about_tokens_is_not_redacted() {
        // The bare `token` key requires an explicit `:` or `=`
        // separator precisely so log prose keeps reading normally.
        let input = "request used 1204 tokens; token budget nearly exhausted";
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn a_quoted_reference_survives_its_punctuation() {
        // JSON and quoted YAML put the closing quote and comma inside the
        // `\S` run, so the trailing-punctuation trim is load bearing.
        let input = r#"{"password": "${SB_ADMIN_PASSWORD}", "port": 9901}"#;
        assert_eq!(redact_secrets(input), input);
    }
}
