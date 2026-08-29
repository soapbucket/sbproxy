//! Secrets redaction for log output.
//!
//! Scans strings for known secret patterns and replaces them with `[REDACTED]`.
//! Prevents accidental leakage of API keys, tokens, and passwords in logs.
//!
//! # What this module does and does not catch
//!
//! Every pattern here is one of two shapes.
//!
//! * *Shape* patterns match a credential by its own bytes, with no
//!   surrounding context: `sk-ant-...`, `sk-...`, `sk_live_...`,
//!   `ghp_...`, `AKIA...`, `Bearer <token>`, `Basic <creds>`.
//! * *Keyed* patterns match a credential by the name in front of it,
//!   because the value has no recognizable shape of its own:
//!   `secret...`, `api_key`, `password`, and the schema's own key /
//!   secret / token names (`RE_CREDENTIAL_KEY`, `RE_BARE_TOKEN`).
//! * One *positional* pattern, [`RE_URL_USERINFO`]. A credential
//!   embedded in a URL's userinfo has neither a recognizable shape nor
//!   a key name in front of it; what identifies it is where it sits,
//!   between `://` and `@`.
//!
//! A credential that is neither a known shape nor under a known name
//! is returned as written. In particular there is no JWT pattern: a
//! bare `eyJ...` compact JWS is only masked when it follows `Bearer `
//! or sits under one of the keyed names. `docs/access-log.md` states
//! the same limit, because the field-key denylist in
//! [`crate::logging`] is what actually covers a header value by name,
//! and it only runs when the line still parses.
//!
//! # Structure survives redaction
//!
//! `redact_secrets` runs over already-rendered JSON log lines and over
//! the YAML `GET /admin/config` hands back, so every keyed pattern
//! captures (key, separator, value) and returns groups 1 and 2 byte
//! for byte. A mask that eats the `":"` between a key and its value
//! does not merely read wrong: the line stops being JSON,
//! [`crate::logging::redact_json_line`] fails its `serde_json::from_str`
//! and silently skips the whole field-key denylist for that line, so a
//! `prompt` or `cookie` later in the same record ships verbatim. A
//! redactor that destroys the evidence it was protecting is worse than
//! one that does nothing; the shared replacement that enforces this is
//! `keyed_credential_replacement`.

use regex::Regex;
use std::sync::LazyLock;

// --- Pattern definitions ---

/// A credential in a URL's userinfo: `https://user:hvs.MUSTNOTAPPEAR...@host`.
///
/// Runs first, before every shape and keyed pattern, because it is the
/// one pattern identified by position rather than by bytes or by name.
/// A config value like `key_management.crypto.root_of_trust.address` is
/// an ordinary unparsed URL under an ordinary key name, so nothing else
/// here looks at it, and `GET /admin/config` and
/// `/admin/config/effective` handed it back verbatim while the `token`
/// beside it was masked by [`RE_BARE_TOKEN`]. The branch that added
/// that field already treats the address as secret-bearing on those
/// exact grounds, redacting it in `TransitConfig`'s and
/// `RootOfTrustConfig`'s `Debug` and keeping it out of Transit errors;
/// this closes the fourth surface.
///
/// Two groups, and only the second is masked, so the scheme and
/// everything from the `@` on survive: an operator still reads which
/// host is configured, which is the whole reason the field is on the
/// route. The whole userinfo goes, user and password together, because
/// a bare `user@host` in a config a customer sends to support is a name
/// worth not shipping either, and telling the two apart costs a branch
/// that buys nothing.
///
/// The userinfo run stops at whitespace, `/` and `@`, so a `@` later in
/// a path or query (`.../data?to=a@b`) cannot pull the match across the
/// authority: the first `/` ends the run before the `@` is reached.
static RE_URL_USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)([a-z][a-z0-9+.\-]*://)([^\s/@]+)@").expect("valid regex"));

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
/// The label runs to 26 chars (`secret` plus 20, e.g. `SECRET_ACCESS_KEY`).
///
/// Groups: label, separator, value; see
/// [`keyed_credential_replacement`]. The separator class is wide
/// enough to cover a JSON `":"`, so it used to be consumed along with
/// the label and the line stopped parsing.
static RE_AWS_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(secret[a-zA-Z0-9_]{0,20})([^a-zA-Z0-9]{1,5})([a-zA-Z0-9/+=]{40})")
        .expect("valid regex")
});

/// HTTP Authorization: Bearer tokens.
static RE_BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Bearer [a-zA-Z0-9._\-]{20,}").expect("valid regex"));

/// HTTP Authorization: Basic credentials.
static RE_BASIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Basic [a-zA-Z0-9+/=]{10,}").expect("valid regex"));

/// Generic `api_key = "..."` / `api-key: ...` patterns.
///
/// Groups: key, separator, value; see
/// [`keyed_credential_replacement`]. The separator class matches the
/// whole `":"` run in a rendered JSON line, so a captured `x-api-key`
/// request header (`access_log.capture_headers.request`) used to come
/// out as `{"request_headers":{"x-api_key=[REDACTED]"},...}`: not
/// JSON, and every denylisted field after it in the record shipped
/// verbatim as a result.
static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(api[_\-]?key)(["'\s:=]+)([a-zA-Z0-9_\-]{16,})"#).expect("valid regex")
});

/// Credential-bearing keys this product's own schema defines
/// (`master_key`, `signing_key`, `shared_key`, `virtual_key`,
/// `challenge_binding_key`, `signing_secret`, `client_secret`,
/// `session_token`) whose values have no vendor-recognizable shape of
/// their own: a 32-hex Slack signing secret, a Google `GOCSPX-...`
/// client secret (its hyphen breaks `RE_AWS_SECRET`'s base64 run), and
/// a raw cluster master key all sail past the shape patterns above.
/// Matched by key, like `api_key` and `password`, but the separator
/// must contain a real `:` or `=`: a key name that merely PRECEDES
/// other text is not an assignment. Without that, the access log's
/// `"principal_kind":"virtual_key","api_key_id":"..."` matched as
/// `virtual_key` + separator `"` + value `,"api_key_id":...`, and the
/// mask swallowed the rest of the JSON line (a v1.13 pre-release
/// regression caught by the governed_key_policy e2e). The value run
/// stops at quotes and commas for the same reason: a credential never
/// contains them, and JSON structure must survive redaction.
/// Groups: key, separator, value; see
/// [`keyed_credential_replacement`].
///
/// # This list is not exhaustive, and cannot be
///
/// The name alternation is an allowlist of names that mean the same
/// thing everywhere the redactor can see them. Two credential-bearing
/// config keys are deliberately absent because their names do not:
///
/// * `proxy.secrets.backends[].auth.external_id` is the AWS STS
///   `AssumeRole` external id, an unguessable value shared with the
///   trusting account. The same name is also the payment lane's own
///   obligation id (`StripeChargeRequest::external_id`, copied from
///   `requirement_id`), which is the join key an operator reconciles
///   settlements on. Masking by name would trade a config leak for an
///   evidence gap in the settlement records.
/// * `proxy.secrets.backends[].auth.secret_id` is the Vault AppRole
///   secret id, a live credential. `secret_id` is also the AWS
///   SecretsManager parameter naming *which secret to read*, which is
///   metadata an operator needs in an error message.
///
/// Neither pair is separable here. This module is a line-level regex
/// pass with no notion of which document a line came from, and the
/// leak surface for both is `GET /admin/config`, which redacts raw
/// YAML *text*: there is no parsed tree, so the field-key walk in
/// [`crate::logging`] and any key-path variant of it cannot reach it
/// either. The serde spellings do differ today (`external_id` in the
/// config, `externalId` on the payment wire), but that is one
/// `#[serde(rename)]` in a crate this pattern does not depend on and
/// would not be told about.
///
/// The layer that has the path is `sbproxy-config`, whose key registry
/// already enumerates both keys by their full path. A schema-driven
/// mask there would cover every backend-auth credential at once
/// instead of one name at a time; that is the fix, not another
/// alternation branch. Until then the control for these two is the
/// documented one: put a `${VAR}` or `vault://` reference in the
/// field, which [`is_secret_reference`] preserves verbatim, and rely
/// on the config file's own `0600` permissions. `docs/configuration.md`
/// already tells operators that masking is by recognized shape and key
/// name and that an unrecognized name comes back as written.
static RE_CREDENTIAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(session[_-]?token|master[_-]?key|signing[_-]?key|shared[_-]?key|virtual[_-]?key|challenge[_-]?binding[_-]?key|signing[_-]?secret|client[_-]?secret)(["'\s]*[:=]["'\s]*)([^\s"',;]{4,})"#,
    )
    .expect("valid regex")
});

/// A bare `token` key (`token: eyJ...`), which `RE_BEARER` misses
/// because it requires the literal `Bearer ` prefix. Split from
/// [`RE_CREDENTIAL_KEY`] because prose uses the word constantly
/// ("token count", "token budget"), so this one requires an explicit
/// `:` or `=` separator rather than matching across a bare space.
static RE_BARE_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(token)(["'\s]*[:=]["'\s]*)([^\s"',;]{4,})"#).expect("valid regex")
});

/// Generic `password = "..."` / `password: ...` patterns.
///
/// Groups: key, separator, value, so the value can be inspected before
/// anything is replaced ([`is_secret_reference`]) and the separator can
/// be handed back verbatim ([`keyed_credential_replacement`]).
///
/// The value run stops at whitespace, quotes, commas and semicolons:
/// the same stop set [`RE_CREDENTIAL_KEY`] uses, for the same reason.
/// Those four characters are structure in JSON, in YAML flow style and
/// in logfmt, so a run that swallows them takes the rest of the line
/// with it. The previous `\S{4,}` did exactly that: on a compact JSON
/// line it matched from the password value to the next space, and
/// `{"upstream_password":"hunter2xyz","authorization":"..."}` collapsed
/// to a single broken string.
///
/// The stated cost of the stop set, repeated in `docs/access-log.md`:
/// a password that literally contains `"`, `'`, `,` or `;` is masked
/// only up to that character, and the remainder is emitted. A
/// line-level regex cannot tell that tail from the document structure
/// around it, so the denylist in [`crate::logging`] (which keys on the
/// field name and never reads the value) is the control for those.
///
/// Minimum length 4 so short real passwords (`hunter2`) are still
/// masked, while staying above YAML's one-character block and quote
/// indicators (`|`, `>`, `-`, `"`).
static RE_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(password)(["'\s:=]+)([^\s"',;]{4,})"#).expect("valid regex")
});

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
/// `RE_API_KEY` and `RE_AWS_SECRET` need no reference check of their
/// own: their value classes (`[a-zA-Z0-9_\-]` and `[a-zA-Z0-9/+=]`)
/// cannot match `$`, `{`, `}`, or the `:` in `env:` / `vault://`, so a
/// reference never reaches them as a value in the first place.
///
/// The check is deliberately whole-value. `${VAR}suffix` is not a
/// reference, the resolver passes it through literally (and warns), so it
/// stays redactable.
fn is_secret_reference(value: &str) -> bool {
    // Defensive: every caller's value class already stops at these,
    // so a captured value cannot carry them today. Kept because the
    // check is also the public-ish contract for "is this a
    // reference", and a future caller with a wider class must not
    // silently start redacting `"${VAR}",`.
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

/// Whether a keyed pattern's captured value is one the mask actually
/// replaces.
///
/// The single predicate behind both [`keyed_credential_replacement`]
/// (the enforcer) and [`contains_secret`] (the detector), so the two
/// cannot drift: a value handed back verbatim must not be reported as
/// a secret, and a value that is reported must be one the redactor
/// really removes.
fn masks_value(value: &str) -> bool {
    // A resolver reference names a secret rather than being one, and
    // an earlier pattern's output is already masked
    // (`master_key: sk-ant-[REDACTED]` must not double-mask,
    // `token: Bearer [REDACTED]` is already done).
    !is_secret_reference(value)
        && !value.contains("[REDACTED]")
        && !value.eq_ignore_ascii_case("bearer")
        && !value.eq_ignore_ascii_case("basic")
}

/// Replacement shared by every keyed pattern: [`RE_AWS_SECRET`],
/// [`RE_API_KEY`], [`RE_CREDENTIAL_KEY`], [`RE_BARE_TOKEN`] and
/// [`RE_PASSWORD`]. Each captures (key, separator, value); groups 1
/// and 2 come back byte for byte and only group 3 is masked.
///
/// Handing the separator back is the whole point. These keys appear
/// inside JSON log lines (`"virtual_key":"..."`,
/// `"x-api-key":"..."`) and inside the YAML `GET /admin/config`
/// returns, where the `":"` or `: ` between key and value is
/// structure. Consuming it produced a line that no longer parsed, and
/// [`crate::logging::redact_json_line`] answers a parse failure by
/// returning the string unchanged, which skips the entire field-key
/// denylist (`prompt`, `messages`, `cookie`, bundle secret vars) for
/// that record. One mangled `api_key` therefore un-redacted every
/// other secret on the line.
///
/// A GET-edit-PUT round trip through `/admin/config` now returns a
/// document that still parses, with `[REDACTED]` where the inline
/// secret was. That matches what the credential-key patterns have
/// always done for `master_key`, `client_secret` and the rest, and
/// WOR-2333's loud-failure requirement survives it: unquoted
/// `[REDACTED]` is a one-element YAML flow sequence, not a string, so
/// saving the redacted document back fails on a type mismatch that
/// names the field instead of on a generic "failed to parse config
/// YAML". The earlier `password`-only behavior (deliberately
/// emitting a broken separator so the save failed) bought a worse
/// version of the same signal at the cost of corrupting every log
/// line that mentioned the word.
fn keyed_credential_replacement(caps: &regex::Captures<'_>) -> String {
    if masks_value(&caps[3]) {
        format!("{}{}[REDACTED]", &caps[1], &caps[2])
    } else {
        caps[0].to_string()
    }
}

// --- Public API ---

/// Redact secrets from a string. Returns a new string with secrets replaced.
///
/// Applies all thirteen patterns in priority order. The result is
/// suitable for safe emission in log lines or error messages.
///
/// Two properties callers depend on, both pinned by tests:
///
/// * **Every match is replaced, not the first.** Each pass is
///   `replace_all`, and each pass runs over the previous pass's whole
///   output, so a line carrying three secrets comes out with three
///   masks.
/// * **The document survives.** No pattern consumes a delimiter it
///   only matched as a boundary, so a JSON line still parses as JSON
///   and a YAML document still parses as YAML afterwards. That is what
///   lets `logging::redact_json_line` run the field-key denylist on
///   the result.
pub fn redact_secrets(input: &str) -> String {
    // Work through a scratch buffer so each replacement sees the previous output.
    // Ordering matters: more-specific patterns (Anthropic) come before more-general
    // ones (OpenAI `sk-`) to avoid double-redaction artifacts.
    // Userinfo first: it is bounded by `://` and `@` on both sides, so
    // masking it whole avoids a shape pattern hitting the embedded
    // credential first and leaving `https://user:sk-ant-[REDACTED]@host`,
    // which still names the user.
    let s = RE_URL_USERINFO.replace_all(input, "${1}[REDACTED]@");
    let s = RE_ANTHROPIC.replace_all(&s, "sk-ant-[REDACTED]");
    let s = RE_STRIPE.replace_all(&s, "stripe_[REDACTED]");
    let s = RE_OPENAI.replace_all(&s, "sk-[REDACTED]");
    let s = RE_GITHUB.replace_all(&s, "gh_[REDACTED]");
    let s = RE_AWS_ACCESS.replace_all(&s, "AKIA[REDACTED]");
    let s = RE_AWS_SECRET.replace_all(&s, keyed_credential_replacement);
    let s = RE_BEARER.replace_all(&s, "Bearer [REDACTED]");
    let s = RE_BASIC.replace_all(&s, "Basic [REDACTED]");
    let s = RE_API_KEY.replace_all(&s, keyed_credential_replacement);
    let s = RE_CREDENTIAL_KEY.replace_all(&s, keyed_credential_replacement);
    let s = RE_BARE_TOKEN.replace_all(&s, keyed_credential_replacement);
    RE_PASSWORD
        .replace_all(&s, keyed_credential_replacement)
        .into_owned()
}

/// Check if a string contains any known secret patterns.
///
/// Cheaper than a full `redact_secrets` call when you only need a boolean
/// answer (e.g. for metrics or alerting).
pub fn contains_secret(input: &str) -> bool {
    RE_URL_USERINFO.is_match(input)
        || RE_ANTHROPIC.is_match(input)
        || RE_STRIPE.is_match(input)
        || RE_OPENAI.is_match(input)
        || RE_GITHUB.is_match(input)
        || RE_AWS_ACCESS.is_match(input)
        || RE_AWS_SECRET.is_match(input)
        || RE_BEARER.is_match(input)
        || RE_BASIC.is_match(input)
        || RE_API_KEY.is_match(input)
        // A reference is not a secret, so it must not count as one
        // here either. These three run their captured value through
        // the same `masks_value` the replacement uses, so for the
        // keyed patterns this answer is exactly "would
        // `redact_secrets` change this", never wider and never
        // narrower. The two keyed patterns above stay on `is_match`
        // because their value classes cannot express a reference or a
        // prior mask: neither can hold `$`, `{`, `[`, or a `:`.
        || RE_PASSWORD
            .captures_iter(input)
            .any(|caps| masks_value(&caps[3]))
        || RE_CREDENTIAL_KEY
            .captures_iter(input)
            .any(|caps| masks_value(&caps[3]))
        || RE_BARE_TOKEN
            .captures_iter(input)
            .any(|caps| masks_value(&caps[3]))
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
        // Label and separator come back verbatim; only the value is masked.
        assert_eq!(output, "secret: [REDACTED]");
    }

    #[test]
    fn test_aws_secret_key_uppercase_label_redacted() {
        let input = "SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let output = redact_secrets(input);
        assert!(!output.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        // The label the operator wrote survives, so the line still
        // says which credential was masked.
        assert_eq!(output, "SECRET_ACCESS_KEY=[REDACTED]");
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
        assert_eq!(output, r#"{"api_key": "[REDACTED]"}"#);
    }

    #[test]
    fn test_api_key_dash_form_redacted() {
        let input = "api-key=my_secret_api_key_1234567890abcdef";
        let output = redact_secrets(input);
        assert!(!output.contains("my_secret_api_key_1234567890abcdef"));
        // The hyphenated spelling the operator wrote is not rewritten
        // to the underscore one.
        assert_eq!(output, "api-key=[REDACTED]");
    }

    #[test]
    fn test_password_redacted() {
        let input = "password: supersecretpassword123";
        let output = redact_secrets(input);
        assert!(!output.contains("supersecretpassword123"));
        assert_eq!(output, "password: [REDACTED]");
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
        assert!(output.contains(r#""api_key": "[REDACTED]""#), "{output}");
        // Non-secret fields preserved, and the line is still a document.
        assert!(output.contains("alice"));
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("still valid JSON");
        assert_eq!(parsed["user"], "alice");
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
        assert_eq!(output, "password: [REDACTED]");
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
        assert_eq!(output, "password: [REDACTED]");
    }

    #[test]
    fn a_partial_interpolation_is_not_treated_as_a_reference() {
        // `${VAR}suffix` is not a reference: the resolver passes it
        // through literally and warns. Whole-value only, so this stays
        // redactable.
        let input = "password: ${SB_ADMIN_PASSWORD}-suffix";
        assert_eq!(redact_secrets(input), "password: [REDACTED]");
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
        assert_eq!(output, "password: [REDACTED]");
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

    /// v1.13 pre-release regression, caught by the governed_key_policy
    /// e2e: the widened credential-key pattern treated the access log's
    /// `"principal_kind":"virtual_key"` as an assignment and masked the
    /// rest of the JSON line, `api_key_id` included. A key name that
    /// merely precedes other text is not an assignment, and a masked
    /// value must never swallow JSON structure.
    #[test]
    fn a_json_field_value_naming_a_key_kind_is_not_an_assignment() {
        let line =
            r#"{"principal_kind":"virtual_key","api_key_id":"e395a57ccae195f9","status":200}"#;
        let out = redact_secrets(line);
        assert_eq!(out, line, "no assignment, nothing to mask");
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("line stays valid JSON");
        assert_eq!(parsed["api_key_id"], "e395a57ccae195f9");
    }

    /// The real assignment forms still mask, and the mask stops at the
    /// JSON string terminator instead of eating the next field.
    #[test]
    fn a_real_credential_assignment_masks_only_its_value() {
        let out = redact_secrets(r#"{"virtual_key":"abcd1234secretvalue","next_field":"stays"}"#);
        assert!(!out.contains("abcd1234secretvalue"), "got: {out}");
        assert!(out.contains(r#""next_field":"stays""#), "got: {out}");
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("still valid JSON");
        assert_eq!(parsed["next_field"], "stays");
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
        // JSON and quoted YAML put the closing quote and comma right
        // after the value, so the value run has to stop at them.
        let input = r#"{"password": "${SB_ADMIN_PASSWORD}", "port": 9901}"#;
        assert_eq!(redact_secrets(input), input);
    }

    // --- The mask must not eat the key separator ---
    //
    // `RE_API_KEY`, `RE_AWS_SECRET` and `RE_PASSWORD` used to replace
    // the whole key-separator-value run with a flat `key=[REDACTED]`
    // token. Two consequences, and the second is the serious one: the
    // emitted line stopped being JSON, and `redact_json_line` answers
    // a parse failure by returning the string untouched, so the whole
    // field-key denylist was skipped for that record.
    //
    // Asserting only that the secret is gone passes on both sides of
    // the fix and proves nothing. Each of these asserts on structure.

    #[test]
    fn a_captured_api_key_header_keeps_the_line_parseable() {
        // `access_log.capture_headers.request: ["x-api-key"]` is an
        // anticipated configuration, and headers are captured
        // lowercased with hyphens. The old output was
        // `{"request_headers":{"x-api_key=[REDACTED]"},...}`.
        let line = r#"{"request_headers":{"x-api-key":"abcdefghijklmnop1234"},"status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(
            parsed["request_headers"]["x-api-key"], "[REDACTED]",
            "{out}"
        );
        assert_eq!(parsed["status"], 200, "{out}");
        assert!(!out.contains("abcdefghijklmnop1234"), "{out}");
    }

    #[test]
    fn a_secret_labeled_value_keeps_the_line_parseable() {
        // `RE_AWS_SECRET`'s separator class `[^a-zA-Z0-9]{1,5}` covers
        // the JSON `":"` run, so it took the key with it and the old
        // output was `{"secret=[REDACTED]","status":200}`.
        let line = r#"{"secret_hash":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(parsed["secret_hash"], "[REDACTED]", "{out}");
        assert_eq!(parsed["status"], 200, "{out}");
    }

    #[test]
    fn an_inline_password_no_longer_swallows_the_rest_of_the_line() {
        // The old value run was `\S{4,}`, and a compact JSON line has
        // no spaces in it, so the match ran from the password value to
        // the end of the record.
        let line = r#"{"upstream_password":"hunter2xyz","tenant":"acme","status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(parsed["upstream_password"], "[REDACTED]", "{out}");
        assert_eq!(parsed["tenant"], "acme", "{out}");
        assert_eq!(parsed["status"], 200, "{out}");
    }

    #[test]
    fn three_secrets_on_one_line_are_all_masked() {
        // The scan does not stop at the first hit: every pass is
        // `replace_all`, and each pass runs over the previous pass's
        // whole output. The old result was
        // `{"x-api_key=[REDACTED]","upstream_password=[REDACTED] [REDACTED]","status":200}`
        // -- two of the three key names gone, the third field erased.
        let line = concat!(
            r#"{"x-api-key":"abcdefghijklmnop1234","#,
            r#""upstream_password":"hunter2xyz","#,
            r#""authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc","#,
            r#""status":200}"#
        );
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(parsed["x-api-key"], "[REDACTED]", "{out}");
        assert_eq!(parsed["upstream_password"], "[REDACTED]", "{out}");
        assert_eq!(parsed["authorization"], "Bearer [REDACTED]", "{out}");
        assert_eq!(parsed["status"], 200, "{out}");
    }

    #[test]
    fn a_redacted_yaml_flow_mapping_still_parses() {
        // The other document format this pass runs over. Flow style is
        // where the comma in the value stop set earns its place: the
        // old output was `admin: {password=[REDACTED] port: 9901}`,
        // which is not YAML at all.
        //
        // Note what the marker becomes: unquoted `[REDACTED]` is a
        // one-element flow *sequence*, not a string. That is the same
        // thing `master_key: [REDACTED]` has always produced, and it
        // is the property that keeps a GET-edit-PUT round trip honest
        // -- the document parses, and the save then fails on a type
        // mismatch that names the field, rather than on a generic
        // "failed to parse config YAML".
        let input = "admin: {password: hunter2, port: 9901}";
        let out = redact_secrets(input);
        assert_eq!(out, "admin: {password: [REDACTED], port: 9901}");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&out).unwrap_or_else(|e| panic!("not YAML ({e}): {out}"));
        assert_eq!(parsed["admin"]["port"].as_u64(), Some(9901));
        // The marker is a sequence, so it is deliberately not a string.
        assert_eq!(parsed["admin"]["password"].as_str(), None, "{out}");
    }

    #[test]
    fn a_password_containing_a_comma_is_masked_only_up_to_the_comma() {
        // The stated cost of the value stop set, pinned so it is a
        // known limit rather than a surprise. A line-level regex
        // cannot tell a comma inside an unquoted YAML scalar from the
        // comma that ends a JSON member or a flow entry, and guessing
        // wrong destroys the document. `docs/access-log.md` tells
        // operators the same thing.
        let out = redact_secrets("password: p@ss,word-tail");
        assert_eq!(out, "password: [REDACTED],word-tail");
    }

    /// A tripwire, not a wish. `external_id` and `secret_id` are
    /// credential-bearing config keys the name alternation deliberately
    /// leaves out, because each name is also a non-secret identifier
    /// elsewhere in the product: `external_id` is the settlement
    /// obligation id operators reconcile on, and `secret_id` is the
    /// AWS SecretsManager parameter naming which secret to read.
    /// Widening the alternation would trade a config-read leak for an
    /// evidence gap. Read the note on `RE_CREDENTIAL_KEY` before
    /// changing this; the fix that works is a key-path mask in
    /// `sbproxy-config`, which is the layer that knows the path.
    #[test]
    fn two_overloaded_credential_names_are_left_out_on_purpose() {
        for input in [
            "external_id: 7f3c9a21b4e64d80",
            "secret_id: 3e1b9c74-5a2f-4c8d-9b17-6e0a2d4f8c31",
        ] {
            assert_eq!(
                redact_secrets(input),
                input,
                "if this now masks, the reasoning on RE_CREDENTIAL_KEY has to change with it"
            );
        }
    }

    #[test]
    fn contains_secret_answers_exactly_what_redact_secrets_would_change() {
        // Detector and enforcer share `masks_value`, so they cannot
        // drift. The password arm read capture group 2 while the
        // replacement read group 3; adding the separator group without
        // moving the index would have made every `password:` line
        // report a secret whether or not one was there.
        for input in [
            "password: hunter2",
            "password: ${SB_ADMIN_PASSWORD}",
            "token: env:SB_UPSTREAM_TOKEN",
            "master_key: 6fa459eaee8a3ca4894edb77e160355e",
            "client_secret: vault://primary/oidc?key=client_secret",
            "GET /health HTTP/1.1 200 OK",
        ] {
            assert_eq!(
                contains_secret(input),
                redact_secrets(input) != input,
                "detector and enforcer disagree on: {input}"
            );
        }
    }

    /// The seam: a credential carried in a URL's userinfo, on the two
    /// routes that hand a whole config document back.
    ///
    /// `key_management.crypto.root_of_trust.address` is an unparsed URL
    /// under a key name no pattern here matches. Its `token` sibling is
    /// masked by `RE_BARE_TOKEN`, so the field beside it came back in
    /// full: `GET /admin/config` returned
    /// `address: https://sbproxy:hvs.MUSTNOTAPPEAR...@vault.internal:8200` to
    /// anyone who could read the route, which is a Vault token in a
    /// document operators paste into support tickets.
    ///
    /// Deleting `RE_URL_USERINFO` from `redact_secrets` reddens this on
    /// the first assertion. The last two are the boundary: the mask must
    /// not eat the host (an operator still has to see which Vault is
    /// configured) and must not fire on a `@` that lives in a path or a
    /// query, where it is not userinfo at all.
    #[test]
    fn a_credential_in_a_urls_userinfo_is_masked_on_the_config_routes() {
        let out = redact_secrets(
            "  address: https://sbproxy:hvs.MUSTNOTAPPEARINACONFIGROUTE@vault.internal:8200",
        );
        assert_eq!(
            out, "  address: https://[REDACTED]@vault.internal:8200",
            "userinfo must be masked whole, and the host must survive it"
        );
        assert!(!out.contains("hvs.MUSTNOTAPPEARINACONFIGROUTE"));
        assert!(contains_secret(
            "address: https://sbproxy:hvs.MUSTNOTAPPEARINACONFIGROUTE@vault.internal:8200"
        ));

        // A bare user is masked too: telling a name from a password
        // costs a branch that buys nothing, and a username is not worth
        // shipping either.
        assert_eq!(
            redact_secrets("amqp://svc-billing@broker.internal:5672"),
            "amqp://[REDACTED]@broker.internal:5672"
        );

        // The boundary. An `@` after the authority is not userinfo, and
        // a URL without one is returned as written.
        for untouched in [
            "GET https://api.example.com/v1/data?notify=ops@example.com 200",
            "https://vault.internal:8200/v1/transit/decrypt/sbproxy-root",
            "vault://primary/upstream?key=openai",
        ] {
            assert_eq!(
                redact_secrets(untouched),
                untouched,
                "no userinfo here, so nothing to mask: {untouched}"
            );
        }
    }
}
