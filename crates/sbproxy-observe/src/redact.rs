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
//! * One *positional* rule, `mask_url_userinfo`. A credential embedded
//!   in a URL's userinfo has neither a recognizable shape nor a key
//!   name in front of it; what identifies it is where it sits, between
//!   `://` and the last `@` of the authority. The authority is matched
//!   by an allowlist, `[A-Za-z0-9]` plus `-._~%:@`, which is a strict
//!   subset of the RFC 3986 authority charset. Neither `"` nor `\` is
//!   in it, and that is what keeps a rule with no key name to anchor on
//!   inside the JSON string token it started in.
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

/// Mask the userinfo of every URL in `input`: `https://user:tok@host`
/// becomes `https://[REDACTED]@host`.
///
/// Runs before every shape and keyed pattern, because it is the one rule
/// here that identifies a credential by position rather than by its bytes
/// or by the name in front of it. A config value like
/// `key_management.crypto.root_of_trust.address` is an ordinary unparsed
/// URL under an ordinary key name, so nothing else in this module looks at
/// it, and `GET /admin/config` and `/admin/config/effective` handed it
/// back verbatim while the `token` beside it was masked by
/// [`RE_BARE_TOKEN`]. The branch that added that field already treats the
/// address as secret-bearing on those exact grounds, redacting it in
/// `TransitConfig`'s and `RootOfTrustConfig`'s `Debug` and keeping it out
/// of Transit errors; this closes the fourth surface.
///
/// The scheme and everything from the `@` on survive, so an operator still
/// reads which host is configured, which is the whole reason the field is
/// on the route. The whole userinfo goes, user and password together,
/// because a bare `user@host` in a config a customer sends to support is a
/// name worth not shipping either, and telling the two apart costs a
/// branch that buys nothing.
///
/// # The authority run is an allowlist, and that is the load-bearing part
///
/// The first version of this stopped the run at three bytes, `@`, `/`, and
/// whitespace, which is a denylist and was wrong in the way this module
/// has already been wrong three times. On a rendered JSON line a URL with
/// no path, `{"src":"https://ref.example"}`, ran straight through the
/// closing quote and the comma and the next key and deleted everything up
/// to some later `@` in the record. That does not merely mangle one field:
/// [`crate::logging::redact_json_line`] applies the field-key denylist only
/// when the secret pass left something that still parses, so a line this
/// broke shipped its `prompt`, its `cookie`, and any bundle secret var on
/// the same record verbatim. `user_agent` and `referer` are client-set and
/// serialize before `user`, `metadata`, `attribution`, and
/// `request_headers`, so a caller could reach it from a request header.
///
/// So the run is an allowlist. A byte continues the authority only if it
/// is one of:
///
/// ```text
/// A-Z a-z 0-9   - . _ ~   %   :   @
/// ```
///
/// Unreserved characters, percent-encoding, the `:` that separates user
/// from password and host from port, and `@` itself. That is a strict
/// subset of what RFC 3986 permits in an authority, chosen so the run
/// cannot walk out of the field it started in.
///
/// # Two surfaces, two sets, and why one cannot serve both
///
/// The narrow set is `[A-Za-z0-9]` plus `-._~%:@`. The wide set adds the
/// RFC 3986 userinfo sub-delims that are not structure anywhere this runs,
/// `!$&*+=`. [`redact_secrets`] takes the narrow one, and
/// [`redact_config_document`] the wide one. Each got its set from a
/// finding, so both are worth stating.
///
/// **Why the log pass is narrow.** The first allowlist kept `&` and `=`
/// on the reasoning that they are legal in an authority and are not
/// structure. They are the structural bytes of a query string and of
/// `application/x-www-form-urlencoded`, a serialization that reasoning
/// did not name. The access log stores the client's raw query string with
/// the leading `?` already stripped, so
/// `u=https://a.example&op=drop_all&next=b@c.example` had no `?` left to
/// stop on and masked to `u=https://[REDACTED]@c.example`. Nothing leaked,
/// because the line still parsed, but the caller chose the ordering of
/// their own parameters and therefore chose which of them survived into
/// their own audit record.
///
/// **Why the config pass is wide.** Narrowing the set then created the
/// opposite defect on the three routes this mask was written for.
/// `https://sbproxy:hvs.CAESIQpAbCdEf=@vault.internal:8200` is an ordinary
/// value of `key_management.crypto.root_of_trust.address`, because a Vault
/// token is `hvs.` plus base64 and `=` is its padding; stopping at `=`
/// returned it verbatim. `p&w0rd` is the same story for `&`.
///
/// The difference between the surfaces is not a preference, it is who
/// chose the delimiter. In a log line the run can be inside a field whose
/// own delimiters an attacker supplied. In a rendered config document
/// there is no such field: the value is a whole scalar and the delimiter
/// around it was chosen by the renderer, a newline in block YAML or a `"`
/// in pretty JSON, neither of which is in either set.
///
/// `[` and `]` are in neither set. RFC 3986 forbids them in userinfo, and
/// an IPv6 host sits *after* the `@`, so the run would only need them to
/// keep scanning for a later `@` that a well-formed URL cannot have.
/// `https://u:pw@[2001:db8::1]:8200` masks identically without them.
///
/// # Why a line still parses, which is not the byte-class argument
///
/// An earlier version of this comment claimed the rule cannot break a line
/// "because no allowed byte is structure". That is false and worth
/// correcting rather than quietly narrowing: `:` is JSON structure and is
/// allowed, and it has to be. The property holds for a different and
/// stronger reason.
///
/// The mask deletes exactly the bytes in `[authority, at)`, every one of
/// which passed `continues_authority`. Neither `"` nor `\` is in that set.
/// A JSON string ends only at an unescaped `"`, and every escape sequence
/// begins with `\`. So a deleted span can contain neither a string
/// terminator nor any part of an escape, and **it cannot leave the JSON
/// string token it started in.** A `:` inside a string value is not
/// structure; only one outside a string is, and the run cannot reach it.
/// That is an argument about the two bytes that delimit the token, not
/// about the class of every byte in the set, and it is what
/// `a_url_in_a_json_field_keeps_the_line_parseable` pins.
///
/// The other serializations are held by their own delimiters rather than
/// by a claim about byte classes. Whitespace ends a logfmt pair and an
/// unquoted YAML scalar; `,` ends a YAML flow scalar, though not a logfmt
/// value, where a comma is legal unquoted; `&` and `=` end a query
/// parameter. None of those four bytes is in the log-line set.
///
/// # What it therefore does not mask, stated rather than discovered
///
/// Userinfo containing any byte outside the surface's set is not masked at
/// all, rather than masked halfway. For both surfaces that covers `'`,
/// `(`, `)`, `,`, `;`, which RFC 3986 permits in userinfo, and **every
/// non-ASCII byte**, so `https://usér:pw@vault.internal:8200` comes back
/// verbatim. For the log surface it also covers `!$&*+=`. Failing to mask
/// is the safe direction here and deleting a delimiter is not, which is
/// the same trade [`RE_PASSWORD`] documents for its own stop set.
///
/// **The control differs by surface, and naming the wrong one is how this
/// went wrong once already.** On a log line it is the field-name denylist
/// in [`crate::logging`], which keys on the name and never reads a value.
/// That denylist runs inside `redact_json_line` and **does not run on the
/// config routes**: there `redact_config_document` is the whole pass. The
/// control there is the one [`RE_CREDENTIAL_KEY`] already names for the
/// two field names it deliberately leaves out: put a `${VAR}` or
/// `vault://` reference in the field, which [`is_secret_reference`]
/// preserves verbatim and which never holds the value in the first place,
/// and rely on the config file's own `0600` permissions. Percent-encoding
/// the userinfo also restores the mask on either surface, since `%` is in
/// both sets.
///
/// # The last `@`, not the first
///
/// The run continues past an `@` and remembers the most recent one, because
/// `@` is legal in a password and common in generated ones. Stopping at the
/// first left `https://user:p@ssw0rd@vault.internal:8200` masked to
/// `https://[REDACTED]@ssw0rd@vault.internal:8200`, publishing six bytes of
/// the password on the one field this rule exists for.
///
/// # Boundaries
///
/// The arithmetic is byte-wise and stays on character boundaries, because
/// every byte it compares or splits at is ASCII and no UTF-8 continuation
/// byte matches one.
///
/// The scheme run walks back over `[A-Za-z0-9+.-]` and requires the byte it
/// lands on to be a letter, so a URL glued directly to a preceding digit
/// with no separator (`8080https://u:p@h`) is not masked. It is *not* true
/// that every `[0-9+.-]` prefix has that effect, which an earlier version
/// of this note claimed: `v1.2https://u:p@h` and `x.https://u:p@h` both
/// mask, because the walk-back continues through `.` and `-` to a letter.
/// Over-masking is the safe direction, so the difference is documented
/// rather than removed.
fn mask_url_userinfo(input: &str, sub_delims: bool) -> std::borrow::Cow<'_, str> {
    // Unreserved, percent-encoding, `:` and `@`, plus the userinfo
    // sub-delims when the caller is a whole config document. See the
    // allowlist section above for why the two surfaces differ and why
    // `[` and `]` are in neither.
    fn continues_authority(c: u8, sub_delims: bool) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b'~' | b'%' | b':' | b'@')
            || (sub_delims && matches!(c, b'!' | b'$' | b'&' | b'*' | b'+' | b'='))
    }

    let bytes = input.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut search = 0usize;

    while let Some(offset) = input[search..].find("://") {
        let colon = search + offset;
        let authority = colon + 3;
        // Advance past this separator whatever happens below, so a URL
        // carrying no userinfo cannot spin here.
        search = authority;

        // A scheme is one or more of `[A-Za-z0-9+.-]` ending at the colon
        // and opening with a letter. Without one, `://` is three
        // characters in some prose.
        let mut scheme = colon;
        while scheme > 0 {
            let c = bytes[scheme - 1];
            if c.is_ascii_alphanumeric() || c == b'+' || c == b'.' || c == b'-' {
                scheme -= 1;
            } else {
                break;
            }
        }
        if scheme == colon || !bytes[scheme].is_ascii_alphabetic() {
            continue;
        }

        // Walk the whole authority and keep the LAST `@`, not the first.
        let mut at = None;
        let mut i = authority;
        while i < bytes.len() && continues_authority(bytes[i], sub_delims) {
            if bytes[i] == b'@' {
                at = Some(i);
            }
            i += 1;
        }
        // `scheme://@host` carries no userinfo to mask.
        let Some(at) = at.filter(|at| *at > authority) else {
            continue;
        };

        let buffer = out.get_or_insert_with(String::new);
        buffer.push_str(&input[copied..authority]);
        buffer.push_str("[REDACTED]");
        copied = at;
        search = at + 1;
    }

    match out {
        Some(mut buffer) => {
            buffer.push_str(&input[copied..]);
            std::borrow::Cow::Owned(buffer)
        }
        None => std::borrow::Cow::Borrowed(input),
    }
}

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
        r#"(?i)\b(session[_-]?token|master[_-]?key|signing[_-]?key|shared[_-]?key|virtual[_-]?key|challenge[_-]?binding[_-]?key|signing[_-]?secret|client[_-]?secret|pepper)(["'\s]*[:=]["'\s]*)([^\s"',;]{4,})"#,
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
        // `sbproxy config print` masks by key name first, stamping
        // `***MASKED***`, and then runs this pass over the rendered
        // document so a URL's userinfo is caught by position. Without this
        // arm a value that both passes recognize comes back as
        // `[REDACTED]` while its neighbours keep `***MASKED***`, so one
        // operator surface shows two markers for the same thing. Harmless
        // for secrecy, since it is double-masking, and confusing to read.
        && !value.contains("***MASKED***")
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

/// Redact secrets from a **log line, an error, or any other free text**.
///
/// This is the pass for input that may embed a URL inside a
/// caller-controlled field, and the access log is the case that matters:
/// its `query` field holds the client's raw query string with the leading
/// `?` already stripped, so `&` and `=` are live delimiters inside it and
/// the userinfo run must stop at them. See
/// [`redact_config_document`] for the other surface, and the
/// `mask_url_userinfo` doc for why one byte set cannot serve both.
///
/// Applies the userinfo rule and then all twelve patterns, in priority
/// order. The result is suitable for safe emission in log lines or error
/// messages.
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
    redact_with(input, false)
}

/// Redact secrets from a **rendered config document**: the YAML
/// `GET /admin/config` and `/admin/config/effective` return, the stored
/// documents `GET /admin/config/history/{digest}` hands back, and the
/// output of `sbproxy config print`.
///
/// Identical to [`redact_secrets`] except that a URL's userinfo may also
/// contain the RFC 3986 sub-delims `!$&*+=`, and the difference is the
/// whole point of there being two functions.
///
/// On these surfaces a URL is a complete scalar value written by the
/// operator, and `=` is base64 padding: a Vault token is `hvs.` plus
/// base64, so `https://sbproxy:hvs.CAESIQpAbCdEf=@vault.internal:8200`
/// is an ordinary value of `key_management.crypto.root_of_trust.address`.
/// Stopping the run at `=` leaves that credential in the clear on the
/// three routes this mask was written for. There is no caller-supplied
/// query field in a rendered config document, so the delimiter that
/// bounds the run is the one the *renderer* chose, not one an attacker
/// picked: a newline in block YAML, a `"` in pretty JSON. Neither is in
/// either set, so the same "cannot leave the token it started in"
/// argument holds here.
///
/// The narrower [`redact_secrets`] must not be widened to match. Its
/// input includes a field whose own delimiters are `&` and `=`, and
/// admitting them there let a caller delete their own query parameters
/// from their own audit record.
pub fn redact_config_document(input: &str) -> String {
    redact_with(input, true)
}

/// The shared body of [`redact_secrets`] and [`redact_config_document`].
///
/// `sub_delims` selects the authority set; every pattern after the
/// userinfo rule is identical, because those match by shape or by an
/// adjacent key name and neither depends on the surface.
fn redact_with(input: &str, sub_delims: bool) -> String {
    // Work through a scratch buffer so each replacement sees the previous output.
    // Ordering matters: more-specific patterns (Anthropic) come before more-general
    // ones (OpenAI `sk-`) to avoid double-redaction artifacts.
    // Userinfo first: it is bounded by `://` and `@` on both sides, so
    // masking it whole avoids a shape pattern hitting the embedded
    // credential first and leaving `https://user:sk-ant-[REDACTED]@host`,
    // which still names the user.
    let s = mask_url_userinfo(input, sub_delims);
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
    matches!(mask_url_userinfo(input, false), std::borrow::Cow::Owned(_))
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
    /// Deleting `mask_url_userinfo` from `redact_secrets` reddens this on
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

        // A password with an unencoded `@` in it. The run keeps the
        // LAST `@`, not the first: stopping at the first published
        // `ssw0rd` on the one field this rule exists for.
        assert_eq!(
            redact_secrets("address: https://user:p@ssw0rd@vault.internal:8200"),
            "address: https://[REDACTED]@vault.internal:8200",
            "the mask must run to the last @ of the authority"
        );

        // The boundary, and every case here has to be able to fail.
        // The first three carry the `@` after a `?`, a `#`, and a `/`
        // respectively, which are the three RFC 3986 authority
        // terminators; the earlier version of this test asserted only
        // the `/` shape, so the `?` and `#` claims its doc comment made
        // were held up by cases that could not fail. The fourth has no
        // `@` at all.
        for untouched in [
            "GET https://api.example.com?notify=ops@example.com 200",
            "GET https://api.example.com#ops@example.com 200",
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

    /// The two surfaces want different authority sets, and this is the
    /// pair of cases that forced that.
    ///
    /// A Vault token is `hvs.` plus base64, so `=` is padding and belongs
    /// in the userinfo of a perfectly ordinary
    /// `key_management.crypto.root_of_trust.address`. Stopping the run at
    /// `=` returned it in the clear on the three config routes. But `=`
    /// and `&` are also the delimiters of the access log's `query` field,
    /// which holds the client's raw query with the `?` already stripped,
    /// and admitting them there let a caller delete their own parameters
    /// from their own record.
    ///
    /// Narrowing `redact_config_document` to the log set reddens the first
    /// two assertions; widening `redact_secrets` to the document set
    /// reddens the third.
    #[test]
    fn the_config_document_pass_masks_a_sub_delim_userinfo_and_the_log_pass_does_not() {
        // Base64 padding, on the field the epic is sold on.
        assert_eq!(
            redact_config_document(
                "      address: https://sbproxy:hvs.CAESIQpAbCdEf=@vault.internal:8200"
            ),
            "      address: https://[REDACTED]@vault.internal:8200",
            "a base64-padded token is an ordinary value of this field"
        );
        // And a sub-delim in a password.
        assert_eq!(
            redact_config_document("      address: https://sbproxy:p&w0rd@vault.internal:8200"),
            "      address: https://[REDACTED]@vault.internal:8200"
        );

        // The same bytes on the log surface must NOT extend the run: this
        // is the query-string case, where `&` and `=` belong to the field
        // rather than to the URL.
        let line = r#"{"query":"u=https://a.example&op=drop_all&next=b@c.example","status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(
            parsed["query"], "u=https://a.example&op=drop_all&next=b@c.example",
            "the log pass must not admit the query delimiters: {out}"
        );

        // Percent-encoding restores the mask on the log surface, which is
        // the documented mitigation and is worth pinning as one.
        assert_eq!(
            redact_secrets("address: https://sbproxy:hvs.CAESIQpAbCdEf%3D@vault.internal:8200"),
            "address: https://[REDACTED]@vault.internal:8200"
        );

        // A block-YAML document is bounded by newlines, so the wider set
        // still cannot leave the value it started in.
        let doc = "crypto:\n  address: https://u:a=b&c@vault.internal:8200\n  other: keep@me\n";
        assert_eq!(
            redact_config_document(doc),
            "crypto:\n  address: https://[REDACTED]@vault.internal:8200\n  other: keep@me\n"
        );
    }

    /// `key_management.crypto`'s two locally-held secrets are both
    /// covered, on both surfaces.
    ///
    /// `pepper` was on no key-name list and no shape pattern, so an
    /// inline one came back verbatim from `GET /admin/config`. It is the
    /// salt inbound key hashes are built with: leaking it is what makes a
    /// stolen hash table worth brute-forcing.
    #[test]
    fn the_locally_held_crypto_secrets_are_masked_by_name() {
        for surface in [
            redact_secrets as fn(&str) -> String,
            redact_config_document as fn(&str) -> String,
        ] {
            let out = surface(
                "  pepper: a-long-random-server-pepper\n  master_key: a-long-random-master-key\n",
            );
            assert!(!out.contains("a-long-random-server-pepper"), "{out}");
            assert!(!out.contains("a-long-random-master-key"), "{out}");
            assert_eq!(out.matches("[REDACTED]").count(), 2, "{out}");
        }
        // A reference names a secret rather than being one, so it shows.
        assert_eq!(
            redact_secrets("pepper: vault://primary/cluster?key=pepper"),
            "pepper: vault://primary/cluster?key=pepper"
        );
    }

    /// The invariant the whole module is built on, for the one rule that
    /// matches by position: **a redacted line still parses, and no field
    /// but the one the URL sits in changes at all.**
    ///
    /// This is the fourth entry in the family above and it exists because
    /// the first version of this rule was the fourth pattern to break the
    /// rule the family holds. Its authority run stopped at three bytes,
    /// `@`, `/`, and whitespace, so a URL with no path ran through the
    /// closing quote of its own JSON string and deleted every byte up to
    /// some later `@` in the record. `redact_json_line` applies the
    /// field-key denylist only on the `Ok` arm, so a line it broke shipped
    /// `prompt` in the clear.
    ///
    /// **Every block below has to be able to fail under that revert**, and
    /// an earlier version of this test failed that bar: three of its four
    /// blocks produced byte-identical output on both sides, which is the
    /// "asserted by cases that cannot fail" shape a previous round raised
    /// against someone else's test. Reverting `continues_authority` to
    /// `!(c == b'/' || c.is_ascii_whitespace())` reddens each block here,
    /// and `redfirst-round5.txt` records the run.
    #[test]
    fn a_url_in_a_json_field_keeps_the_line_parseable() {
        // 1. The nested shape, which is the actual Blocker mechanism: the
        //    old rule deleted `"},"user":"ops` and the line **stopped
        //    parsing**, which is what dropped the denylist for the whole
        //    record. The flat shape below reddens through field deletion
        //    instead, so both outcomes are pinned rather than one.
        let line = r#"{"attribution":{"src":"https://ref.example"},"user":"ops@corp.com","prompt":"leak me"}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(parsed["attribution"]["src"], "https://ref.example", "{out}");
        assert_eq!(parsed["user"], "ops@corp.com", "{out}");
        assert_eq!(parsed["prompt"], "leak me", "{out}");

        // 2. The flat shape a client can produce directly: `user_agent`
        //    and `referer` are client-set and serialize before `user` and
        //    `prompt`.
        let line = r#"{"user_agent":"https://ref.example","referer":"b@c","user":"ops@corp.com","prompt":"leak me"}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(parsed["user_agent"], "https://ref.example", "{out}");
        assert_eq!(parsed["referer"], "b@c", "{out}");
        assert_eq!(parsed["user"], "ops@corp.com", "{out}");
        assert_eq!(parsed["prompt"], "leak me", "{out}");

        // 3. The query string, which is the fourth serialization this rule
        //    meets and the one an allowlist built only from "legal in an
        //    authority and not JSON structure" got wrong. The access log
        //    stores the client's raw query with the leading `?` already
        //    stripped, so there is no `?` left to stop the run: with `&`
        //    and `=` in the set this masked to `u=https://[REDACTED]@c.example`
        //    and the caller had deleted `op=drop_all` from their own audit
        //    record by choosing the order of their own parameters.
        let line = r#"{"path":"/v1/api","query":"u=https://a.example&op=drop_all&next=b@c.example","status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(
            parsed["query"], "u=https://a.example&op=drop_all&next=b@c.example",
            "a caller must not be able to delete their own query parameters \
             from their own record: {out}"
        );

        // 4. The case the rule is actually for, in the same shape: the
        //    userinfo goes, the field keeps its quotes, and the record
        //    still parses with every other field intact. This block pins
        //    the mask itself rather than the stop set, so it is the one
        //    that reddens when `mask_url_userinfo` is removed from
        //    `redact_secrets` rather than when the set is widened.
        let line = r#"{"address":"https://sbproxy:tok3n@vault.internal:8200","user":"ops@corp.com","status":200}"#;
        let out = redact_secrets(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted line is not JSON ({e}): {out}"));
        assert_eq!(
            parsed["address"], "https://[REDACTED]@vault.internal:8200",
            "{out}"
        );
        assert_eq!(parsed["user"], "ops@corp.com", "{out}");
        assert_eq!(parsed["status"], 200, "{out}");
        assert!(!out.contains("tok3n"), "{out}");

        // 5. The same invariant in the other two serializations the stop
        //    set names, twice over.
        //
        //    The `,` forms are the ones that can fail under the named
        //    revert, because the old rule stopped at whitespace and a
        //    space-separated fixture passes on both sides of it. The
        //    space forms cannot fail under *that* revert and are kept
        //    anyway: they are the only thing pinning "whitespace ends the
        //    run", which an earlier version of this test dropped when it
        //    rewrote both blocks to commas. They redden if whitespace is
        //    ever admitted to the set.
        for (fixture, label) in [
            (
                "[https://ref.example,b@c.example]",
                "YAML flow sequence, comma",
            ),
            (
                "{url: https://ref.example, user: ops@corp.com}",
                "YAML flow mapping, space",
            ),
            (
                "url=https://ref.example,next=b@c.example",
                "logfmt, comma inside an unquoted value",
            ),
            (
                "url=https://ref.example next=b@c.example",
                "logfmt, space between pairs",
            ),
        ] {
            assert_eq!(redact_secrets(fixture), fixture, "{label}");
        }
    }
}
