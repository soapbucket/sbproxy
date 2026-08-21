//! Render an operator-supplied URL in the only shape that is safe to put
//! in a log line, an error string, or a `Debug` impl.
//!
//! # Why this is here rather than in each crate
//!
//! Four private copies of this idea already existed, and they had drifted
//! into four different answers (WOR-2629, WOR-2640). The AI guardrail
//! stripped userinfo, path, query, and fragment. The alerting runtime kept
//! scheme and host but dropped the port, so two receivers on one host read
//! as the same target. The mesh Redis backend masked the password and kept
//! the username, path, and query. The MCP action called
//! [`url::Url::origin`] inline, which is the right answer and the one this
//! module standardizes on, except that an origin is opaque for every
//! scheme the URL spec does not call special and serializes to the literal
//! `"null"`. That is every DSN this workspace actually handles: `redis://`,
//! `rediss://`, `s3://`, `gs://`.
//!
//! What all four are guarding against is one thing. An operator URL is a
//! credential carrier twice over: `scheme://user:password@host` puts the
//! password in the authority, and a Slack, Teams, or PagerDuty webhook
//! puts the whole secret in the path. Both reach shared observability
//! systems the moment the connection goes wrong, which is exactly when
//! they get logged.
//!
//! The scheme, host, and port are the part an operator needs in order to
//! act on a failure, and the part the egress inventory already records for
//! the same dial. So that is what these functions return, and nothing
//! else.
//!
//! # Log forging
//!
//! Parsing is the sanitizer. A host that survives [`url::Url::parse`]
//! cannot contain a newline or a carriage return, so a rendered origin
//! cannot forge a second log line. Anything that fails to parse renders as
//! a constant and is never echoed back.

use url::Url;

/// Returned for input that does not parse as a URL at all.
///
/// Deliberately a constant rather than the input: an unparseable value may
/// be a password pasted into the wrong config key, and echoing it back
/// through a log is the leak this module exists to stop.
const INVALID: &str = "[invalid url]";

/// Stands in for the host of a URL that has no authority component, such
/// as a `unix:` socket DSN or a cannot-be-a-base URL. The scheme alone is
/// never a credential and is the useful half of the diagnosis.
const NO_HOST: &str = "[no host]";

/// Render `raw` as its origin: `scheme://host`, plus `:port` when the URL
/// names one that is not the scheme's default.
///
/// Username, password, path, query, and fragment are all dropped. This is
/// the default form and the one every log site should reach for.
///
/// For the schemes the URL spec calls special this is byte-identical to
/// `url.origin().ascii_serialization()`, the idiom the MCP action already
/// used. Unlike that method it also works for `redis://` and the
/// object-store schemes, whose origins are opaque and serialize to the
/// literal `"null"`.
///
/// ```
/// use sbproxy_security::url_redact::redacted_url;
/// assert_eq!(
///     redacted_url("redis://admin:hunter2@cache.internal:6379/0"),
///     "redis://cache.internal:6379"
/// );
/// assert_eq!(
///     redacted_url("https://hooks.slack.com/services/T0/B0/xoxb-secret"),
///     "https://hooks.slack.com"
/// );
/// ```
#[must_use]
pub fn redacted_url(raw: &str) -> String {
    let Ok(url) = Url::parse(raw) else {
        return INVALID.to_string();
    };
    origin_of(&url)
}

/// [`redacted_url`], but `None` instead of a placeholder for input that
/// has no origin to render: anything that does not parse, and anything
/// with no authority component.
///
/// For a log line the placeholder is the better answer, because the line
/// fires either way and "the URL did not parse" is the diagnosis. For a
/// document that an operator console renders, it is not: a field carrying
/// `[invalid url]` reads as a target rather than as an absence, and the
/// console already has a "target unavailable" state of its own. So an API
/// that omits the field reaches for this one.
///
/// ```
/// use sbproxy_security::url_redact::try_redacted_url;
/// assert_eq!(
///     try_redacted_url("https://hooks.slack.com/services/T0/xoxb-secret"),
///     Some("https://hooks.slack.com".to_string())
/// );
/// assert_eq!(try_redacted_url("hooks.slack.com/services"), None);
/// assert_eq!(try_redacted_url("mailto:ops@example.test"), None);
/// ```
#[must_use]
pub fn try_redacted_url(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    // Only the presence check lives here. The rendering stays in
    // `origin_of`, so the two forms cannot drift into different answers
    // for the same URL.
    url.host_str().filter(|host| !host.is_empty())?;
    Some(origin_of(&url))
}

/// Render `raw` as its origin plus its path, still dropping username,
/// password, query, and fragment.
///
/// Only for DSN-shaped URLs whose path is a structural selector the
/// operator needs in order to act, which in this workspace means the Redis
/// database index in `redis://host:6379/3`.
///
/// Never reach for this on an `http(s)` URL. Slack, Teams, and PagerDuty
/// all put the entire webhook secret in the path, so keeping the path
/// there logs the credential. Use [`redacted_url`] instead.
///
/// ```
/// use sbproxy_security::url_redact::redacted_url_with_path;
/// assert_eq!(
///     redacted_url_with_path("redis://admin:hunter2@cache.internal:6379/3"),
///     "redis://cache.internal:6379/3"
/// );
/// ```
#[must_use]
pub fn redacted_url_with_path(raw: &str) -> String {
    let Ok(url) = Url::parse(raw) else {
        return INVALID.to_string();
    };
    let mut rendered = origin_of(&url);
    match url.path() {
        "" | "/" => {}
        path => rendered.push_str(path),
    }
    rendered
}

/// `scheme://host[:port]`, with the port present only when the URL names
/// one the scheme does not already imply.
///
/// [`Url::port`] returns `None` for a port equal to the scheme's known
/// default, which is what keeps this identical to the ASCII serialization
/// of a tuple origin.
fn origin_of(url: &Url) -> String {
    let host = url.host_str().filter(|h| !h.is_empty()).unwrap_or(NO_HOST);
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_drops_every_credential_carrier() {
        assert_eq!(
            redacted_url("redis://admin:hunter2@cache.internal:6379/0"),
            "redis://cache.internal:6379"
        );
        assert_eq!(
            redacted_url("https://hooks.slack.com/services/T0/B0/xoxb-secret"),
            "https://hooks.slack.com"
        );
    }

    #[test]
    fn no_secret_component_survives_the_rendering() {
        let raw = "https://u-secret:p-secret@guard.test/path-secret?q=q-secret#f-secret";
        let rendered = redacted_url(raw);
        for secret in [
            "u-secret",
            "p-secret",
            "path-secret",
            "q-secret",
            "f-secret",
        ] {
            assert!(!rendered.contains(secret), "{secret} survived: {rendered}");
        }
        assert_eq!(rendered, "https://guard.test");
    }

    /// The alerting runtime's copy built `scheme://host` by hand and lost
    /// the port, so two backends on one host reported as one target.
    #[test]
    fn a_non_default_port_is_kept() {
        assert_eq!(redacted_url("https://h.test:8443/x"), "https://h.test:8443");
        assert_eq!(redacted_url("http://h.test:9000"), "http://h.test:9000");
        assert_eq!(redacted_url("redis://h.test:6380"), "redis://h.test:6380");
    }

    #[test]
    fn a_default_port_is_omitted_exactly_as_the_origin_idiom_does() {
        for raw in [
            "https://h.test/a/b",
            "https://h.test:443/a/b",
            "http://h.test:80/a/b",
            "http://h.test:8080/a/b",
        ] {
            let url = Url::parse(raw).expect("fixture parses");
            assert_eq!(
                redacted_url(raw),
                url.origin().ascii_serialization(),
                "diverged from the origin idiom for {raw}"
            );
        }
    }

    /// [`Url::origin`] is opaque for every scheme the spec does not call
    /// special, and an opaque origin serializes to the literal `"null"`.
    /// Every DSN this workspace handles is in that set, which is why the
    /// MCP action's inline idiom could not simply be lifted as-is.
    #[test]
    fn dsn_schemes_render_a_real_origin_not_null() {
        for raw in [
            "redis://cache.internal:6379/0",
            "rediss://cache.internal:6380/0",
            "s3://bucket/prefix",
            "gs://bucket/prefix",
        ] {
            let url = Url::parse(raw).expect("fixture parses");
            assert_eq!(url.origin().ascii_serialization(), "null");
            assert_ne!(redacted_url(raw), "null", "{raw} rendered as opaque");
        }
        assert_eq!(redacted_url("s3://bucket/prefix/cert-key"), "s3://bucket");
    }

    #[test]
    fn ipv6_hosts_keep_their_brackets() {
        assert_eq!(
            redacted_url("redis://[fd00::1]:6379/0"),
            "redis://[fd00::1]:6379"
        );
        assert_eq!(redacted_url("https://[fd00::1]/path"), "https://[fd00::1]");
    }

    #[test]
    fn unparseable_input_is_never_echoed() {
        for raw in ["", "not a url", "hunter2", "://missing-scheme"] {
            assert_eq!(redacted_url(raw), INVALID, "{raw} was not refused");
            assert_eq!(
                redacted_url_with_path(raw),
                INVALID,
                "{raw} was not refused"
            );
        }
    }

    /// The `try_` form is the one an API document reaches for: a field it
    /// omits is an absence, where `[invalid url]` would render to an
    /// operator as if it were the target.
    #[test]
    fn the_try_form_answers_none_where_the_placeholder_would_render() {
        for raw in [
            "",
            "not a url",
            "hunter2",
            "hooks.example.com/x",
            "mailto:ops@example.test",
            "unix:/var/run/redis.sock",
        ] {
            assert_eq!(try_redacted_url(raw), None, "{raw} rendered a target");
            assert_ne!(redacted_url(raw), "", "{raw} left the log form empty");
        }
    }

    /// Wherever it does answer, it answers exactly what the log form
    /// does. Two renderings of one URL is the drift this module exists
    /// to have ended.
    #[test]
    fn the_try_form_never_diverges_from_the_log_form() {
        for raw in [
            "https://alerts.test:8443/hooks/path-secret",
            "https://alerts.test/hooks/path-secret",
            "http://h.test:80/a/b",
            "redis://admin:hunter2@cache.internal:6379/0",
            "s3://bucket/prefix",
            "https://[fd00::1]:9443/x",
        ] {
            assert_eq!(
                try_redacted_url(raw).as_deref(),
                Some(redacted_url(raw).as_str()),
                "diverged for {raw}"
            );
        }
    }

    #[test]
    fn a_url_without_an_authority_still_names_its_scheme() {
        assert_eq!(redacted_url("unix:/var/run/redis.sock"), "unix://[no host]");
        let socket = "redis+unix:///tmp/redis.sock?password=hunter2";
        assert_eq!(redacted_url(socket), "redis+unix://[no host]");
    }

    /// An unsanitized value at a log site is newline log forging. Parsing
    /// is what stops it here: a newline cannot survive into a host, and
    /// everything after the authority is dropped anyway.
    #[test]
    fn a_newline_cannot_reach_the_rendered_origin() {
        for raw in [
            "https://h.test/a\nlevel=INFO msg=forged",
            "https://h.test/a\r\nlevel=INFO",
            "https://h.test/a?q=\nforged",
        ] {
            let rendered = redacted_url(raw);
            assert!(!rendered.contains('\n'), "newline survived: {rendered:?}");
            assert!(!rendered.contains('\r'), "return survived: {rendered:?}");
        }
        let rendered = redacted_url_with_path("redis://h.test:6379/0\nforged");
        assert!(!rendered.contains('\n'), "newline survived: {rendered:?}");
    }

    #[test]
    fn the_with_path_form_keeps_only_the_path() {
        assert_eq!(
            redacted_url_with_path("redis://admin:hunter2@cache.internal:6379/3"),
            "redis://cache.internal:6379/3"
        );
        // Query and fragment go, same as the origin form.
        assert_eq!(
            redacted_url_with_path("redis://cache.internal:6379/3?x=secret#f"),
            "redis://cache.internal:6379/3"
        );
        // An empty or root path adds nothing, so the two forms agree.
        let bare = "redis://cache.internal:6379";
        assert_eq!(redacted_url_with_path(bare), bare);
        let root = "https://h.test/";
        assert_eq!(redacted_url_with_path(root), redacted_url(root));
    }
}
