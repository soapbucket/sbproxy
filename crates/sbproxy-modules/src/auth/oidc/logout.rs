//! WOR-892 follow-up: OIDC RP-initiated logout.
//!
//! When the user clicks "sign out" in the application, two things
//! must happen:
//!
//! 1. The proxy's sealed session cookie has to disappear from the
//!    browser. Setting the same cookie with `Max-Age=0` is the
//!    canonical way; the next request will not match the session.
//! 2. The OP's own session has to end. Otherwise hitting "log in"
//!    again silently re-establishes the same identity without the
//!    user ever seeing an IdP prompt, which is the wrong UX (and
//!    the wrong audit trail) for "log out". OpenID Connect
//!    RP-Initiated Logout 1.0 §2 defines the standard way: redirect
//!    the user-agent to the OP's `end_session_endpoint` carrying an
//!    `id_token_hint`, an optional `post_logout_redirect_uri`, and
//!    an optional opaque `state` for CSRF binding.
//!
//! This module ships the pure helpers; the HTTP wiring (recognise
//! `/oidc/logout` on the request path, look up the active session,
//! emit the cookie-deletion `Set-Cookie` and the 302 to the OP)
//! lives in `sbproxy-core` and is the next step.
//!
//! Three helpers, all sync, all unit-testable:
//!
//! 1. [`build_end_session_redirect_url`] composes the redirect URL
//!    to the OP per §2.
//! 2. [`build_session_deletion_cookie`] composes the `Set-Cookie`
//!    value that expires the proxy's own session cookie.
//! 3. [`resolve_post_logout_redirect`] decides which
//!    `post_logout_redirect_uri` the proxy should send: an
//!    operator-allowed URI if supplied by the caller, otherwise the
//!    fallback configured by the operator, otherwise nothing.

use super::OidcAuth;

/// Compose the redirect URL to the OP's `end_session_endpoint` per
/// OpenID Connect RP-Initiated Logout 1.0 §2. `id_token_hint` is
/// REQUIRED for the OP to identify which session to end without an
/// interactive prompt. `post_logout_redirect_uri`, if supplied, is
/// where the OP will bounce the user back to after the OP-side
/// logout completes; the OP will only honour it if the URI is
/// pre-registered. `state` is an opaque CSRF token round-tripped
/// back on that final bounce.
///
/// Returns `None` when the IdP did not advertise an
/// `end_session_endpoint` (the field is OPTIONAL in OIDC discovery).
/// The caller should fall back to a pure cookie-deletion logout in
/// that case.
pub fn build_end_session_redirect_url(
    end_session_endpoint: Option<&str>,
    id_token_hint: &str,
    post_logout_redirect_uri: Option<&str>,
    state: Option<&str>,
) -> Option<String> {
    let endpoint = end_session_endpoint?;
    let mut params: Vec<(&'static str, &str)> = Vec::with_capacity(3);
    params.push(("id_token_hint", id_token_hint));
    if let Some(uri) = post_logout_redirect_uri {
        params.push(("post_logout_redirect_uri", uri));
    }
    if let Some(s) = state {
        params.push(("state", s));
    }
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let separator = if endpoint.contains('?') { "&" } else { "?" };
    Some(format!("{endpoint}{separator}{query}"))
}

/// Compose the `Set-Cookie` value that expires the session cookie on
/// the user-agent. Uses `Max-Age=0` plus a `Path=/` matching the
/// original; `Secure` + `HttpOnly` + `SameSite=Lax` mirror the live
/// cookie's attributes so an interception/downgrade attack cannot
/// race a stale cookie back in.
pub fn build_session_deletion_cookie(cfg: &OidcAuth) -> String {
    format!(
        "{}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        cfg.session_cookie_name
    )
}

/// Decide which `post_logout_redirect_uri` to send to the OP.
///
/// * If the caller passed an explicit `requested_uri` AND it appears
///   verbatim in `allowed_uris`, use it. Anything else is rejected:
///   blindly forwarding a caller-supplied redirect URL is an open
///   redirect waiting to be weaponised in a phishing chain.
/// * Otherwise return `default_uri` (operator-configured).
/// * If neither resolves, return `None`. The caller should then
///   redirect to the OP with NO `post_logout_redirect_uri`, which
///   leaves the user on the OP's own logout-complete page.
pub fn resolve_post_logout_redirect<'a>(
    requested_uri: Option<&'a str>,
    allowed_uris: &'a [String],
    default_uri: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(req) = requested_uri {
        if allowed_uris.iter().any(|allowed| allowed == req) {
            return Some(req);
        }
    }
    default_uri
}

/// Minimal RFC 3986-friendly percent-encoder for query-string
/// values. Encodes everything outside the unreserved set; matches
/// what the `callback` module uses for the same reason.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        let unreserved =
            b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OidcAuth {
        OidcAuth::from_config(serde_json::json!({
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "issuer": "https://idp.example.com",
            "client_id": "sbproxy",
            "client_secret": "super-secret-client-secret",
            "cookie_secret": "operator-supplied-32-plus-byte-cookie-secret",
        }))
        .unwrap()
    }

    #[test]
    fn end_session_url_returns_none_when_endpoint_absent() {
        let url = build_end_session_redirect_url(None, "id-token", None, None);
        assert!(url.is_none());
    }

    #[test]
    fn end_session_url_includes_required_id_token_hint() {
        let url = build_end_session_redirect_url(
            Some("https://idp.example.com/logout"),
            "id-token-value",
            None,
            None,
        )
        .unwrap();
        assert!(url.starts_with("https://idp.example.com/logout?"));
        assert!(url.contains("id_token_hint=id-token-value"));
    }

    #[test]
    fn end_session_url_includes_post_logout_redirect_uri() {
        let url = build_end_session_redirect_url(
            Some("https://idp.example.com/logout"),
            "id-token",
            Some("https://app.example.com/bye"),
            None,
        )
        .unwrap();
        assert!(url.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fbye"));
    }

    #[test]
    fn end_session_url_includes_state_when_supplied() {
        let url = build_end_session_redirect_url(
            Some("https://idp.example.com/logout"),
            "id-token",
            None,
            Some("csrf-token-42"),
        )
        .unwrap();
        assert!(url.contains("state=csrf-token-42"));
    }

    #[test]
    fn end_session_url_uses_ampersand_when_endpoint_already_has_query() {
        let url = build_end_session_redirect_url(
            Some("https://idp.example.com/logout?tenant=acme"),
            "id-token",
            None,
            None,
        )
        .unwrap();
        assert!(url.contains("?tenant=acme&id_token_hint=id-token"));
        assert!(!url.contains("?tenant=acme?id_token_hint"));
    }

    #[test]
    fn deletion_cookie_uses_configured_session_name() {
        let mut config = cfg();
        config.session_cookie_name = "__Host-mysession".into();
        let header = build_session_deletion_cookie(&config);
        assert!(header.starts_with("__Host-mysession="));
        assert!(header.contains("Max-Age=0"));
        assert!(header.contains("Secure"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn resolve_returns_requested_when_allowlisted() {
        let allowed = vec!["https://app.example.com/bye".to_string()];
        let resolved = resolve_post_logout_redirect(
            Some("https://app.example.com/bye"),
            &allowed,
            Some("https://app.example.com/default"),
        );
        assert_eq!(resolved, Some("https://app.example.com/bye"));
    }

    #[test]
    fn resolve_falls_back_to_default_when_requested_not_allowlisted() {
        let allowed = vec!["https://app.example.com/bye".to_string()];
        let resolved = resolve_post_logout_redirect(
            Some("https://attacker.example.com/phish"),
            &allowed,
            Some("https://app.example.com/default"),
        );
        assert_eq!(resolved, Some("https://app.example.com/default"));
    }

    #[test]
    fn resolve_returns_default_when_no_requested() {
        let allowed: Vec<String> = vec![];
        let resolved =
            resolve_post_logout_redirect(None, &allowed, Some("https://app.example.com/default"));
        assert_eq!(resolved, Some("https://app.example.com/default"));
    }

    #[test]
    fn resolve_returns_none_when_neither_resolvable() {
        let allowed: Vec<String> = vec![];
        let resolved = resolve_post_logout_redirect(
            Some("https://attacker.example.com/phish"),
            &allowed,
            None,
        );
        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_rejects_close_match_against_allowlist() {
        // Substring / prefix / suffix attacks should NOT pass.
        let allowed = vec!["https://app.example.com/bye".to_string()];
        let resolved = resolve_post_logout_redirect(
            Some("https://app.example.com/bye/../redirect"),
            &allowed,
            None,
        );
        assert_eq!(resolved, None);
    }
}
