//! WOR-892 follow-up: OIDC refresh-token rotation.
//!
//! When the proxy's session cookie nears expiry it should NOT force
//! the user back to the OP for another interactive login if the IdP
//! handed out a refresh token at original-login time. RFC 6749 §6
//! says the relying party can POST the refresh token to the token
//! endpoint and receive a new access token (and, for OPs that
//! implement refresh-token rotation per OAuth 2.1 §4.3.1, a new
//! refresh token as well).
//!
//! Two concerns ship here, both sync + pure:
//!
//! 1. [`build_refresh_token_form`] composes the
//!    `application/x-www-form-urlencoded` body the proxy POSTs to
//!    `token_endpoint` to refresh the access token.
//! 2. [`should_refresh_now`] decides — given the current time, the
//!    access-token expiry, and a configurable safety skew — whether
//!    the proxy should fire a refresh before serving the next request
//!    or wait until the next one. Done as a free function so the
//!    request-time hot path has a single, branchless call rather
//!    than reading wall-clock + cookie state in three places.
//! 3. [`parse_refresh_token_response`] reads the OP's token-endpoint
//!    JSON response into a typed struct, falling back to the OP's
//!    rotation semantics: an OP that does NOT rotate refresh tokens
//!    will omit `refresh_token` from the response and the caller
//!    keeps using the original.
//!
//! What deliberately does NOT ship: the HTTP POST itself, and the
//! cookie-mint logic that takes the response and seals a fresh
//! session cookie. Both touch `sbproxy-core`; the pure helpers and
//! the security checks are pinned here.

use anyhow::{anyhow, Result};
use serde::Deserialize;

use super::OidcAuth;

/// Compose the form body for the refresh-token POST per RFC 6749 §6.
/// The body is `application/x-www-form-urlencoded` and carries
/// `grant_type=refresh_token` + the refresh token + the client_id.
/// `client_secret` (if the OP requires it) is sent via the
/// `Authorization: Basic` header, NOT in the body, so it does not
/// appear in proxy logs that capture form bodies; this mirrors the
/// auth-code exchange flow's behaviour.
pub fn build_refresh_token_form(cfg: &OidcAuth, refresh_token: &str) -> String {
    let params: [(&str, &str); 3] = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &cfg.client_id),
    ];
    params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Decide whether a refresh should be triggered now.
///
/// `now` and `access_token_exp` are unix-seconds; `skew_secs` is how
/// far before expiry to start refreshing (operator-tunable, defaults
/// to 60 seconds at the callsite).
///
/// Behaviour:
///
/// * Already-expired access token: returns `true`. The proxy should
///   refresh before serving the next request, otherwise the next
///   upstream call lands with a token the origin will reject.
/// * Within `skew_secs` of expiry: returns `true`. Refreshing
///   slightly early avoids a race with in-flight requests sitting in
///   the upstream's queue.
/// * Comfortably in the future: returns `false`. No refresh needed.
///
/// The function is intentionally branch-light so it can sit on the
/// per-request hot path without measurable cost.
pub fn should_refresh_now(now: u64, access_token_exp: u64, skew_secs: u64) -> bool {
    let safety_window = access_token_exp.saturating_sub(skew_secs);
    now >= safety_window
}

/// Subset of RFC 6749 §5.1 token-endpoint response that the proxy
/// needs after a refresh. `expires_in` is OPTIONAL per the RFC; when
/// omitted the OP is implying the access token has no fixed expiry
/// (a long-lived opaque token), in which case the caller should use
/// the configured `session_ttl_secs` instead.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenResponse {
    /// Fresh access token. REQUIRED per RFC 6749 §5.1.
    pub access_token: String,
    /// Refresh token. Per OAuth 2.1 §4.3.1 the OP MAY rotate refresh
    /// tokens (issuing a new one and revoking the old) or MAY NOT
    /// (returning the same token effectively, or omitting the field
    /// to signal "reuse the original"). When `None`, the caller
    /// keeps using the original refresh token.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Token type. Per RFC 6749 §7.1 this is canonically `Bearer`;
    /// captured for forward compat with DPoP / mTLS-bound tokens.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Access-token lifetime in seconds. OPTIONAL per RFC 6749 §5.1.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// ID token, when the OP chooses to re-issue one. Most do.
    /// Optional because the spec does not require it on refresh.
    #[serde(default)]
    pub id_token: Option<String>,
    /// Granted scope, comma-separated, when the OP chose to narrow
    /// the original grant.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Parse a token-endpoint refresh response into the typed struct.
/// Wraps the serde error so operator logs include the field that
/// failed; a missing `access_token` is the most common shape error
/// (an OP that 200s an error body), so it is called out by name.
pub fn parse_refresh_token_response(body: &str) -> Result<RefreshTokenResponse> {
    serde_json::from_str::<RefreshTokenResponse>(body)
        .map_err(|e| anyhow!("oidc refresh: failed to parse token-endpoint response: {e}"))
        .and_then(|r| {
            if r.access_token.is_empty() {
                Err(anyhow!(
                    "oidc refresh: response missing required `access_token`"
                ))
            } else {
                Ok(r)
            }
        })
}

/// Decide which refresh token the proxy will use going forward after
/// a successful refresh. If the OP rotated (returned a fresh value),
/// use the fresh one; otherwise keep the original. Pulled into its
/// own function so the cookie-mint call site does not duplicate the
/// "OP did vs did not rotate" branch.
pub fn pick_next_refresh_token<'a>(
    original: &'a str,
    response: &'a RefreshTokenResponse,
) -> &'a str {
    response.refresh_token.as_deref().unwrap_or(original)
}

/// Minimal RFC 3986-friendly percent-encoder for form-body values.
/// Encodes everything outside the unreserved set. Mirrors the
/// `callback` + `logout` encoders so the three flows behave
/// identically on edge characters.
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
    fn refresh_form_includes_grant_type_token_and_client_id() {
        let body = build_refresh_token_form(&cfg(), "rt-value-42");
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=rt-value-42"));
        assert!(body.contains("client_id=sbproxy"));
    }

    #[test]
    fn refresh_form_omits_client_secret_so_logs_stay_clean() {
        // client_secret travels via Authorization: Basic, NOT body.
        // The auth-code exchange enforces the same invariant.
        let body = build_refresh_token_form(&cfg(), "rt-value");
        assert!(!body.contains("super-secret-client-secret"));
        assert!(!body.contains("client_secret"));
    }

    #[test]
    fn refresh_form_percent_encodes_unsafe_token_chars() {
        let body = build_refresh_token_form(&cfg(), "rt with spaces+and/slashes");
        assert!(body.contains("refresh_token=rt%20with%20spaces%2Band%2Fslashes"));
    }

    #[test]
    fn should_refresh_when_token_already_expired() {
        assert!(should_refresh_now(1_700_000_100, 1_700_000_000, 60));
    }

    #[test]
    fn should_refresh_when_within_safety_skew() {
        assert!(should_refresh_now(1_700_000_000, 1_700_000_030, 60));
    }

    #[test]
    fn should_not_refresh_when_comfortably_in_future() {
        assert!(!should_refresh_now(1_700_000_000, 1_700_000_600, 60));
    }

    #[test]
    fn should_refresh_boundary_exactly_at_safety_window_is_refresh() {
        // expiry - skew == now → trigger refresh (>= boundary).
        // Refreshing slightly early is safer than slightly late.
        assert!(should_refresh_now(1_700_000_000, 1_700_000_060, 60));
    }

    #[test]
    fn should_refresh_handles_skew_larger_than_expiry_without_panic() {
        // Pathological: skew > expiry would underflow without saturating_sub.
        assert!(should_refresh_now(0, 30, 60));
    }

    #[test]
    fn parse_extracts_all_optional_fields() {
        let body = r#"{
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "new-id-token",
            "scope": "openid email"
        }"#;
        let r = parse_refresh_token_response(body).unwrap();
        assert_eq!(r.access_token, "new-access-token");
        assert_eq!(r.refresh_token.as_deref(), Some("new-refresh-token"));
        assert_eq!(r.expires_in, Some(3600));
        assert_eq!(r.id_token.as_deref(), Some("new-id-token"));
        assert_eq!(r.scope.as_deref(), Some("openid email"));
    }

    #[test]
    fn parse_tolerates_op_without_rotation_omitting_refresh_token() {
        let body = r#"{
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;
        let r = parse_refresh_token_response(body).unwrap();
        assert_eq!(r.access_token, "new-access-token");
        assert!(r.refresh_token.is_none());
    }

    #[test]
    fn parse_rejects_response_missing_access_token() {
        let body = r#"{ "token_type": "Bearer" }"#;
        let err = parse_refresh_token_response(body).unwrap_err();
        // serde signals the missing field before the empty-string check,
        // so accept either signal so long as `access_token` is named.
        assert!(format!("{err:#}").contains("access_token"));
    }

    #[test]
    fn parse_rejects_response_with_empty_access_token_string() {
        let body = r#"{ "access_token": "" }"#;
        let err = parse_refresh_token_response(body).unwrap_err();
        assert!(format!("{err:#}").contains("missing required `access_token`"));
    }

    #[test]
    fn parse_reports_parser_error_for_malformed_json() {
        let err = parse_refresh_token_response("not json").unwrap_err();
        assert!(format!("{err:#}").contains("failed to parse"));
    }

    #[test]
    fn pick_next_refresh_token_returns_rotated_when_op_rotates() {
        let r = RefreshTokenResponse {
            access_token: "a".into(),
            refresh_token: Some("rt-NEW".into()),
            token_type: None,
            expires_in: None,
            id_token: None,
            scope: None,
        };
        assert_eq!(pick_next_refresh_token("rt-OLD", &r), "rt-NEW");
    }

    #[test]
    fn pick_next_refresh_token_falls_back_to_original_when_op_does_not_rotate() {
        let r = RefreshTokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            token_type: None,
            expires_in: None,
            id_token: None,
            scope: None,
        };
        assert_eq!(pick_next_refresh_token("rt-OLD", &r), "rt-OLD");
    }
}
