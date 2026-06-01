//! WOR-892 follow-up: OIDC userinfo → upstream trust headers.
//!
//! After the callback handler successfully exchanges the auth code
//! for an access token + ID token, sbproxy can call the IdP's
//! UserInfo Endpoint (OIDC Core 1.0 §5.3) to fetch claims that are
//! NOT in the ID token (verified email, groups, preferred_username,
//! tenant-specific fields). The proxy then projects a small,
//! well-known subset of those claims into `X-Auth-*` headers on the
//! upstream request so the origin sees a single, sanitised auth view
//! that does not need to parse the IdP's JWT.
//!
//! Three small pieces ship here, all sync, all unit-testable without
//! network I/O. The HTTP call against the OP is the caller's job
//! (same pattern as `discovery::DiscoveryCache::get_or_fetch`); this
//! module stays off the `reqwest` graph.
//!
//! 1. [`UserInfoClaims`] — typed subset of the userinfo JSON.
//! 2. [`parse_userinfo`] — JSON → claims with operator-friendly
//!    error wrapping.
//! 3. [`build_userinfo_authorization_header`] — assembles the
//!    `Authorization: Bearer …` value the caller sends to the OP.
//! 4. [`trust_headers_from_claims`] — maps validated claims into a
//!    `Vec<(name, value)>` ready to be set on the upstream request.
//!
//! ### Header naming
//!
//! The proxy emits standard `X-Auth-*` headers, NOT IdP-specific
//! ones. This matches what `oauth2-proxy`, `traefik-forward-auth`,
//! and the cookie-paved origin world already expect:
//!
//! | Header              | Source claim          |
//! |---------------------|-----------------------|
//! | `X-Auth-Subject`    | `sub` (required)      |
//! | `X-Auth-Email`      | `email` (when present and `email_verified` is true) |
//! | `X-Auth-User`       | `preferred_username` or `name` (first present) |
//! | `X-Auth-Groups`     | `groups`, comma-joined |
//!
//! The verified-email check is deliberate: an unverified email is
//! attacker-controlled at the IdP for most enterprise OPs (Google
//! Workspace's "I claim this email" flow, Okta's "self-registration"
//! template). Treating it as an identity is a known privilege-
//! escalation foothold; sbproxy will not project it.

use anyhow::{anyhow, Result};
use serde::Deserialize;

/// Subset of OIDC Core 1.0 §5.3.2 userinfo claims that sbproxy reads
/// when projecting trust headers. Anything else in the response is
/// tolerated and ignored.
///
/// All fields except `sub` are optional because the OP is free to
/// release exactly the claims the requested scopes allowed. An origin
/// configured to trust only `X-Auth-Subject` will work even against
/// an OP that only releases `sub`.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct UserInfoClaims {
    /// REQUIRED per OIDC Core 1.0 §5.3.2. The Subject identifier for
    /// the End-User at the IdP. Stable per (issuer, audience).
    pub sub: String,
    /// End-User's preferred email address.
    #[serde(default)]
    pub email: Option<String>,
    /// True if the End-User's email has been verified by the OP.
    /// Unverified emails are NOT projected to `X-Auth-Email`.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// End-User's full name.
    #[serde(default)]
    pub name: Option<String>,
    /// Shorthand name that the End-User wishes to be referred to.
    /// Preferred over `name` when projecting `X-Auth-User`.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Group memberships. Not part of OIDC Core but emitted by every
    /// enterprise OP (Okta, Auth0, Azure AD, Keycloak); we accept it
    /// here so the trust-header projection has a uniform place to read.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Compose the `Authorization` header value the caller sends to the
/// OP's userinfo endpoint. Per OIDC Core 1.0 §5.3.1 the call is a
/// GET with `Authorization: Bearer <access_token>`.
pub fn build_userinfo_authorization_header(access_token: &str) -> String {
    format!("Bearer {access_token}")
}

/// Parse a userinfo JSON response body. Wraps the serde error so
/// operator logs include the field that failed rather than a raw
/// `serde_json` path that points at internal column offsets.
pub fn parse_userinfo(body: &str) -> Result<UserInfoClaims> {
    serde_json::from_str::<UserInfoClaims>(body)
        .map_err(|e| anyhow!("oidc userinfo: failed to parse response: {e}"))
        .and_then(|c| {
            if c.sub.is_empty() {
                Err(anyhow!("oidc userinfo: response missing required `sub`"))
            } else {
                Ok(c)
            }
        })
}

/// Map validated userinfo claims to the upstream trust-header pairs.
/// Returns `(header_name, value)` tuples in a deterministic order so
/// callsites that hash or log the projection get stable output.
///
/// Rules:
///
/// * `X-Auth-Subject` always emitted (parser already enforced
///   non-empty `sub`).
/// * `X-Auth-Email` emitted ONLY when both `email` is present AND
///   `email_verified == Some(true)`. Missing or false verification
///   suppresses the header; see the module docs for why.
/// * `X-Auth-User` emitted when `preferred_username` is present,
///   else when `name` is present, else suppressed.
/// * `X-Auth-Groups` emitted when `groups` is non-empty, value is
///   comma-joined (no spaces).
pub fn trust_headers_from_claims(claims: &UserInfoClaims) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::with_capacity(4);
    out.push(("X-Auth-Subject", claims.sub.clone()));
    if let Some(email) = claims.email.as_deref() {
        if claims.email_verified == Some(true) {
            out.push(("X-Auth-Email", email.to_string()));
        }
    }
    if let Some(user) = claims
        .preferred_username
        .as_deref()
        .or(claims.name.as_deref())
    {
        out.push(("X-Auth-User", user.to_string()));
    }
    if !claims.groups.is_empty() {
        out.push(("X-Auth-Groups", claims.groups.join(",")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_userinfo() -> &'static str {
        r#"{
            "sub": "user-42",
            "email": "alice@example.com",
            "email_verified": true,
            "name": "Alice Example",
            "preferred_username": "alice",
            "groups": ["eng", "platform"]
        }"#
    }

    #[test]
    fn bearer_header_uses_access_token_unmodified() {
        assert_eq!(
            build_userinfo_authorization_header("opaque-access-token"),
            "Bearer opaque-access-token"
        );
    }

    #[test]
    fn parse_extracts_required_and_optional_fields() {
        let claims = parse_userinfo(full_userinfo()).unwrap();
        assert_eq!(claims.sub, "user-42");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
        assert_eq!(claims.groups, vec!["eng", "platform"]);
    }

    #[test]
    fn parse_tolerates_missing_optional_fields() {
        let claims = parse_userinfo(r#"{"sub":"user-42"}"#).unwrap();
        assert_eq!(claims.sub, "user-42");
        assert!(claims.email.is_none());
        assert!(claims.groups.is_empty());
    }

    #[test]
    fn parse_tolerates_unknown_op_specific_fields() {
        let body = r#"{
            "sub": "user-42",
            "tenant_id": "acme",
            "okta_user_type": "platinum",
            "custom_attribute": [1, 2, 3]
        }"#;
        let claims = parse_userinfo(body).unwrap();
        assert_eq!(claims.sub, "user-42");
    }

    #[test]
    fn parse_rejects_missing_sub() {
        let err = parse_userinfo(r#"{"email":"alice@example.com"}"#).unwrap_err();
        let msg = format!("{err:#}");
        // serde flags missing required field before our explicit empty-string check;
        // either signal is acceptable so long as the message names `sub`.
        assert!(
            msg.contains("missing required `sub`") || msg.contains("sub"),
            "expected sub-related error, got: {msg}"
        );
    }

    #[test]
    fn parse_rejects_empty_sub_string() {
        let err = parse_userinfo(r#"{"sub":""}"#).unwrap_err();
        assert!(format!("{err:#}").contains("missing required `sub`"));
    }

    #[test]
    fn parse_reports_parser_error_for_malformed_json() {
        let err = parse_userinfo("not json").unwrap_err();
        assert!(format!("{err:#}").contains("failed to parse"));
    }

    #[test]
    fn trust_headers_emit_subject_always() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert_eq!(headers, vec![("X-Auth-Subject", "user-42".to_string())]);
    }

    #[test]
    fn trust_headers_suppress_unverified_email() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            email: Some("alice@example.com".into()),
            email_verified: Some(false),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(!headers.iter().any(|(k, _)| *k == "X-Auth-Email"));
    }

    #[test]
    fn trust_headers_suppress_email_when_verification_absent() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            email: Some("alice@example.com".into()),
            email_verified: None,
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(!headers.iter().any(|(k, _)| *k == "X-Auth-Email"));
    }

    #[test]
    fn trust_headers_emit_verified_email() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            email: Some("alice@example.com".into()),
            email_verified: Some(true),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(headers.contains(&("X-Auth-Email", "alice@example.com".to_string())));
    }

    #[test]
    fn trust_headers_prefer_preferred_username_over_name() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            name: Some("Alice Example".into()),
            preferred_username: Some("alice".into()),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(headers.contains(&("X-Auth-User", "alice".to_string())));
        assert!(!headers
            .iter()
            .any(|(k, v)| *k == "X-Auth-User" && v == "Alice Example"));
    }

    #[test]
    fn trust_headers_fall_back_to_name_when_preferred_username_absent() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            name: Some("Alice Example".into()),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(headers.contains(&("X-Auth-User", "Alice Example".to_string())));
    }

    #[test]
    fn trust_headers_comma_join_groups() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            groups: vec!["eng".into(), "platform".into(), "oncall".into()],
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(headers.contains(&("X-Auth-Groups", "eng,platform,oncall".to_string())));
    }

    #[test]
    fn trust_headers_omit_groups_when_empty() {
        let claims = UserInfoClaims {
            sub: "user-42".into(),
            ..Default::default()
        };
        let headers = trust_headers_from_claims(&claims);
        assert!(!headers.iter().any(|(k, _)| *k == "X-Auth-Groups"));
    }

    #[test]
    fn trust_headers_full_projection_preserves_deterministic_order() {
        let claims = parse_userinfo(full_userinfo()).unwrap();
        let headers = trust_headers_from_claims(&claims);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                "X-Auth-Subject",
                "X-Auth-Email",
                "X-Auth-User",
                "X-Auth-Groups"
            ]
        );
    }
}
