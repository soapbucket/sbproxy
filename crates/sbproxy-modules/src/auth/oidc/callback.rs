//! WOR-892 PR1 step 2/3: pure helpers for the OIDC `/oidc/callback`
//! handler.
//!
//! Three concerns, all sync, all testable without network I/O:
//!
//! 1. [`build_authorize_redirect_url`] composes the URL the proxy
//!    redirects an unauthenticated caller to. Used at challenge time.
//! 2. [`build_token_exchange_form`] composes the form body the
//!    callback handler POSTs to the IdP's token endpoint. The
//!    actual HTTP call lives in `sbproxy-core` step 3/3.
//! 3. [`validate_id_token_claims`] validates the IdP-returned ID
//!    token's claims (iss, aud, exp, nonce per OIDC Core 1.0
//!    §3.1.3.7). The signature check is the caller's responsibility
//!    so step 3/3 can reuse the existing `JwksCache` from a sibling
//!    `jwt` provider pointed at the same IdP.

use anyhow::{anyhow, Result};
use serde::Deserialize;

use super::OidcAuth;

/// Build the IdP `authorization_endpoint` redirect URL. Includes the
/// PKCE `code_challenge`, the operator-configured `client_id`, the
/// CSRF `state`, the OIDC `nonce`, the OIDC `scope`, the configured
/// `redirect_uri`, and `response_type=code` (the auth-code grant).
pub fn build_authorize_redirect_url(
    cfg: &OidcAuth,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    nonce: &str,
) -> String {
    let params: [(&str, &str); 8] = [
        ("response_type", "code"),
        ("client_id", &cfg.client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &cfg.scope),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];
    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let separator = if cfg.authorization_endpoint.contains('?') {
        "&"
    } else {
        "?"
    };
    format!("{}{separator}{query}", cfg.authorization_endpoint)
}

/// Build the form body for the token-endpoint POST. Per OIDC Core
/// 1.0 §3.1.3.1 the body is `application/x-www-form-urlencoded` with
/// the auth-code grant parameters.
pub fn build_token_exchange_form(
    cfg: &OidcAuth,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> String {
    let params: [(&str, &str); 5] = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &cfg.client_id),
        ("code_verifier", code_verifier),
    ];
    params
        .iter()
        .map(|(k, v)| format!("{}={}", k, percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Validated ID-token claims that the callback handler converts into
/// a [`super::session::SessionClaims`] before sealing into the
/// session cookie.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// `sub` per OIDC Core 1.0 §2.
    pub sub: String,
    /// `iss` per OIDC Core 1.0 §2.
    pub iss: String,
    /// `aud` per OIDC Core 1.0 §2. Can be a single string or an array;
    /// we tolerate both by deserialising into `IdTokenAudience`.
    pub aud: IdTokenAudience,
    /// `exp` per OIDC Core 1.0 §2.
    pub exp: u64,
    /// `iat` per OIDC Core 1.0 §2.
    pub iat: u64,
    /// `nonce` per OIDC Core 1.0 §3.1.3.7 step 11. Required for
    /// auth-code flow; we reject tokens missing it.
    pub nonce: Option<String>,
}

/// OIDC Core 1.0 §2: `aud` can be a single string or an array. Some
/// IdPs use one shape, some the other; tolerate both.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum IdTokenAudience {
    /// Single audience string (most IdPs).
    Single(String),
    /// Audience array (some IdPs emit `[ "client-id" ]`).
    Many(Vec<String>),
}

impl IdTokenAudience {
    /// True when `client_id` appears in this audience claim.
    pub fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::Single(s) => s == client_id,
            Self::Many(v) => v.iter().any(|s| s == client_id),
        }
    }
}

/// Validate an IdP-returned ID token against the configured
/// `expected_iss`, `expected_aud`, and the previously-issued
/// `expected_nonce`. The signature check is the caller's
/// responsibility (it needs a `JwksCache`); this function performs
/// the claim checks per OIDC Core 1.0 §3.1.3.7.
///
/// Returns the validated claims on success; on any check failure
/// returns a generic error so the callback handler responds 401 to
/// the user without leaking the discriminator.
pub fn validate_id_token_claims(
    claims: &IdTokenClaims,
    expected_iss: &str,
    expected_aud: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<()> {
    // §3.1.3.7 step 1-2: iss MUST match.
    if claims.iss != expected_iss {
        return Err(anyhow!(
            "id token iss {:?} does not match expected {:?}",
            claims.iss,
            expected_iss
        ));
    }
    // §3.1.3.7 step 3-4: aud MUST contain the client_id.
    if !claims.aud.contains(expected_aud) {
        return Err(anyhow!(
            "id token aud {:?} does not contain expected aud {:?}",
            claims.aud,
            expected_aud
        ));
    }
    // §3.1.3.7 step 9: current time MUST be before exp.
    if now >= claims.exp {
        return Err(anyhow!(
            "id token expired (exp={} <= now={})",
            claims.exp,
            now
        ));
    }
    // §3.1.3.7 step 11: nonce MUST equal the value we put in the
    // auth request. The callback handler retrieves expected_nonce
    // from the tx cookie. Without this check, an ID token captured
    // from one browser tab can be replayed into another.
    let actual_nonce = claims
        .nonce
        .as_deref()
        .ok_or_else(|| anyhow!("id token missing nonce claim"))?;
    if actual_nonce != expected_nonce {
        return Err(anyhow!(
            "id token nonce {:?} does not match expected {:?}",
            actual_nonce,
            expected_nonce
        ));
    }
    Ok(())
}

/// Percent-encode a value for use in a URL query string. Encodes
/// everything except the unreserved set `[A-Z][a-z][0-9]-._~` per
/// RFC 3986 §2.3.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OidcAuth {
        let value = serde_json::json!({
            "type": "oidc",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "issuer": "https://idp.example.com",
            "client_id": "sbproxy",
            "client_secret": "super-secret-client-secret-of-arbitrary-length",
            "cookie_secret": "operator-supplied-32-plus-byte-cookie-secret",
        });
        OidcAuth::from_config(value).unwrap()
    }

    #[test]
    fn authorize_redirect_carries_every_pkce_parameter() {
        let url = build_authorize_redirect_url(
            &cfg(),
            "https://api.example.com/oidc/callback",
            "challenge-abc",
            "state-xyz",
            "nonce-123",
        );
        assert!(url.starts_with("https://idp.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=sbproxy"));
        assert!(url.contains("code_challenge=challenge-abc"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state-xyz"));
        assert!(url.contains("nonce=nonce-123"));
        // redirect_uri's colons + slashes percent-encode.
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapi.example.com%2Foidc%2Fcallback"));
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn authorize_redirect_uses_amp_separator_when_endpoint_already_has_query() {
        // Some IdPs publish an authorization_endpoint with a fixed
        // query string baked in (e.g. multi-tenant). We MUST use `&`
        // not `?` in that case or the URL becomes malformed.
        let mut c = cfg();
        c.authorization_endpoint = "https://idp.example.com/authorize?tenant=acme".to_string();
        let url = build_authorize_redirect_url(
            &c,
            "https://api.example.com/oidc/callback",
            "x",
            "y",
            "z",
        );
        assert!(url.contains("?tenant=acme&response_type="));
    }

    #[test]
    fn token_exchange_form_uses_authorization_code_grant() {
        let body = build_token_exchange_form(
            &cfg(),
            "https://api.example.com/oidc/callback",
            "code-from-idp",
            "verifier-abc",
        );
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code-from-idp"));
        assert!(body.contains("code_verifier=verifier-abc"));
        assert!(body.contains("client_id=sbproxy"));
        assert!(body.contains("redirect_uri=https%3A%2F%2Fapi.example.com%2Foidc%2Fcallback"));
    }

    fn claims(iss: &str, aud: IdTokenAudience, nonce: Option<&str>, exp: u64) -> IdTokenClaims {
        IdTokenClaims {
            sub: "alice@example.com".to_string(),
            iss: iss.to_string(),
            aud,
            exp,
            iat: 1_700_000_000,
            nonce: nonce.map(String::from),
        }
    }

    #[test]
    fn validate_id_token_accepts_well_formed_token() {
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Single("sbproxy".into()),
            Some("nonce-xyz"),
            1_700_000_999,
        );
        validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "nonce-xyz",
            1_700_000_500,
        )
        .unwrap();
    }

    #[test]
    fn validate_id_token_accepts_aud_array_containing_client_id() {
        // Some IdPs (Auth0 multi-audience configs) emit aud as an
        // array. The validator MUST accept the array shape.
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Many(vec!["other".into(), "sbproxy".into()]),
            Some("n"),
            1_700_000_999,
        );
        validate_id_token_claims(&c, "https://idp.example.com", "sbproxy", "n", 1_700_000_500)
            .unwrap();
    }

    #[test]
    fn validate_id_token_rejects_wrong_iss() {
        let c = claims(
            "https://EVIL.example.com",
            IdTokenAudience::Single("sbproxy".into()),
            Some("n"),
            1_700_000_999,
        );
        assert!(validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "n",
            1_700_000_500
        )
        .is_err());
    }

    #[test]
    fn validate_id_token_rejects_aud_not_containing_client_id() {
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Single("DIFFERENT".into()),
            Some("n"),
            1_700_000_999,
        );
        assert!(validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "n",
            1_700_000_500
        )
        .is_err());
    }

    #[test]
    fn validate_id_token_rejects_expired() {
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Single("sbproxy".into()),
            Some("n"),
            1_700_000_100,
        );
        // now > exp
        assert!(validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "n",
            1_700_000_500
        )
        .is_err());
    }

    #[test]
    fn validate_id_token_rejects_missing_nonce() {
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Single("sbproxy".into()),
            None,
            1_700_000_999,
        );
        assert!(validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "n",
            1_700_000_500
        )
        .is_err());
    }

    #[test]
    fn validate_id_token_rejects_wrong_nonce() {
        // Cross-tab replay defence: token from tab A's auth must not
        // validate against tab B's tx-cookie nonce.
        let c = claims(
            "https://idp.example.com",
            IdTokenAudience::Single("sbproxy".into()),
            Some("nonce-from-tab-A"),
            1_700_000_999,
        );
        assert!(validate_id_token_claims(
            &c,
            "https://idp.example.com",
            "sbproxy",
            "nonce-from-tab-B",
            1_700_000_500
        )
        .is_err());
    }

    #[test]
    fn percent_encode_preserves_unreserved_and_escapes_reserved() {
        assert_eq!(percent_encode("abcABC0-9_.~"), "abcABC0-9_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a/b?c"), "a%2Fb%3Fc");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
    }
}
