//! WOR-892 PR1 step 2/3: OIDC auth provider.
//!
//! Turns sbproxy into an OpenID Connect Relying Party. Unlike the
//! existing `JwtAuth` provider, which only validates a bearer JWT
//! presented by the caller, this provider drives the auth-code +
//! PKCE flow: it redirects an unauthenticated caller to the IdP,
//! exchanges the returned code for an ID token at the token
//! endpoint, validates the ID token (`iss`, `aud`, `exp`, `nonce`),
//! and mints a sealed session cookie. Subsequent requests carry the
//! cookie, the proxy decrypts it, and the caller is treated as
//! authenticated until the session expires.
//!
//! ## Scope of PR1 step 2/3
//!
//! This module ships the *types* + *config* + *session helpers* the
//! auth provider needs. The HTTP wiring (`/oidc/callback` synthetic
//! endpoint, the request-time challenge redirect, the token-endpoint
//! POST against the IdP) lives in `sbproxy-core` and is the subject
//! of step 3/3.
//!
//! Discovery (`.well-known/openid-configuration`) is deliberately
//! NOT scoped here. PR1 takes the IdP endpoints as explicit config
//! fields (`authorization_endpoint`, `token_endpoint`, `jwks_uri`,
//! `issuer`); discovery + cached fetch is a clean additive PR2.
//!
//! Refresh-token rotation, RP-initiated logout, userinfo → trust
//! headers, server-side session store, and DPoP binding are all out
//! of scope for PR1; they are tracked as separate Linear children
//! of WOR-892.

pub mod callback;
pub mod discovery;
pub mod kv_store;
pub mod logout;
pub mod pkce;
pub mod refresh;
pub mod session;
pub mod store;
pub mod userinfo;

use serde::Deserialize;

/// Compiled OIDC auth provider config. Constructed by
/// [`compile_auth`](crate::compile::compile_auth) at config-load
/// time and stored on `Auth::Oidc`. The request-time `check` path
/// (step 3/3) reads these fields without further parsing.
#[derive(Debug, Deserialize)]
pub struct OidcAuth {
    /// IdP `authorization_endpoint`. The proxy redirects
    /// unauthenticated callers here with the configured `client_id`,
    /// the PKCE `code_challenge`, the `state` CSRF token, and the
    /// OIDC `nonce`.
    pub authorization_endpoint: String,
    /// IdP `token_endpoint`. The callback handler POSTs the code +
    /// PKCE verifier here to exchange for an ID token.
    pub token_endpoint: String,
    /// IdP `jwks_uri`. The proxy fetches the IdP's public key set
    /// from here via the existing [`crate::auth::jwks::JwksCache`].
    pub jwks_uri: String,
    /// Expected `iss` value on the ID token. Pinned by config so a
    /// rogue token from a different IdP (even one signed by a key
    /// pulled from `jwks_uri`) is rejected.
    pub issuer: String,
    /// OAuth `client_id` the proxy advertises. Used both as a query
    /// parameter on the auth redirect and as the expected `aud` on
    /// the ID token.
    pub client_id: String,
    /// OAuth `client_secret`. Sent over Basic on the token-endpoint
    /// POST. The secret-resolver pass substitutes `vault://`
    /// references; bare strings work for dev / CI fixtures.
    pub client_secret: String,
    /// Path on the proxy that handles the IdP redirect-back. Default
    /// `/oidc/callback`. Must be one of the URIs registered with the
    /// IdP under `redirect_uris`.
    #[serde(default = "default_redirect_path")]
    pub redirect_path: String,
    /// Path on the proxy that triggers RP-initiated logout. Default
    /// `/oidc/logout`. The handler always deletes the session cookie;
    /// when [`OidcAuth::end_session_endpoint`] is configured the
    /// browser is then 302'd to the OP per OpenID Connect
    /// RP-Initiated Logout 1.0 §2.
    #[serde(default = "default_logout_path")]
    pub logout_path: String,
    /// Optional OP `end_session_endpoint`. When set, the
    /// `/oidc/logout` handler redirects to it (with the session
    /// cookie deleted) so the OP terminates its own session too. When
    /// unset, `/oidc/logout` only deletes the cookie and 302's to
    /// [`OidcAuth::post_logout_redirect_default`] (or `/`).
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// Default URI to send the browser to after a logout completes,
    /// when the caller did not supply (or did not allowlist) one of
    /// their own. Defaults to `/`.
    #[serde(default = "default_post_logout_uri")]
    pub post_logout_redirect_default: String,
    /// Allowlist of permitted `post_logout_redirect_uri` values that
    /// `/oidc/logout` will honour when supplied via the
    /// `post_logout_redirect_uri` query parameter. Without this gate
    /// the endpoint becomes an open-redirect; the resolver in
    /// [`logout::resolve_post_logout_redirect`] enforces verbatim
    /// match before forwarding.
    #[serde(default)]
    pub post_logout_redirect_allowlist: Vec<String>,
    /// Space-separated OIDC scope list sent on the auth redirect.
    /// Defaults to `"openid"` (the minimum that produces an ID
    /// token); operators add `email profile groups` etc. as needed.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Operator-supplied 32+ byte secret used as the HKDF IKM for
    /// the two cookie keys. Same `vault://` substitution as
    /// `client_secret`. Rotating this secret invalidates every
    /// outstanding session and tx cookie, which is the intended
    /// behaviour for a key rotation.
    pub cookie_secret: String,
    /// TTL for the long-lived session cookie, seconds. Default
    /// 3600 (1 hour). PR4 will add server-side sessions; until then
    /// this is the maximum age between IdP round-trips.
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// TTL for the short-lived transaction cookie, seconds. Default
    /// 300 (5 minutes). Should comfortably exceed the operator's
    /// expected time between auth redirect and callback redirect; a
    /// stale tx cookie aborts the login.
    #[serde(default = "default_tx_ttl_secs")]
    pub tx_ttl_secs: u64,
    /// Name of the session cookie. Defaults to `__Host-sbproxy_session`
    /// per [RFC 6265bis] — the `__Host-` prefix forces `Secure` +
    /// `Path=/` + no `Domain`, which closes the cookie-tossing
    /// attack against the session secret.
    #[serde(default = "default_session_cookie_name")]
    pub session_cookie_name: String,
    /// Name of the transaction cookie. Defaults to
    /// `__Host-sbproxy_oidc_tx` for the same reason.
    #[serde(default = "default_tx_cookie_name")]
    pub tx_cookie_name: String,
}

fn default_redirect_path() -> String {
    "/oidc/callback".to_string()
}

fn default_logout_path() -> String {
    "/oidc/logout".to_string()
}

fn default_post_logout_uri() -> String {
    "/".to_string()
}

fn default_scope() -> String {
    "openid".to_string()
}

fn default_session_ttl_secs() -> u64 {
    3600
}

fn default_tx_ttl_secs() -> u64 {
    300
}

fn default_session_cookie_name() -> String {
    "__Host-sbproxy_session".to_string()
}

fn default_tx_cookie_name() -> String {
    "__Host-sbproxy_oidc_tx".to_string()
}

impl OidcAuth {
    /// Compile an [`OidcAuth`] from a generic JSON config value.
    /// Mirrors every other auth provider's `from_config` shape so
    /// the dispatcher in [`crate::compile::compile_auth`] stays
    /// uniform.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let parsed: Self = serde_json::from_value(value)?;
        if parsed.cookie_secret.len() < 32 {
            anyhow::bail!(
                "oidc auth: cookie_secret must be at least 32 bytes (got {})",
                parsed.cookie_secret.len()
            );
        }
        if parsed.client_id.is_empty() {
            anyhow::bail!("oidc auth: client_id is required");
        }
        if parsed.issuer.is_empty() {
            anyhow::bail!("oidc auth: issuer is required");
        }
        if !parsed.authorization_endpoint.starts_with("https://") {
            anyhow::bail!(
                "oidc auth: authorization_endpoint must be https:// (got {:?})",
                parsed.authorization_endpoint
            );
        }
        if !parsed.token_endpoint.starts_with("https://") {
            anyhow::bail!(
                "oidc auth: token_endpoint must be https:// (got {:?})",
                parsed.token_endpoint
            );
        }
        if !parsed.jwks_uri.starts_with("https://") {
            anyhow::bail!(
                "oidc auth: jwks_uri must be https:// (got {:?})",
                parsed.jwks_uri
            );
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_config() -> serde_json::Value {
        serde_json::json!({
            "type": "oidc",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "issuer": "https://idp.example.com",
            "client_id": "sbproxy",
            "client_secret": "super-secret-client-secret-of-arbitrary-length",
            "cookie_secret": "operator-supplied-32-plus-byte-cookie-secret",
        })
    }

    #[test]
    fn from_config_accepts_minimal_input_with_defaults() {
        let cfg = OidcAuth::from_config(good_config()).unwrap();
        assert_eq!(cfg.redirect_path, "/oidc/callback");
        assert_eq!(cfg.logout_path, "/oidc/logout");
        assert_eq!(cfg.scope, "openid");
        assert_eq!(cfg.session_ttl_secs, 3600);
        assert_eq!(cfg.tx_ttl_secs, 300);
        assert_eq!(cfg.session_cookie_name, "__Host-sbproxy_session");
        assert_eq!(cfg.tx_cookie_name, "__Host-sbproxy_oidc_tx");
        assert!(cfg.end_session_endpoint.is_none());
        assert_eq!(cfg.post_logout_redirect_default, "/");
        assert!(cfg.post_logout_redirect_allowlist.is_empty());
    }

    #[test]
    fn from_config_carries_optional_logout_fields() {
        let mut v = good_config();
        v["end_session_endpoint"] = serde_json::json!("https://idp.example.com/logout");
        v["post_logout_redirect_default"] = serde_json::json!("https://app.example.com/goodbye");
        v["post_logout_redirect_allowlist"] = serde_json::json!([
            "https://app.example.com/bye",
            "https://app.example.com/sso/exit"
        ]);
        let cfg = OidcAuth::from_config(v).unwrap();
        assert_eq!(
            cfg.end_session_endpoint.as_deref(),
            Some("https://idp.example.com/logout")
        );
        assert_eq!(
            cfg.post_logout_redirect_default,
            "https://app.example.com/goodbye"
        );
        assert_eq!(cfg.post_logout_redirect_allowlist.len(), 2);
    }

    #[test]
    fn from_config_rejects_short_cookie_secret() {
        let mut v = good_config();
        v["cookie_secret"] = serde_json::json!("too-short");
        let err = OidcAuth::from_config(v).unwrap_err();
        assert!(format!("{err:#}").contains("at least 32 bytes"));
    }

    #[test]
    fn from_config_rejects_http_authorization_endpoint() {
        let mut v = good_config();
        v["authorization_endpoint"] = serde_json::json!("http://idp.example.com/authorize");
        let err = OidcAuth::from_config(v).unwrap_err();
        assert!(format!("{err:#}").contains("must be https"));
    }

    #[test]
    fn from_config_rejects_empty_client_id() {
        let mut v = good_config();
        v["client_id"] = serde_json::json!("");
        let err = OidcAuth::from_config(v).unwrap_err();
        assert!(format!("{err:#}").contains("client_id"));
    }
}
