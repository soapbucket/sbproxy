//! Newtype wrapper enforcer for the
//! `Policy::Csrf` variant.
//!
//! Lifts the body of the `Policy::Csrf(csrf)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. The CSRF policy is
//! split between two responsibilities:
//!
//! 1. Safe methods (GET / HEAD / OPTIONS by default): mint a fresh
//!    CSRF token, sign it with the configured secret, and stash a
//!    `Set-Cookie` string on `RequestContext::csrf_cookie` so the
//!    response phase can write it on the way out.
//! 2. Protected methods: compare the token in the configured
//!    request header against the value in the matching cookie. A
//!    missing or mismatched token denies the request with `403`.
//!
//! The wrapper consults [`RequestContext::tls_terminated`] (set
//! once per request in the pipeline by PR 1c.0) to decide whether
//! to stamp `; Secure` on the cookie. It cannot reach the live
//! Pingora `Session` from inside the trait `enforce()` body, which
//! is why the slot exists.
//!
//! Per-deny-reason labels:
//!
//! - `"csrf"` for both the token-generation failure (500) and the
//!   token-mismatch (403) deny paths. The policy emits one label
//!   today; if a future split is wanted (e.g. `csrf_token_gen`
//!   vs `csrf_token_mismatch`) this is the only place the label
//!   strings need to change.
//!
//! Behaviour-neutral with the previous enum-arm: the cookie
//! attributes (`Path`, `SameSite`, `Secure`), the header / cookie
//! parsing, and the protected-method semantics are byte-identical.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use sbproxy_modules::policy::CsrfPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};
use tracing::warn;

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`CsrfPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct CsrfEnforcer(pub Arc<CsrfPolicy>);

impl PolicyEnforcer for CsrfEnforcer {
    fn policy_type(&self) -> &'static str {
        "csrf"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let csrf = Arc::clone(&self.0);
        let method = req.method().as_str().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.path().to_string())
            .unwrap_or_else(|| "/".to_string());
        // Snapshot the two header values the wrapper inspects so
        // the future does not borrow `req`.
        let header_token = req
            .headers()
            .get(csrf.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let cookie_header = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Pull the typed RequestContext out of the trait's
        // `&mut dyn Any` carrier. The dispatcher always feeds a
        // RequestContext; if the downcast ever fails the policy
        // fails closed, mirroring the WAF-engine-error fallback in
        // the rest of the chain.
        let downcast: Option<(&mut RequestContext,)> = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => Some((c,)),
            None => None,
        };
        let Some((ctx,)) = downcast else {
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 500,
                    message: "CSRF enforcer: bad context".to_string(),
                })
            });
        };

        // The cookie-stamping path mutates `RequestContext`
        // directly. Snapshot every input we need from the live
        // ctx, then drop the borrow before spawning the future.
        let hostname = ctx.hostname.to_string();
        let tls_terminated = ctx.tls_terminated;

        // Decide right here whether this request is exempt or
        // protected so the future never re-references `csrf`'s
        // owned lists. The two stamp paths return distinct
        // outcomes:
        //   1. Allow + cookie -> set ctx.csrf_cookie = Some(...).
        //   2. Allow (no cookie) -> path is exempt; nothing to do.
        //   3. Deny 403 -> token missing / mismatched.
        //   4. Deny 500 -> token generation failed.
        let exempt = csrf
            .exempt_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()));
        if exempt {
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        }
        let is_protected = csrf.is_protected_method(&method);
        if !is_protected {
            // Safe-method path: generate the token, build the
            // cookie string, stash it on the context for the
            // response phase to drain.
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let token = match csrf_token(csrf.secret_key.as_str(), timestamp, &hostname) {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "csrf: token generation failed");
                    ctx.deny_policy_type = Some("csrf");
                    return Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 500,
                            message: "CSRF token generation failed".to_string(),
                        })
                    });
                }
            };
            let cookie_path = csrf.cookie_path.as_deref().unwrap_or("/");
            let same_site = csrf.cookie_same_site.as_deref().unwrap_or("Lax");
            let mut cookie = format!(
                "{}={}; Path={}; SameSite={}",
                csrf.cookie_name, token, cookie_path, same_site,
            );
            if tls_terminated {
                cookie.push_str("; Secure");
            }
            ctx.csrf_cookie = Some(cookie);
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        }

        // Protected-method path: validate header against cookie.
        let cookie_token = cookie_header
            .split(';')
            .find_map(|c| {
                let c = c.trim();
                let (name, value) = c.split_once('=')?;
                if name.trim() == csrf.cookie_name {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        if header_token.is_empty() || cookie_token.is_empty() || header_token != cookie_token {
            ctx.deny_policy_type = Some("csrf");
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 403,
                    message: "CSRF token missing or invalid".to_string(),
                })
            });
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

/// Compute the HMAC-SHA256 CSRF token for the configured secret /
/// timestamp / hostname triple. Hex-encoded so the value drops
/// directly into a Set-Cookie body. Forging a token requires
/// knowledge of `secret`, which never leaves the process.
fn csrf_token(secret: &str, timestamp: u128, hostname: &str) -> Result<String> {
    use hmac::{KeyInit, Mac, SimpleHmac};
    use sha2::Sha256;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("csrf hmac init failed: {e}"))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(hostname.as_bytes());
    let bytes = mac.finalize().into_bytes();
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_stable_for_same_inputs() {
        let t1 = csrf_token("secret", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        let t2 = csrf_token("secret", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        assert_eq!(t1, t2);
        // SHA-256 hex output is 64 chars.
        assert_eq!(t1.len(), 64);
        // Different secret -> different token.
        let t3 = csrf_token("other", 1_700_000_000_000_000_000u128, "example.com").unwrap();
        assert_ne!(t1, t3);
        // Different hostname -> different token (binds to host).
        let t4 = csrf_token("secret", 1_700_000_000_000_000_000u128, "other.com").unwrap();
        assert_ne!(t1, t4);
    }
}
