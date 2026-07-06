// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Admin browser sessions + operator identity (WOR-1714 / WOR-1716).
//!
//! The admin API accepts HTTP Basic (for CI and the top-level admin) and,
//! for a browser UI, a signed session cookie. `POST /admin/login` verifies
//! credentials and mints a token; the token is an HMAC-signed
//! `username | role | expiry | nonce`, so it is stateless (no server-side
//! session table) apart from a small revocation set for logout. The
//! signing key is ephemeral (random per process): a restart invalidates
//! all sessions, which is the safe default for an admin surface.
//!
//! CSRF: the token rides an `HttpOnly` cookie the browser cannot read,
//! and login also returns the nonce as a CSRF token. A state-changing
//! request must echo it in `X-CSRF-Token`; since a cross-site attacker
//! cannot read the `HttpOnly` cookie's nonce, it cannot forge the header
//! (double-submit).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sbproxy_config::types::AdminRole;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Name of the admin session cookie.
pub const SESSION_COOKIE: &str = "sb_admin_session";

/// A verified admin session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The operator who logged in.
    pub username: String,
    /// The operator's role.
    pub role: AdminRole,
    /// Random per-session id, also the CSRF token.
    pub nonce: String,
    /// Unix expiry (seconds).
    pub expiry: u64,
}

/// Ephemeral HMAC signer for session tokens (random key per process).
#[derive(Debug)]
pub struct SessionSigner {
    key: [u8; 32],
}

impl SessionSigner {
    /// A signer with a fresh random key. Sessions do not survive a restart.
    pub fn random() -> Self {
        Self {
            key: rand::random(),
        }
    }

    /// Mint a token for `username`/`role` valid for `ttl_secs` from `now`.
    /// Returns `(token, nonce)`; the nonce doubles as the CSRF token.
    pub fn mint(
        &self,
        username: &str,
        role: AdminRole,
        ttl_secs: u64,
        now: u64,
    ) -> (String, String) {
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = hex::encode(nonce_bytes);
        let expiry = now + ttl_secs;
        let payload = format!(
            "{}|{}|{}|{}",
            B64.encode(username.as_bytes()),
            role_str(role),
            expiry,
            nonce
        );
        let e = B64.encode(payload.as_bytes());
        let mac = self.mac(e.as_bytes());
        let token = format!("{e}.{}", B64.encode(mac));
        (token, nonce)
    }

    /// Verify a token: signature, structure, and expiry. Revocation is
    /// checked by the caller against its own set. Returns the session on
    /// success.
    pub fn verify(&self, token: &str, now: u64) -> Option<Session> {
        let (e, sig) = token.split_once('.')?;
        let expected = self.mac(e.as_bytes());
        let got = B64.decode(sig).ok()?;
        if !ct_eq(&expected, &got) {
            return None;
        }
        let payload = String::from_utf8(B64.decode(e).ok()?).ok()?;
        let mut parts = payload.split('|');
        let username = String::from_utf8(B64.decode(parts.next()?).ok()?).ok()?;
        let role = role_from_str(parts.next()?)?;
        let expiry: u64 = parts.next()?.parse().ok()?;
        let nonce = parts.next()?.to_string();
        if parts.next().is_some() || expiry <= now {
            return None;
        }
        Some(Session {
            username,
            role,
            nonce,
            expiry,
        })
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

/// Extract a named cookie value from a `Cookie:` header line.
pub fn cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn role_str(role: AdminRole) -> &'static str {
    match role {
        AdminRole::Admin => "admin",
        AdminRole::ReadOnly => "read_only",
    }
}

fn role_from_str(s: &str) -> Option<AdminRole> {
    match s {
        "admin" => Some(AdminRole::Admin),
        "read_only" => Some(AdminRole::ReadOnly),
        _ => None,
    }
}

/// Constant-time byte-slice equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_verify_roundtrips() {
        let s = SessionSigner::random();
        let (token, nonce) = s.mint("alice", AdminRole::Admin, 3600, 1000);
        let sess = s.verify(&token, 1000).expect("valid");
        assert_eq!(sess.username, "alice");
        assert_eq!(sess.role, AdminRole::Admin);
        assert_eq!(sess.nonce, nonce);
        assert_eq!(sess.expiry, 4600);
    }

    #[test]
    fn expired_token_rejected() {
        let s = SessionSigner::random();
        let (token, _) = s.mint("bob", AdminRole::ReadOnly, 10, 1000);
        assert!(s.verify(&token, 1005).is_some());
        assert!(s.verify(&token, 2000).is_none(), "past expiry");
    }

    #[test]
    fn tampered_token_rejected() {
        let s = SessionSigner::random();
        let (token, _) = s.mint("carol", AdminRole::Admin, 3600, 1000);
        // Flip a char in the signature part.
        let (e, sig) = token.split_once('.').unwrap();
        let bad = format!("{e}.{}x", &sig[..sig.len() - 1]);
        assert!(s.verify(&bad, 1000).is_none());
        // A different signer's key does not verify.
        assert!(SessionSigner::random().verify(&token, 1000).is_none());
    }

    #[test]
    fn read_only_role_round_trips() {
        let s = SessionSigner::random();
        let (token, _) = s.mint("ro", AdminRole::ReadOnly, 3600, 0);
        assert_eq!(s.verify(&token, 0).unwrap().role, AdminRole::ReadOnly);
    }

    #[test]
    fn cookie_value_parses() {
        assert_eq!(
            cookie_value("a=1; sb_admin_session=tok123; b=2", SESSION_COOKIE).as_deref(),
            Some("tok123")
        );
        assert_eq!(cookie_value("other=1", SESSION_COOKIE), None);
    }
}
