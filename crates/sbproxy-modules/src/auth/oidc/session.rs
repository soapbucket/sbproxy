//! WOR-892 PR1 step 2/3: sealed-cookie session payload for the OIDC
//! auth provider.
//!
//! Two cookies, two payload shapes:
//!
//! * `SessionClaims` — what the long-lived `__Host-sbproxy_session`
//!   cookie carries after a successful login. Holds the OIDC ID
//!   token's `sub`, `iss`, `aud`, and an absolute `exp` so the proxy
//!   can short-circuit auth on subsequent requests without an IdP
//!   round-trip.
//! * `TxClaims` — what the short-lived `__Host-sbproxy_oidc_tx`
//!   cookie carries during the auth-code dance. Holds the `state`
//!   (CSRF), `nonce` (ID-token replay defence), `pkce_verifier` (RFC
//!   7636), and the `return_to` URL the caller wanted.
//!
//! Both encode as CBOR (smaller wire shape than JSON, no
//! percent-encoding gymnastics inside the Set-Cookie header) and
//! seal via [`sbproxy_security::cookie`] under their respective
//! [`HkdfPurpose`] variant. HKDF separation guarantees a captured
//! session cookie can never decrypt as a tx cookie and vice versa.

use anyhow::{anyhow, Context, Result};
use sbproxy_security::cookie;
use sbproxy_security::HkdfPurpose;
use serde::{Deserialize, Serialize};

/// Claims carried in the long-lived OIDC session cookie. Set after
/// a successful login, consulted on every subsequent request to
/// short-circuit the auth check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// OIDC `sub` claim from the ID token — the authenticated user.
    pub sub: String,
    /// OIDC `iss` claim — pinned at issue time so a key rotation that
    /// changes `iss` invalidates old sessions cleanly.
    pub iss: String,
    /// OIDC `aud` claim — the proxy's `client_id` at the IdP. Pinned
    /// for the same reason as `iss`.
    pub aud: String,
    /// Absolute expiry, unix seconds. The proxy checks this on every
    /// request and 401s when expired; the IdP's own `exp` is only
    /// consulted at login time.
    pub exp: u64,
    /// Absolute issued-at, unix seconds. Used by audit / event logs
    /// to compute session age.
    pub iat: u64,
    /// Trust-header projection from the IdP's userinfo response,
    /// captured at login time. Pairs of (header-name, value) like
    /// `("X-Auth-Email", "alice@example.com")`. Empty when userinfo
    /// is not configured or the OP did not release any projectable
    /// claims. The request-time auth check replays these onto the
    /// upstream request so the origin sees a stable trust view
    /// regardless of which OP issued the session.
    ///
    /// Serde-defaulted so cookies issued before this field existed
    /// continue to deserialise; they simply project no headers.
    #[serde(default)]
    pub trust_headers: Vec<(String, String)>,
}

/// Claims carried in the short-lived OIDC transaction cookie. Set
/// when the proxy redirects the unauthenticated caller to the IdP,
/// consulted exactly once when the IdP redirects back to
/// `/oidc/callback`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxClaims {
    /// CSRF token round-tripped through the IdP. The callback handler
    /// rejects the redirect when the IdP-supplied `state` query
    /// parameter does not equal this value.
    pub state: String,
    /// OIDC `nonce`. Pinned into the auth request, asserted equal to
    /// the ID token's `nonce` claim by the callback handler to defeat
    /// cross-tab ID-token replay.
    pub nonce: String,
    /// RFC 7636 `code_verifier` the callback handler sends to the
    /// token endpoint. The corresponding `code_challenge` was sent
    /// on the auth request.
    pub pkce_verifier: String,
    /// Where the caller originally tried to go. The callback handler
    /// redirects here after minting the session cookie. Defaults to
    /// `/` when the operator does not preserve the original target.
    pub return_to: String,
    /// Absolute expiry of this transaction, unix seconds. A stale tx
    /// cookie (the user wandered off mid-login) MUST be rejected so
    /// stash-and-replay attacks across days are impossible.
    pub exp: u64,
}

/// Seal `claims` into a base64url-no-pad string suitable for a
/// `Set-Cookie` value. CBOR-encode → AES-256-GCM under
/// `HkdfPurpose::OidcSessionCookie`.
pub fn seal_session(claims: &SessionClaims, ikm: &[u8]) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    ciborium::into_writer(claims, &mut buf).context("cbor encode SessionClaims")?;
    cookie::seal(&buf, ikm, HkdfPurpose::OidcSessionCookie).context("seal session cookie")
}

/// Decrypt + decode a value produced by [`seal_session`]. Returns
/// `Err` for any of: bad base64, AEAD tag mismatch, wrong key, CBOR
/// decode failure, expired claims (relative to `now`).
pub fn open_session(b64: &str, ikm: &[u8], now: u64) -> Result<SessionClaims> {
    let plaintext =
        cookie::open(b64, ikm, HkdfPurpose::OidcSessionCookie).context("open session cookie")?;
    let claims: SessionClaims =
        ciborium::from_reader(&plaintext[..]).context("cbor decode SessionClaims")?;
    if now >= claims.exp {
        return Err(anyhow!(
            "session expired (exp={} <= now={})",
            claims.exp,
            now
        ));
    }
    Ok(claims)
}

/// Seal `claims` into a base64url-no-pad string for the tx cookie.
/// Uses the distinct [`HkdfPurpose::OidcTxCookie`] keyspace so a
/// captured tx cookie cannot be replayed as a session cookie.
pub fn seal_tx(claims: &TxClaims, ikm: &[u8]) -> Result<String> {
    let mut buf = Vec::with_capacity(256);
    ciborium::into_writer(claims, &mut buf).context("cbor encode TxClaims")?;
    cookie::seal(&buf, ikm, HkdfPurpose::OidcTxCookie).context("seal tx cookie")
}

/// Decrypt + decode a value produced by [`seal_tx`]. Same failure
/// modes as [`open_session`].
pub fn open_tx(b64: &str, ikm: &[u8], now: u64) -> Result<TxClaims> {
    let plaintext = cookie::open(b64, ikm, HkdfPurpose::OidcTxCookie).context("open tx cookie")?;
    let claims: TxClaims = ciborium::from_reader(&plaintext[..]).context("cbor decode TxClaims")?;
    if now >= claims.exp {
        return Err(anyhow!(
            "tx cookie expired (exp={} <= now={})",
            claims.exp,
            now
        ));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IKM: &[u8] = b"operator-supplied-secret-ikm-of-arbitrary-length";

    fn session_at(now: u64, ttl: u64) -> SessionClaims {
        SessionClaims {
            sub: "alice@example.com".to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: "sbproxy-client-id".to_string(),
            iat: now,
            exp: now + ttl,
            trust_headers: Vec::new(),
        }
    }

    fn tx_at(now: u64, ttl: u64) -> TxClaims {
        TxClaims {
            state: "csrf-state-abc".to_string(),
            nonce: "id-token-nonce-xyz".to_string(),
            pkce_verifier: "verifier-43-chars-base64url-nopad-padding-x".to_string(),
            return_to: "/dashboard?tab=usage".to_string(),
            exp: now + ttl,
        }
    }

    #[test]
    fn session_round_trip_preserves_every_field() {
        let now = 1_700_000_000;
        let claims = session_at(now, 3600);
        let sealed = seal_session(&claims, IKM).unwrap();
        let opened = open_session(&sealed, IKM, now).unwrap();
        assert_eq!(opened, claims);
    }

    #[test]
    fn session_round_trip_preserves_trust_headers() {
        // The userinfo follow-up stashes trust-header projections in
        // the session cookie; the round-trip must preserve them
        // verbatim or the request-time replay sends the wrong values.
        let now = 1_700_000_000;
        let mut claims = session_at(now, 3600);
        claims.trust_headers = vec![
            (
                "X-Auth-Subject".to_string(),
                "alice@example.com".to_string(),
            ),
            ("X-Auth-Email".to_string(), "alice@example.com".to_string()),
            ("X-Auth-Groups".to_string(), "eng,platform".to_string()),
        ];
        let sealed = seal_session(&claims, IKM).unwrap();
        let opened = open_session(&sealed, IKM, now).unwrap();
        assert_eq!(opened.trust_headers, claims.trust_headers);
    }

    #[test]
    fn session_rejects_expired_claims() {
        let now = 1_700_000_000;
        let claims = session_at(now, 60);
        let sealed = seal_session(&claims, IKM).unwrap();
        // Skip the clock past exp.
        let err = open_session(&sealed, IKM, now + 120).unwrap_err();
        assert!(format!("{err:#}").contains("session expired"));
    }

    #[test]
    fn session_cookie_does_not_open_as_tx_cookie() {
        // HKDF purpose separation is the load-bearing security
        // property: a captured session cookie MUST NOT be replayable
        // through the tx-cookie verification path.
        let now = 1_700_000_000;
        let sealed = seal_session(&session_at(now, 3600), IKM).unwrap();
        assert!(open_tx(&sealed, IKM, now).is_err());
    }

    #[test]
    fn tx_round_trip_preserves_every_field() {
        let now = 1_700_000_000;
        let claims = tx_at(now, 300);
        let sealed = seal_tx(&claims, IKM).unwrap();
        let opened = open_tx(&sealed, IKM, now).unwrap();
        assert_eq!(opened, claims);
    }

    #[test]
    fn tx_rejects_expired_claims() {
        let now = 1_700_000_000;
        let sealed = seal_tx(&tx_at(now, 60), IKM).unwrap();
        let err = open_tx(&sealed, IKM, now + 120).unwrap_err();
        assert!(format!("{err:#}").contains("tx cookie expired"));
    }

    #[test]
    fn tx_cookie_does_not_open_as_session_cookie() {
        let now = 1_700_000_000;
        let sealed = seal_tx(&tx_at(now, 300), IKM).unwrap();
        assert!(open_session(&sealed, IKM, now).is_err());
    }

    #[test]
    fn wrong_ikm_rejects() {
        let now = 1_700_000_000;
        let sealed = seal_session(&session_at(now, 3600), IKM).unwrap();
        assert!(open_session(&sealed, b"different-ikm", now).is_err());
    }

    #[test]
    fn session_serializes_to_url_safe_alphabet() {
        // The sealed value must be embeddable in a Set-Cookie value
        // without further percent-encoding.
        let now = 1_700_000_000;
        let sealed = seal_session(&session_at(now, 3600), IKM).unwrap();
        for c in sealed.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-url-safe char {c:?}"
            );
        }
    }
}
