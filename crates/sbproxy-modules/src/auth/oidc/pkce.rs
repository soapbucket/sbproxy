//! WOR-892 PR1 step 2/3: PKCE (RFC 7636) code-verifier + code-challenge
//! helpers used by the OIDC auth-code flow.
//!
//! [RFC 7636 §4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1)
//! pins the `code_verifier` shape: 43-128 characters from the
//! `[A-Z][a-z][0-9]-._~` unreserved set. We always emit 43-char
//! base64url-no-pad of 32 random bytes, which is the natural floor
//! and matches every major IdP (Auth0, Keycloak, Okta, Google).
//!
//! [§4.2](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2)
//! pins the `code_challenge` as `base64url(SHA-256(code_verifier))`
//! when `code_challenge_method=S256` (the only method we emit, since
//! `plain` is grandfathered for legacy clients and is not safe).

use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a fresh 43-character base64url-no-pad PKCE code verifier
/// (RFC 7636 §4.1). 32 random bytes → 43 chars after base64url
/// encoding without padding; the result is safe to ship in a sealed
/// cookie.
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive the `code_challenge` from a `code_verifier` per RFC 7636
/// §4.2 when `code_challenge_method=S256`. SHA-256 the verifier,
/// then base64url-encode without padding.
pub fn derive_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_verifier_is_43_base64url_chars() {
        let v = generate_code_verifier();
        assert_eq!(v.len(), 43);
        for c in v.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-url-safe char {c:?} in verifier {v}"
            );
        }
    }

    #[test]
    fn two_verifiers_differ() {
        // CSPRNG so collisions are infeasible; this catches the bug
        // where someone replaces the rng with a fixed seed.
        let a = generate_code_verifier();
        let b = generate_code_verifier();
        assert_ne!(a, b);
    }

    #[test]
    fn challenge_is_deterministic_for_a_given_verifier() {
        let verifier = "test-verifier-fixed-string-of-the-right-shape";
        let a = derive_code_challenge(verifier);
        let b = derive_code_challenge(verifier);
        assert_eq!(a, b);
    }

    #[test]
    fn challenge_matches_rfc_7636_appendix_b_vector() {
        // RFC 7636 Appendix B: code_verifier =
        // "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(derive_code_challenge(verifier), expected);
    }

    #[test]
    fn challenge_is_43_base64url_chars() {
        let c = derive_code_challenge("any-verifier");
        // SHA-256 = 32 bytes → 43 base64url-no-pad chars.
        assert_eq!(c.len(), 43);
        for c in c.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_');
        }
    }
}
