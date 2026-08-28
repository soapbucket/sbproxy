// PKCE (RFC 7636) state machine for the MCP OAuth 2.1 broker.
//
// OAuth 2.1 mandates PKCE for all clients (RFC 9700, draft OAuth 2.1
// section 4.1.2). This module implements the verifier / challenge
// types and the SHA-256 challenge derivation. The `plain` method is
// not implemented; callers MUST reject `code_challenge_method=plain`
// at the request layer.

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;

// --- Constants ---

/// Minimum verifier length per RFC 7636 section 4.1.
pub const VERIFIER_MIN_LEN: usize = 43;
/// Maximum verifier length per RFC 7636 section 4.1.
pub const VERIFIER_MAX_LEN: usize = 128;

/// Unreserved characters allowed in a PKCE verifier per RFC 7636 §4.1:
/// `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`.
const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

// --- Errors ---

/// Reasons a verifier or challenge value is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkceError {
    /// Verifier was shorter than 43 or longer than 128 characters.
    VerifierLength(usize),
    /// Verifier contained a character outside the RFC 7636 unreserved set.
    VerifierCharacter(char),
    /// `plain` challenge method is forbidden by OAuth 2.1.
    PlainMethodForbidden,
    /// Unknown challenge method string.
    UnknownMethod(String),
}

impl fmt::Display for PkceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkceError::VerifierLength(n) => write!(
                f,
                "PKCE verifier length {n} outside RFC 7636 range [{VERIFIER_MIN_LEN}, {VERIFIER_MAX_LEN}]"
            ),
            PkceError::VerifierCharacter(c) => {
                write!(f, "PKCE verifier contains invalid character {c:?}")
            }
            PkceError::PlainMethodForbidden => write!(
                f,
                "PKCE method 'plain' is forbidden by OAuth 2.1; use 'S256'"
            ),
            PkceError::UnknownMethod(s) => write!(f, "unknown PKCE method {s:?}"),
        }
    }
}

impl std::error::Error for PkceError {}

// --- Code verifier ---

/// A PKCE code verifier (RFC 7636 §4.1).
///
/// The verifier is a high-entropy random string between 43 and 128
/// characters drawn from the unreserved set. As a broker, sbproxy
/// generates and holds its own verifier when forwarding the client's
/// authorization request to the upstream Authorization Server, so the
/// upstream sees one PKCE pair (broker-to-AS) and the client sees a
/// separate one (client-to-broker).
#[derive(Clone, PartialEq, Eq)]
pub struct CodeVerifier(String);

impl CodeVerifier {
    /// Wraps a raw string after validating its length and character set.
    pub fn new(raw: impl Into<String>) -> Result<Self, PkceError> {
        let raw = raw.into();
        let len = raw.len();
        if !(VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&len) {
            return Err(PkceError::VerifierLength(len));
        }
        for c in raw.chars() {
            if !UNRESERVED.contains(&(c as u8)) {
                return Err(PkceError::VerifierCharacter(c));
            }
        }
        Ok(Self(raw))
    }

    /// Generates a fresh random verifier of the given length using
    /// `rand::thread_rng`. Length is clamped to the RFC 7636 range.
    pub fn generate(len: usize) -> Self {
        let len = len.clamp(VERIFIER_MIN_LEN, VERIFIER_MAX_LEN);
        let mut rng = rand::thread_rng();
        let bytes: String = (0..len)
            .map(|_| {
                let i = rng.gen_range(0..UNRESERVED.len());
                UNRESERVED[i] as char
            })
            .collect();
        // SAFETY: bytes is built from UNRESERVED, all of which are ASCII.
        Self(bytes)
    }

    /// Borrows the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking the raw verifier into logs.
        f.debug_struct("CodeVerifier")
            .field("len", &self.0.len())
            .finish()
    }
}

// --- Code challenge ---

/// A PKCE code challenge. With the S256 method, this is
/// BASE64URL(SHA256(verifier)) with no padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// Derives an S256 challenge from the given verifier per RFC 7636 §4.2.
    pub fn from_verifier_s256(verifier: &CodeVerifier) -> Self {
        let digest = Sha256::digest(verifier.as_str().as_bytes());
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Self(encoded)
    }

    /// Wraps an opaque challenge value. The broker stores the client's
    /// challenge verbatim and forwards it to the upstream AS; we never
    /// re-validate the encoding because RFC 7636 leaves the format to
    /// the method.
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrows the underlying encoded challenge.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// --- Method enum ---

/// Supported PKCE challenge methods. Only `S256` is supported by
/// design; OAuth 2.1 forbids `plain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// SHA-256 challenge derivation.
    S256,
}

impl CodeChallengeMethod {
    /// Parses a method string from the wire. Rejects `plain` with
    /// `PkceError::PlainMethodForbidden`. Anything else returns
    /// `PkceError::UnknownMethod`.
    pub fn parse(s: &str) -> Result<Self, PkceError> {
        match s {
            "S256" => Ok(Self::S256),
            "plain" => Err(PkceError::PlainMethodForbidden),
            other => Err(PkceError::UnknownMethod(other.to_string())),
        }
    }
}

impl fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S256 => f.write_str("S256"),
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_min_length_accepted() {
        let v = "a".repeat(VERIFIER_MIN_LEN);
        assert!(CodeVerifier::new(v).is_ok());
    }

    #[test]
    fn verifier_max_length_accepted() {
        let v = "a".repeat(VERIFIER_MAX_LEN);
        assert!(CodeVerifier::new(v).is_ok());
    }

    #[test]
    fn verifier_too_short_rejected() {
        let v = "a".repeat(VERIFIER_MIN_LEN - 1);
        let err = CodeVerifier::new(v).unwrap_err();
        assert_eq!(err, PkceError::VerifierLength(VERIFIER_MIN_LEN - 1));
    }

    #[test]
    fn verifier_too_long_rejected() {
        let v = "a".repeat(VERIFIER_MAX_LEN + 1);
        let err = CodeVerifier::new(v).unwrap_err();
        assert_eq!(err, PkceError::VerifierLength(VERIFIER_MAX_LEN + 1));
    }

    #[test]
    fn verifier_invalid_char_rejected() {
        let mut v = "a".repeat(VERIFIER_MIN_LEN - 1);
        v.push('+'); // '+' is reserved per RFC 7636
        let err = CodeVerifier::new(v).unwrap_err();
        assert_eq!(err, PkceError::VerifierCharacter('+'));
    }

    #[test]
    fn generated_verifier_is_valid() {
        for _ in 0..32 {
            let v = CodeVerifier::generate(64);
            assert_eq!(v.as_str().len(), 64);
            // Re-validates that the generator only emits unreserved chars.
            assert!(CodeVerifier::new(v.as_str()).is_ok());
        }
    }

    #[test]
    fn generated_verifier_clamps_length() {
        // Below min is clamped up.
        let v = CodeVerifier::generate(1);
        assert_eq!(v.as_str().len(), VERIFIER_MIN_LEN);
        // Above max is clamped down.
        let v = CodeVerifier::generate(9999);
        assert_eq!(v.as_str().len(), VERIFIER_MAX_LEN);
    }

    #[test]
    fn s256_challenge_known_vector() {
        // RFC 7636 appendix B test vector.
        let verifier = CodeVerifier::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        let challenge = CodeChallenge::from_verifier_s256(&verifier);
        assert_eq!(
            challenge.as_str(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn s256_round_trip_is_stable() {
        let v = CodeVerifier::generate(64);
        let c1 = CodeChallenge::from_verifier_s256(&v);
        let c2 = CodeChallenge::from_verifier_s256(&v);
        assert_eq!(c1.as_str(), c2.as_str());
    }

    #[test]
    fn method_parse_s256() {
        assert_eq!(
            CodeChallengeMethod::parse("S256").unwrap(),
            CodeChallengeMethod::S256
        );
    }

    #[test]
    fn method_parse_plain_forbidden() {
        assert_eq!(
            CodeChallengeMethod::parse("plain").unwrap_err(),
            PkceError::PlainMethodForbidden
        );
    }

    #[test]
    fn method_parse_unknown_rejected() {
        let err = CodeChallengeMethod::parse("MD5").unwrap_err();
        assert!(matches!(err, PkceError::UnknownMethod(s) if s == "MD5"));
    }

    #[test]
    fn method_display_round_trips() {
        assert_eq!(format!("{}", CodeChallengeMethod::S256), "S256");
    }

    #[test]
    fn verifier_debug_does_not_leak() {
        let v = CodeVerifier::generate(64);
        let debug = format!("{v:?}");
        assert!(!debug.contains(v.as_str()), "debug output leaked verifier");
    }
}
