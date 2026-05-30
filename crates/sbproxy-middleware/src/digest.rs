//! RFC 9530 Digest Fields: `Content-Digest` and `Repr-Digest` for
//! message bodies.
//!
//! Implements the compute, parse, and verify path for the registered
//! algorithm subset that SBproxy treats as production-ready:
//! `sha-256` and `sha-512`. These are the only two algorithms in the
//! IANA "Hash Algorithms for HTTP Digest Fields" registry whose status
//! is "active" (RFC 9530 §6.1). Older or "deprecated" entries
//! (`md5`, `sha`, `unixsum`, `unixcksum`, `adler`, `crc32c`) are
//! intentionally rejected.
//!
//! # What this module is for
//!
//! RFC 9421 HTTP Message Signatures co-signs the `Content-Digest`
//! component so the signed-payload integrity binding survives proxies
//! that re-encode or re-frame the body. The signer needs the digest
//! value on the egress side at the moment it serialises the response,
//! so we expose two shapes:
//!
//! - A one-shot `compute_content_digest(alg, body)` that returns the
//!   header value verbatim (already colon-wrapped per §3).
//! - A streaming `DigestSink::new(alg)` that accepts body chunks via
//!   `update(&[u8])` and finalises into the same header value. The
//!   sink shape is what the Pingora body filter will hook into once
//!   sign-on-egress is wired.
//!
//! # Wire format (RFC 9530 §3)
//!
//! The header is a structured-fields Dictionary keyed by algorithm
//! name, with each value being a Byte Sequence (raw digest bytes).
//! Byte sequences in structured fields are colon-wrapped base64, so
//! the full header value for a sha-256 of the bytes
//! `{"hello": "world"}` is:
//!
//! ```text
//! Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
//! ```
//!
//! Multiple algorithms are emitted as a comma-separated list, e.g.
//! `sha-256=:...:, sha-512=:...:`.
//!
//! # Out of scope (intentionally)
//!
//! - `Repr-Digest` representation-metadata negotiation. We treat
//!   `Content-Digest` and `Repr-Digest` as the same header value over
//!   the message body. The full representation-metadata semantics in
//!   RFC 9530 §2 are not needed for the sign-on-egress integration and
//!   are left for a follow-up.
//! - `Want-Content-Digest` and `Want-Repr-Digest` negotiation
//!   headers.
//! - Pingora body-filter integration; see WOR-519.

use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};

/// Registered RFC 9530 digest algorithm.
///
/// Only the two "active" entries from the IANA registry are accepted.
/// Anything else is rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// SHA-256 (RFC 6234). Header token: `sha-256`.
    Sha256,
    /// SHA-512 (RFC 6234). Header token: `sha-512`.
    Sha512,
}

impl Algorithm {
    /// Canonical lowercase token used in the header dictionary key.
    pub fn token(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha-256",
            Algorithm::Sha512 => "sha-512",
        }
    }

    /// Parse a single algorithm token. Case-insensitive on the prefix
    /// because RFC 9530 §6.1 registers the names in lowercase but
    /// structured-fields dictionary keys are ASCII-lowercase by
    /// definition; we accept the common casing variants to be friendly
    /// to hand-written clients.
    fn parse_token(token: &str) -> Result<Self, DigestError> {
        match token.trim().to_ascii_lowercase().as_str() {
            "sha-256" => Ok(Algorithm::Sha256),
            "sha-512" => Ok(Algorithm::Sha512),
            other => Err(DigestError::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Public counterpart to the internal `parse_token` for callers
    /// that only need to validate a configured algorithm name (e.g.
    /// the WOR-805 `content_digest` policy's `algorithms:` list).
    /// Returns `None` for unknown / deprecated tokens so the caller
    /// can wrap the failure in its own error context.
    pub fn parse(token: &str) -> Option<Self> {
        Self::parse_token(token).ok()
    }
}

/// Errors produced by the digest parser / verifier.
///
/// One-shot and streaming emission are infallible; the only failure
/// surfaces live on the receive side.
#[derive(Debug, PartialEq, Eq)]
pub enum DigestError {
    /// The header value was not a syntactically valid RFC 9530
    /// Dictionary entry (missing `=`, missing colon wrap, etc).
    Malformed(String),
    /// The header named an algorithm that is not in the active subset.
    UnsupportedAlgorithm(String),
    /// The colon-wrapped value did not decode as base64.
    InvalidBase64(String),
}

impl std::fmt::Display for DigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestError::Malformed(m) => write!(f, "malformed Content-Digest header: {m}"),
            DigestError::UnsupportedAlgorithm(a) => {
                write!(f, "unsupported digest algorithm: {a}")
            }
            DigestError::InvalidBase64(b) => write!(f, "invalid base64 in digest value: {b}"),
        }
    }
}

impl std::error::Error for DigestError {}

// --- Compute path -----------------------------------------------------

/// Streaming digest computation. Accept body chunks via [`update`] and
/// finalise into the RFC 9530 header value via [`finalise`].
///
/// The streaming output is byte-identical to the one-shot output for
/// the same total byte sequence; this is asserted in the test module.
///
/// [`update`]: DigestSink::update
/// [`finalise`]: DigestSink::finalise
#[derive(Debug)]
pub struct DigestSink {
    inner: DigestInner,
    algorithm: Algorithm,
}

#[derive(Debug)]
enum DigestInner {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl DigestSink {
    /// Construct a new sink for the given algorithm.
    pub fn new(algorithm: Algorithm) -> Self {
        let inner = match algorithm {
            Algorithm::Sha256 => DigestInner::Sha256(Sha256::new()),
            Algorithm::Sha512 => DigestInner::Sha512(Sha512::new()),
        };
        Self { inner, algorithm }
    }

    /// Feed the next chunk of body bytes into the running digest.
    pub fn update(&mut self, chunk: &[u8]) {
        match &mut self.inner {
            DigestInner::Sha256(s) => s.update(chunk),
            DigestInner::Sha512(s) => s.update(chunk),
        }
    }

    /// Finalise the running digest and return the RFC 9530 header
    /// value (single algorithm, e.g. `sha-256=:<base64>:`).
    pub fn finalise(self) -> String {
        let raw = match self.inner {
            DigestInner::Sha256(s) => s.finalize().to_vec(),
            DigestInner::Sha512(s) => s.finalize().to_vec(),
        };
        format_header_value(self.algorithm, &raw)
    }

    /// Finalise and return both the algorithm and the raw digest
    /// bytes, leaving the caller free to format. Used by the
    /// multi-algorithm emitter.
    fn finalise_raw(self) -> (Algorithm, Vec<u8>) {
        let raw = match self.inner {
            DigestInner::Sha256(s) => s.finalize().to_vec(),
            DigestInner::Sha512(s) => s.finalize().to_vec(),
        };
        (self.algorithm, raw)
    }
}

/// One-shot compute. Returns the header value verbatim (single
/// algorithm form).
pub fn compute_content_digest(algorithm: Algorithm, body: &[u8]) -> String {
    let mut sink = DigestSink::new(algorithm);
    sink.update(body);
    sink.finalise()
}

/// One-shot compute for multiple algorithms. Returns the
/// comma-separated header value in the order the algorithms were
/// listed, per RFC 9530 §3 examples.
pub fn compute_content_digest_multi(algorithms: &[Algorithm], body: &[u8]) -> String {
    let parts: Vec<String> = algorithms
        .iter()
        .map(|alg| {
            let mut sink = DigestSink::new(*alg);
            sink.update(body);
            let (alg, raw) = sink.finalise_raw();
            format_header_value(alg, &raw)
        })
        .collect();
    parts.join(", ")
}

fn format_header_value(algorithm: Algorithm, raw_digest: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_digest);
    // Structured-fields Byte Sequence is colon-wrapped base64.
    format!("{}=:{}:", algorithm.token(), b64)
}

// --- Parse path -------------------------------------------------------

/// Parse an RFC 9530 `Content-Digest` (or `Repr-Digest`) header value
/// into its algorithm/raw-digest pairs.
///
/// Strict: every entry must be `<token>=:<base64>:` and every token
/// must be in the active algorithm subset. Unknown tokens fail the
/// whole parse, because partial acceptance would let an attacker
/// downgrade an integrity check by adding a junk algorithm alongside a
/// real one.
pub fn parse_content_digest(header_value: &str) -> Result<Vec<(Algorithm, Vec<u8>)>, DigestError> {
    let mut out = Vec::new();

    for entry in split_top_level_commas(header_value) {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(DigestError::Malformed("empty dictionary entry".to_owned()));
        }

        let (raw_token, raw_value) = entry
            .split_once('=')
            .ok_or_else(|| DigestError::Malformed(format!("missing '=' in entry: {entry}")))?;

        let token = raw_token.trim();
        let value = raw_value.trim();

        // Byte Sequence must be wrapped in colons.
        let inner = value
            .strip_prefix(':')
            .and_then(|v| v.strip_suffix(':'))
            .ok_or_else(|| {
                DigestError::Malformed(format!(
                    "value for '{token}' is not a colon-wrapped Byte Sequence"
                ))
            })?;

        let alg = Algorithm::parse_token(token)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(inner)
            .map_err(|e| DigestError::InvalidBase64(e.to_string()))?;

        out.push((alg, bytes));
    }

    if out.is_empty() {
        return Err(DigestError::Malformed("no dictionary entries".to_owned()));
    }

    Ok(out)
}

/// Split a structured-fields dictionary on commas at the top level
/// only, ignoring commas inside the colon-wrapped Byte Sequence
/// segments. Base64 never contains `:` or `,`, so the wrap markers are
/// unambiguous.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth_colon = false;
    let mut start = 0usize;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b':' => depth_colon = !depth_colon,
            b',' if !depth_colon => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

// --- Verify path ------------------------------------------------------

/// Convenience: parse a header value, recompute each named algorithm
/// over `body`, and return true if every entry matches.
///
/// Returns false on any parse error, any unsupported algorithm, or any
/// digest mismatch. The intent is a single drop-in predicate for the
/// receive side; callers that need to distinguish "malformed" from
/// "mismatched" should call [`parse_content_digest`] directly.
pub fn verify_content_digest(header_value: &str, body: &[u8]) -> bool {
    let parsed = match parse_content_digest(header_value) {
        Ok(p) => p,
        Err(_) => return false,
    };

    for (alg, expected) in parsed {
        let mut sink = DigestSink::new(alg);
        sink.update(body);
        let (_, actual) = sink.finalise_raw();
        // Constant-time compare is overkill for a public integrity
        // tag (the value isn't a secret), but it's free here and
        // keeps the code uniform with the signature path.
        if !constant_time_eq(&actual, &expected) {
            return false;
        }
    }
    true
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9530 §2 publishes the canonical example: the JSON body
    // `{"hello": "world"}` (no trailing newline) hashes to these
    // values. We pin the emitter against those exact vectors so any
    // regression in either base64 encoding or hash output is caught
    // at the unit-test level.
    const RFC_BODY: &[u8] = b"{\"hello\": \"world\"}";
    const RFC_SHA256: &str = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
    const RFC_SHA512: &str = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

    #[test]
    fn one_shot_sha256_matches_rfc_9530_example() {
        assert_eq!(
            compute_content_digest(Algorithm::Sha256, RFC_BODY),
            RFC_SHA256
        );
    }

    #[test]
    fn one_shot_sha512_matches_rfc_9530_example() {
        assert_eq!(
            compute_content_digest(Algorithm::Sha512, RFC_BODY),
            RFC_SHA512
        );
    }

    #[test]
    fn streaming_matches_one_shot_sha256() {
        let one_shot = compute_content_digest(Algorithm::Sha256, RFC_BODY);

        let mut sink = DigestSink::new(Algorithm::Sha256);
        // Feed the body byte by byte to exercise the streaming path.
        for byte in RFC_BODY {
            sink.update(std::slice::from_ref(byte));
        }
        let streamed = sink.finalise();

        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn streaming_matches_one_shot_sha512_with_chunked_input() {
        let one_shot = compute_content_digest(Algorithm::Sha512, RFC_BODY);

        let mut sink = DigestSink::new(Algorithm::Sha512);
        // Arbitrary chunk boundary, just to make sure update() can be
        // called more than once with different sizes.
        let (head, tail) = RFC_BODY.split_at(5);
        sink.update(head);
        sink.update(tail);
        let streamed = sink.finalise();

        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn empty_body_emits_valid_header() {
        let header = compute_content_digest(Algorithm::Sha256, b"");
        // Known digest of the empty byte string under sha-256.
        assert_eq!(
            header,
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );

        // And it round-trips through parse.
        let parsed = parse_content_digest(&header).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, Algorithm::Sha256);
        assert_eq!(parsed[0].1.len(), 32);

        // And it verifies.
        assert!(verify_content_digest(&header, b""));
    }

    #[test]
    fn parse_round_trips_emitted_header() {
        let header = compute_content_digest(Algorithm::Sha256, RFC_BODY);
        let parsed = parse_content_digest(&header).expect("parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, Algorithm::Sha256);
        // Re-emit and compare to the original.
        let re_emitted = format_header_value(parsed[0].0, &parsed[0].1);
        assert_eq!(re_emitted, header);
    }

    #[test]
    fn parse_multi_algorithm_dictionary() {
        let header =
            compute_content_digest_multi(&[Algorithm::Sha256, Algorithm::Sha512], RFC_BODY);
        let parsed = parse_content_digest(&header).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, Algorithm::Sha256);
        assert_eq!(parsed[1].0, Algorithm::Sha512);
        assert!(verify_content_digest(&header, RFC_BODY));
    }

    #[test]
    fn verify_accepts_good_header() {
        let header = compute_content_digest(Algorithm::Sha256, RFC_BODY);
        assert!(verify_content_digest(&header, RFC_BODY));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let header = compute_content_digest(Algorithm::Sha256, RFC_BODY);
        let tampered = b"{\"hello\": \"WORLD\"}";
        assert!(!verify_content_digest(&header, tampered));
    }

    #[test]
    fn verify_rejects_unknown_algorithm() {
        // Synthesise a header that claims to use md5. Even though the
        // base64 happens to decode cleanly, the algorithm token is not
        // in the active subset, so verification must fail.
        let bogus = "md5=:aGVsbG8gd29ybGQ=:";
        assert!(!verify_content_digest(bogus, RFC_BODY));
        // And parse rejects it explicitly.
        let err = parse_content_digest(bogus).unwrap_err();
        assert!(matches!(err, DigestError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn parse_rejects_missing_colon_wrap() {
        let bad = "sha-256=deadbeef";
        let err = parse_content_digest(bad).unwrap_err();
        assert!(matches!(err, DigestError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_missing_equals() {
        let bad = "sha-256:deadbeef:";
        let err = parse_content_digest(bad).unwrap_err();
        assert!(matches!(err, DigestError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_invalid_base64() {
        let bad = "sha-256=:not-valid-base64!!!:";
        let err = parse_content_digest(bad).unwrap_err();
        assert!(matches!(err, DigestError::InvalidBase64(_)));
    }

    #[test]
    fn parse_rejects_empty_string() {
        let err = parse_content_digest("").unwrap_err();
        assert!(matches!(err, DigestError::Malformed(_)));
    }

    #[test]
    fn algorithm_token_is_canonical_lowercase() {
        assert_eq!(Algorithm::Sha256.token(), "sha-256");
        assert_eq!(Algorithm::Sha512.token(), "sha-512");
    }
}
