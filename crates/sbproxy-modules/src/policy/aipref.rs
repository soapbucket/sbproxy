//! aipref signal parsing (Wave 4 / G4.9).
//!
//! aipref is a draft IETF preference signal expressing AI-use opt-out
//! at the resource level. It rides on three transports; Wave 4 only
//! handles the request-side header form:
//!
//! ```text
//! aipref: train=no, search=yes, ai-input=yes
//! ```
//!
//! The header is a comma-separated list of `key=value` pairs. The
//! values are open-ended in the draft, but the canonical encoding is
//! `yes` / `no`. This module exposes a [`AiprefSignal`] struct that
//! flattens the three policy axes (train, search, ai-input) into
//! booleans, with a default-permissive policy when keys are absent or
//! values are unrecognised.
//!
//! The `<meta name="aipref" ...>` and robots.txt forms are not parsed
//! here; they are addressed in a later wave when the response-side
//! signal pipeline lands.
//!
//! ## IETF reference
//! - draft-ietf-aipref-prefs (preference signals)
//! - draft-ietf-aipref-attach (attachment forms)

use std::fmt::Write;

// --- AiprefSignal ---

/// Flattened view of the three Wave 4 aipref axes.
///
/// All three fields default to `true` (permissive); a concrete `false`
/// must be expressed by the publisher via `train=no`, `search=no`, or
/// `ai-input=no`. This matches the draft's "absence of a signal is not
/// a signal" rule and lets operators write expressions like
/// `request.aipref.train == false` without first probing for presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiprefSignal {
    /// `train`: whether the resource may be used for AI model training.
    pub train: bool,
    /// `search`: whether the resource may be indexed for search.
    pub search: bool,
    /// `ai-input`: whether the resource may be used as model input
    /// (inference / RAG).
    pub ai_input: bool,
}

impl Default for AiprefSignal {
    /// Default-permissive: no opt-out asserted.
    fn default() -> Self {
        Self {
            train: true,
            search: true,
            ai_input: true,
        }
    }
}

impl AiprefSignal {
    /// Serialize the signal to its canonical header form. Keys are
    /// emitted in the canonical order (`train`, `search`, `ai-input`).
    /// Used by tests for round-trip verification and by future
    /// projection emitters that need to echo a normalised signal.
    pub fn to_header_string(&self) -> String {
        let mut out = String::with_capacity(40);
        let _ = write!(
            &mut out,
            "train={}, search={}, ai-input={}",
            yes_no(self.train),
            yes_no(self.search),
            yes_no(self.ai_input),
        );
        out
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// --- Parser ---

/// Parse error categories. The wired enricher path treats every
/// `Err` variant as "fall through to default-permissive" while
/// emitting a structured warn log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiprefParseError {
    /// A directive entry had no `=` sign and was therefore
    /// malformed (e.g. `train` instead of `train=no`).
    MissingEquals(String),
    /// A directive had an empty key (e.g. `=yes`).
    EmptyKey,
}

impl std::fmt::Display for AiprefParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEquals(d) => write!(f, "directive has no '=' separator: {:?}", d),
            Self::EmptyKey => write!(f, "directive has empty key"),
        }
    }
}

impl std::error::Error for AiprefParseError {}

/// Parse an aipref header value into an [`AiprefSignal`].
///
/// Lenient per the IETF draft:
///
/// - Whitespace and tabs are tolerated around keys, values, and
///   commas.
/// - Unknown keys are silently ignored.
/// - Unknown values for known keys default to `true` (permissive).
/// - An empty input returns the default permissive signal.
///
/// Strict enough to catch real malformations:
///
/// - A directive without an `=` sign is rejected.
/// - An empty key (`=yes`) is rejected.
///
/// The wired path uses this parser via a request enricher that records
/// "malformed aipref header" at warn and falls through to default-
/// permissive, so callers do not need to swallow `Err` themselves.
pub fn parse_aipref(header: &str) -> Result<AiprefSignal, AiprefParseError> {
    let mut signal = AiprefSignal::default();

    let trimmed = header.trim();
    if trimmed.is_empty() {
        return Ok(signal);
    }

    for raw in trimmed.split(',') {
        let directive = raw.trim();
        if directive.is_empty() {
            // Tolerate trailing or doubled commas.
            continue;
        }

        let Some((key_raw, value_raw)) = directive.split_once('=') else {
            return Err(AiprefParseError::MissingEquals(directive.to_string()));
        };

        let key = key_raw.trim().to_ascii_lowercase();
        let value = value_raw.trim().to_ascii_lowercase();

        if key.is_empty() {
            return Err(AiprefParseError::EmptyKey);
        }

        // Unknown values default to permissive (true). The draft
        // intentionally leaves the value vocabulary open to grow; we
        // match only the vocabulary we currently understand.
        let parsed = match value.as_str() {
            "no" | "false" | "0" => false,
            // Known affirmative or anything else (forward-compat).
            _ => true,
        };

        // Unknown keys are silently ignored (forward-compat).
        match key.as_str() {
            "train" | "ai-train" => signal.train = parsed,
            "search" => signal.search = parsed,
            "ai-input" | "ai_input" | "input" => signal.ai_input = parsed,
            _ => {}
        }
    }

    Ok(signal)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_permissive() {
        let s = AiprefSignal::default();
        assert!(s.train);
        assert!(s.search);
        assert!(s.ai_input);
    }

    #[test]
    fn parses_canonical_example() {
        let s = parse_aipref("train=no, search=yes, ai-input=yes").unwrap();
        assert!(!s.train);
        assert!(s.search);
        assert!(s.ai_input);
    }

    #[test]
    fn parses_with_whitespace_and_tabs() {
        let header = "  train = no  ,\t search=yes ,  ai-input=no  ";
        let s = parse_aipref(header).unwrap();
        assert!(!s.train);
        assert!(s.search);
        assert!(!s.ai_input);
    }

    #[test]
    fn unknown_keys_are_silently_ignored() {
        // `foo=bar` should not panic, should not change anything;
        // known keys should still apply.
        let s = parse_aipref("foo=bar, train=no").unwrap();
        assert!(!s.train);
        // Other axes default-permissive.
        assert!(s.search);
        assert!(s.ai_input);
    }

    #[test]
    fn malformed_directive_without_equals_returns_err() {
        let err = parse_aipref("train").unwrap_err();
        assert!(matches!(err, AiprefParseError::MissingEquals(_)));
    }

    #[test]
    fn empty_key_returns_err() {
        let err = parse_aipref("=yes").unwrap_err();
        assert_eq!(err, AiprefParseError::EmptyKey);
    }

    #[test]
    fn empty_input_yields_defaults() {
        let s = parse_aipref("").unwrap();
        assert_eq!(s, AiprefSignal::default());
        let s2 = parse_aipref("   \t  ").unwrap();
        assert_eq!(s2, AiprefSignal::default());
    }

    #[test]
    fn round_trip_parse_serialize_parse() {
        let original = AiprefSignal {
            train: false,
            search: true,
            ai_input: false,
        };
        let header = original.to_header_string();
        let parsed = parse_aipref(&header).unwrap();
        assert_eq!(parsed, original);

        // Re-serialize and re-parse to confirm idempotency.
        let header2 = parsed.to_header_string();
        assert_eq!(header, header2);
        let parsed2 = parse_aipref(&header2).unwrap();
        assert_eq!(parsed2, original);
    }

    #[test]
    fn unknown_value_defaults_permissive() {
        // A value the draft doesn't define should not be treated as a
        // hard opt-out.
        let s = parse_aipref("train=maybe").unwrap();
        assert!(s.train);
    }

    #[test]
    fn case_insensitive_keys_and_values() {
        let s = parse_aipref("TRAIN=NO, Search=Yes, AI-INPUT=No").unwrap();
        assert!(!s.train);
        assert!(s.search);
        assert!(!s.ai_input);
    }

    #[test]
    fn alternate_value_spellings_for_no() {
        // The canonical encoding is yes/no; tolerate the most common
        // off-spec spellings for opt-out without going hog-wild.
        for v in ["false", "0", "no"] {
            let s = parse_aipref(&format!("train={}", v)).unwrap();
            assert!(!s.train, "expected train=false for value {:?}", v);
        }
    }

    #[test]
    fn doubled_commas_are_tolerated() {
        let s = parse_aipref("train=no,, search=no").unwrap();
        assert!(!s.train);
        assert!(!s.search);
    }

    #[test]
    fn ai_train_alias_is_accepted() {
        // The draft uses `train`; the response `Content-Signal` header
        // uses `ai-train`. We accept both keys here so a single parser
        // can handle both surfaces if a later wave needs it.
        let s = parse_aipref("ai-train=no").unwrap();
        assert!(!s.train);
    }

    #[test]
    fn input_alias_is_accepted() {
        let s = parse_aipref("input=no").unwrap();
        assert!(!s.ai_input);
    }
}
