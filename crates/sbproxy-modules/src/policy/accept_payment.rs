//! `Accept-Payment` header parser (Wave 3 / R3.1).
//!
//! Per `docs/adr-multi-rail-402-challenge.md` (A3.1):
//!
//! - Wire format: `Accept-Payment: x402;q=1, mpp;q=0.9` (Accept-style
//!   q-value list, RFC 9110 § 12.4.2 shape).
//! - Missing header: empty preferences. The proxy emits its default
//!   order.
//! - Unknown rail tokens: `RailKind::Other(...)`, preserved for future
//!   extension (Lightning, MPP variants, ...).
//! - Q-values express preference; missing q is `q=1`. Higher q wins.
//!   Operator preference order breaks ties.
//!
//! The parser is deliberately allocation-light on the hot path and
//! never panics on malformed input. A malformed header is treated the
//! same as a missing header (empty preferences) so a buggy agent
//! degrades to the operator's default rail order rather than failing
//! the request outright.

use std::cmp::Ordering;
use std::fmt;

// --- Public surface ---

/// One agent-side rail-kind preference parsed from the `Accept-Payment`
/// header.
///
/// Stable order is preserved across construction so equal-q entries
/// fall through to the operator's preference order at filter time.
#[derive(Debug, Clone, PartialEq)]
pub struct RailPreference {
    /// The rail-kind token (`x402`, `mpp`, or an unknown extension).
    pub rail_kind: RailKind,
    /// Quality factor in `[0.0, 1.0]`. Defaults to `1.0` when the
    /// header omits an explicit `q=` parameter.
    pub q: f32,
}

/// Closed-with-escape rail-kind enumeration per A1.8 schema rules.
///
/// `X402` and `Mpp` are the Wave 3 closed set. `Other(String)` carries
/// any unknown rail token verbatim so future extensions (Lightning,
/// custom MPP variants) round-trip without the parser dropping them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RailKind {
    /// x402 stablecoin rail (chain-settled). Wire token: `x402`.
    X402,
    /// MPP card / Stripe rail. Wire token: `mpp`.
    Mpp,
    /// Unknown rail token, preserved for forward-compat. The contained
    /// string is the lower-cased, trimmed token from the header.
    Other(String),
}

impl RailKind {
    /// Parse a single rail token.
    ///
    /// Comparison is case-insensitive; whitespace must already be
    /// trimmed by the caller. Unknown tokens become `Other(lowercase)`.
    pub fn parse(token: &str) -> Self {
        let trimmed = token.trim();
        if trimmed.eq_ignore_ascii_case("x402") {
            RailKind::X402
        } else if trimmed.eq_ignore_ascii_case("mpp") {
            RailKind::Mpp
        } else {
            RailKind::Other(trimmed.to_ascii_lowercase())
        }
    }

    /// Render the rail token in its canonical wire form.
    pub fn as_token(&self) -> &str {
        match self {
            RailKind::X402 => "x402",
            RailKind::Mpp => "mpp",
            RailKind::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for RailKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// Parsed `Accept-Payment` header.
///
/// `preferences` is ordered by descending q value; equal-q entries
/// keep their original header order so the operator's preference can
/// break ties at [`AcceptPayment::picks`] time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AcceptPayment {
    /// Ordered preference list. May be empty (no opt-in).
    pub preferences: Vec<RailPreference>,
}

/// Parser error.
///
/// Wave 3 keeps this enum small. The proxy's hot path treats any
/// parse error as "the agent did not opt in" (empty preferences), so
/// these variants surface only when callers explicitly want the
/// distinction (e.g. for diagnostics).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// A `q=` parameter was present but was not a number in `[0.0, 1.0]`.
    #[error("invalid q value: {0}")]
    InvalidQ(String),
    /// A rail-kind token was empty after splitting / trimming.
    #[error("empty rail token")]
    EmptyToken,
}

impl AcceptPayment {
    /// Parse a single `Accept-Payment` header value.
    ///
    /// An empty or whitespace-only header yields an empty
    /// preferences vector (no opt-in).
    pub fn parse(header_value: &str) -> Result<Self, ParseError> {
        let mut preferences: Vec<RailPreference> = Vec::new();
        let trimmed_header = header_value.trim();
        if trimmed_header.is_empty() {
            return Ok(Self { preferences });
        }

        // RFC 9110 § 12.4.2 grammar: comma-separated entries; each
        // entry is `token` plus optional `;param=value` pairs. We only
        // recognise `q=` parameters; unknown params are tolerated and
        // ignored so future header extensions don't break parsing.
        for raw_entry in trimmed_header.split(',') {
            let entry = raw_entry.trim();
            if entry.is_empty() {
                continue;
            }

            let mut parts = entry.split(';');
            let token = parts.next().unwrap_or("").trim();
            if token.is_empty() {
                return Err(ParseError::EmptyToken);
            }

            let mut q: f32 = 1.0;
            for param in parts {
                let p = param.trim();
                if let Some(rest) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                    let parsed: f32 = rest
                        .trim()
                        .parse()
                        .map_err(|_| ParseError::InvalidQ(rest.to_string()))?;
                    if !(0.0..=1.0).contains(&parsed) || parsed.is_nan() {
                        return Err(ParseError::InvalidQ(rest.to_string()));
                    }
                    q = parsed;
                }
                // Unknown parameter: ignored on purpose.
            }

            preferences.push(RailPreference {
                rail_kind: RailKind::parse(token),
                q,
            });
        }

        // Sort by descending q. `sort_by` is stable, so equal-q
        // entries keep their original header order (which is the tie
        // break the ADR pins).
        preferences.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(Ordering::Equal));

        Ok(Self { preferences })
    }

    /// Whether the agent expressed any preference (header was present
    /// and non-empty).
    pub fn is_empty(&self) -> bool {
        self.preferences.is_empty()
    }

    /// Filter `available` (the operator's configured rails) by the
    /// agent's preferences and return the filtered set in agent
    /// preference order.
    ///
    /// - Empty agent preferences: returns `available` unchanged so
    ///   the proxy can fall back to its operator-configured order.
    /// - No overlap: returns an empty vector. Callers translate that
    ///   into the `406 Not Acceptable` ADR response.
    /// - Otherwise: emits the intersection sorted by the agent's q
    ///   values, with equal-q entries falling through to the
    ///   `available` (operator) order.
    pub fn picks(&self, available: &[RailKind]) -> Vec<RailKind> {
        if self.preferences.is_empty() {
            return available.to_vec();
        }

        // Build a vector of (rail, q) pairs in operator order. Equal-q
        // entries inherit a stable position from `available`, which
        // matches the ADR's "operator preference breaks ties" rule.
        let mut scored: Vec<(RailKind, f32, usize)> = Vec::new();
        for (op_idx, rail) in available.iter().enumerate() {
            if let Some(pref) = self.preferences.iter().find(|p| &p.rail_kind == rail) {
                scored.push((rail.clone(), pref.q, op_idx));
            }
        }

        // Sort by descending q; equal q falls through to ascending
        // operator index (which preserves operator preference).
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(Ordering::Equal)
                .then(a.2.cmp(&b.2))
        });

        scored.into_iter().map(|(rail, _, _)| rail).collect()
    }
}

// --- Scripting surface ---

/// Render the parsed header as a flat list of rail-kind tokens for
/// scripting consumers (CEL / Lua / JS / WASM via `sbproxy-extension`).
///
/// Matches the existing `Accept` exposure pattern: scripts receive a
/// `Vec<String>` of rail tokens in agent preference order, and can
/// compare against literal strings (`"x402"`, `"mpp"`) without needing
/// to introspect q values.
pub fn rail_tokens(parsed: &AcceptPayment) -> Vec<String> {
    parsed
        .preferences
        .iter()
        .map(|p| p.rail_kind.as_token().to_string())
        .collect()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_payment_parses_q_values_in_order() {
        let parsed = AcceptPayment::parse("x402;q=1, mpp;q=0.9").unwrap();
        assert_eq!(parsed.preferences.len(), 2);
        assert_eq!(parsed.preferences[0].rail_kind, RailKind::X402);
        assert!((parsed.preferences[0].q - 1.0).abs() < f32::EPSILON);
        assert_eq!(parsed.preferences[1].rail_kind, RailKind::Mpp);
        assert!((parsed.preferences[1].q - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn accept_payment_reorders_by_q_descending() {
        // Header lists mpp first but with lower q. Parser must
        // reorder so x402 leads.
        let parsed = AcceptPayment::parse("mpp;q=0.5, x402;q=1.0").unwrap();
        assert_eq!(parsed.preferences[0].rail_kind, RailKind::X402);
        assert_eq!(parsed.preferences[1].rail_kind, RailKind::Mpp);
    }

    #[test]
    fn accept_payment_default_q_is_one() {
        let parsed = AcceptPayment::parse("x402, mpp").unwrap();
        assert_eq!(parsed.preferences.len(), 2);
        assert!((parsed.preferences[0].q - 1.0).abs() < f32::EPSILON);
        assert!((parsed.preferences[1].q - 1.0).abs() < f32::EPSILON);
        // Equal q: header order is preserved (stable sort).
        assert_eq!(parsed.preferences[0].rail_kind, RailKind::X402);
        assert_eq!(parsed.preferences[1].rail_kind, RailKind::Mpp);
    }

    #[test]
    fn accept_payment_empty_header_yields_no_preferences() {
        let parsed = AcceptPayment::parse("").unwrap();
        assert!(parsed.preferences.is_empty());
        assert!(parsed.is_empty());
    }

    #[test]
    fn accept_payment_whitespace_only_yields_no_preferences() {
        let parsed = AcceptPayment::parse("   \t  ").unwrap();
        assert!(parsed.preferences.is_empty());
    }

    #[test]
    fn accept_payment_picks_intersection_of_available() {
        let parsed = AcceptPayment::parse("x402;q=1, mpp;q=0.9").unwrap();
        let available = vec![RailKind::Mpp, RailKind::X402];
        let picked = parsed.picks(&available);
        // Agent prefers x402 over mpp: x402 must lead.
        assert_eq!(picked, vec![RailKind::X402, RailKind::Mpp]);
    }

    #[test]
    fn accept_payment_picks_only_overlapping_rails() {
        let parsed = AcceptPayment::parse("x402, mpp").unwrap();
        let available = vec![RailKind::X402];
        let picked = parsed.picks(&available);
        assert_eq!(picked, vec![RailKind::X402]);
    }

    #[test]
    fn accept_payment_picks_empty_when_no_overlap() {
        let parsed = AcceptPayment::parse("lightning;q=1").unwrap();
        let available = vec![RailKind::X402, RailKind::Mpp];
        let picked = parsed.picks(&available);
        assert!(
            picked.is_empty(),
            "no overlap produces empty pick set; caller emits 406"
        );
    }

    #[test]
    fn accept_payment_picks_falls_back_to_available_when_no_preferences() {
        let parsed = AcceptPayment::parse("").unwrap();
        let available = vec![RailKind::X402, RailKind::Mpp];
        let picked = parsed.picks(&available);
        assert_eq!(picked, available);
    }

    #[test]
    fn accept_payment_unknown_kind_preserved() {
        let parsed = AcceptPayment::parse("x402;q=1, lightning;q=0.5").unwrap();
        assert_eq!(parsed.preferences.len(), 2);
        assert_eq!(parsed.preferences[0].rail_kind, RailKind::X402);
        assert_eq!(
            parsed.preferences[1].rail_kind,
            RailKind::Other("lightning".to_string())
        );
    }

    #[test]
    fn accept_payment_unknown_kind_lowercased() {
        let parsed = AcceptPayment::parse("LiGhTnInG;q=1").unwrap();
        assert_eq!(
            parsed.preferences[0].rail_kind,
            RailKind::Other("lightning".to_string())
        );
    }

    #[test]
    fn accept_payment_invalid_q_errors() {
        let err = AcceptPayment::parse("x402;q=2.0").unwrap_err();
        match err {
            ParseError::InvalidQ(_) => {}
            other => panic!("expected InvalidQ, got {other:?}"),
        }
    }

    #[test]
    fn accept_payment_non_numeric_q_errors() {
        let err = AcceptPayment::parse("x402;q=banana").unwrap_err();
        assert!(matches!(err, ParseError::InvalidQ(_)));
    }

    #[test]
    fn accept_payment_unknown_param_ignored() {
        // Future-compat: unknown params do not break parsing.
        let parsed = AcceptPayment::parse("x402;q=0.8;version=2").unwrap();
        assert_eq!(parsed.preferences.len(), 1);
        assert_eq!(parsed.preferences[0].rail_kind, RailKind::X402);
        assert!((parsed.preferences[0].q - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn rail_tokens_renders_in_preference_order() {
        let parsed = AcceptPayment::parse("mpp;q=0.5, x402;q=1.0").unwrap();
        let tokens = rail_tokens(&parsed);
        assert_eq!(tokens, vec!["x402".to_string(), "mpp".to_string()]);
    }

    #[test]
    fn picks_breaks_ties_with_operator_order() {
        // Both rails have q=1; operator listed mpp first.
        let parsed = AcceptPayment::parse("x402, mpp").unwrap();
        let available = vec![RailKind::Mpp, RailKind::X402];
        let picked = parsed.picks(&available);
        // Operator preference wins on equal q.
        assert_eq!(picked, vec![RailKind::Mpp, RailKind::X402]);
    }
}
