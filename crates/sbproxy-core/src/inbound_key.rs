//! Extraction of a minted virtual key from inbound request headers.
//!
//! Pure and synchronous: this decides *which* header carries a token and what
//! that token is, and does no store I/O. Resolution against the key plane
//! happens in the caller. Kept out of `request_phase.rs` so the ordering,
//! scheme-stripping, and ambiguity rules are testable without a `Session`.
//!
//! The header a key arrives in belongs to the calling tool, not to the key: an
//! Anthropic SDK sends `x-api-key`, Azure sends `api-key`, and an internal tool
//! sends whatever its author picked. Sweeping a configured list is what lets a
//! minted key be presented by a tool nobody is going to rewrite.

use sbproxy_config::types::KeyInboundConfig;

/// Values scanned per header name before the rest are ignored.
///
/// A request may legally repeat a header. Bounding the scan keeps a
/// pathological request carrying thousands of `authorization` lines from
/// turning the sweep into a denial of service.
pub const MAX_VALUES_PER_HEADER: usize = 8;

/// What the sweep found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// No candidate header carried a well-shaped token. The caller falls
    /// through to the origin's configured auth provider.
    None,
    /// Exactly one distinct token was present.
    Found {
        /// Lowercase name of the header it came from. The caller strips this
        /// header before the request goes upstream, so the proxy's own key
        /// never reaches an origin.
        header: String,
        /// The token, scheme prefix already removed.
        token: String,
    },
    /// Two candidate headers carried different well-shaped tokens. The caller
    /// denies rather than letting configuration order silently pick one.
    Ambiguous,
}

/// Sweep `headers` for a minted token, in the order `cfg.headers` lists.
///
/// The first well-shaped token wins. Scanning continues across the remaining
/// configured headers only to detect a conflicting second token; an identical
/// repeat is not a conflict, because clients commonly set both `authorization`
/// and a vendor header defensively.
pub fn sweep_headers(headers: &http::HeaderMap, cfg: &KeyInboundConfig) -> SweepOutcome {
    let mut found: Option<(String, String)> = None;

    for entry in &cfg.headers {
        let lower = entry.name.trim().to_ascii_lowercase();
        let Ok(name) = http::header::HeaderName::from_bytes(lower.as_bytes()) else {
            // Rejected at config load; skip rather than panic on a hand-built
            // config in a test.
            continue;
        };
        for raw in headers.get_all(&name).iter().take(MAX_VALUES_PER_HEADER) {
            let Ok(value) = raw.to_str() else {
                // Not UTF-8, so it cannot be one of our ASCII tokens.
                continue;
            };
            let value = value.trim();
            let candidate = if entry.scheme.is_empty() {
                value
            } else {
                match strip_scheme(value, &entry.scheme) {
                    Some(rest) => rest,
                    None => continue,
                }
            };
            if sbproxy_keystore::crypto::parse_minted_token(candidate).is_none() {
                continue;
            }
            match &found {
                None => found = Some((lower.clone(), candidate.to_string())),
                // The same token in two headers is one intent, not a conflict.
                Some((_, existing)) if existing == candidate => {}
                Some(_) => return SweepOutcome::Ambiguous,
            }
        }
    }

    match found {
        Some((header, token)) => SweepOutcome::Found { header, token },
        None => SweepOutcome::None,
    }
}

/// Whether a request that produced [`SweepOutcome::None`] must be refused.
///
/// Off by default, so turning the sweep on changes nothing for an existing
/// route: a request with no minted key falls through to whatever auth the
/// origin already configured. Enabling it makes the proxy the only door on an
/// origin that has no other auth provider, where the default would otherwise
/// admit unauthenticated traffic.
pub fn requires_minted_key(cfg: &KeyInboundConfig) -> bool {
    cfg.require
}

/// Strip `scheme` from the front of `value`, case-insensitively, returning the
/// remainder trimmed.
///
/// `None` when the value does not carry the scheme, which is how `Basic ...`
/// is skipped on a `Bearer`-configured header.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let head = value.get(..scheme.len())?;
    if head.eq_ignore_ascii_case(scheme) {
        Some(value[scheme.len()..].trim_start())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::{InboundHeaderConfig, KeyInboundConfig};

    fn token() -> String {
        format!("sbp_{}_{}", "0".repeat(16), "a".repeat(64))
    }

    fn other_token() -> String {
        format!("sbp_{}_{}", "1".repeat(16), "b".repeat(64))
    }

    fn cfg() -> KeyInboundConfig {
        KeyInboundConfig::default()
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn finds_a_token_in_a_raw_value_header() {
        let h = headers(&[("x-api-key", &token())]);
        match sweep_headers(&h, &cfg()) {
            SweepOutcome::Found { header, token: t } => {
                assert_eq!(header, "x-api-key");
                assert_eq!(t, token());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn strips_the_scheme_case_insensitively() {
        for prefix in ["Bearer ", "bearer ", "BEARER "] {
            let h = headers(&[("authorization", &format!("{prefix}{}", token()))]);
            assert!(
                matches!(sweep_headers(&h, &cfg()), SweepOutcome::Found { .. }),
                "{prefix:?} must be stripped"
            );
        }
    }

    #[test]
    fn ignores_a_mismatched_scheme() {
        let h = headers(&[("authorization", &format!("Basic {}", token()))]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }

    #[test]
    fn scans_every_value_of_a_repeated_header() {
        let h = headers(&[("x-api-key", "not-a-token"), ("x-api-key", &token())]);
        assert!(matches!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::Found { .. }
        ));
    }

    #[test]
    fn caps_the_values_scanned_per_header() {
        let mut pairs: Vec<(&str, &str)> = vec![("x-api-key", "filler"); MAX_VALUES_PER_HEADER];
        let t = token();
        pairs.push(("x-api-key", t.as_str()));
        let h = headers(&pairs);
        assert_eq!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::None,
            "a token past the cap is not scanned"
        );
    }

    #[test]
    fn two_different_tokens_are_ambiguous() {
        let h = headers(&[("x-api-key", &token()), ("x-sb-api", &other_token())]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::Ambiguous);
    }

    #[test]
    fn the_same_token_in_two_headers_resolves() {
        let h = headers(&[("x-api-key", &token()), ("x-sb-api", &token())]);
        assert!(matches!(
            sweep_headers(&h, &cfg()),
            SweepOutcome::Found { .. }
        ));
    }

    #[test]
    fn trims_padding_and_ignores_empty_values() {
        let padded = headers(&[("x-api-key", &format!("  {}  ", token()))]);
        assert!(matches!(
            sweep_headers(&padded, &cfg()),
            SweepOutcome::Found { .. }
        ));
        assert_eq!(
            sweep_headers(&headers(&[("x-api-key", "   ")]), &cfg()),
            SweepOutcome::None
        );
    }

    #[test]
    fn a_provider_key_is_not_a_candidate() {
        // The whole point of the sbp_ prefix: sweeping x-api-key must not
        // mistake a caller's real Anthropic key for one of ours.
        let h = headers(&[("x-api-key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz")]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }

    #[test]
    fn an_empty_header_list_disables_the_sweep() {
        let h = headers(&[("x-api-key", &token())]);
        let off = KeyInboundConfig {
            headers: vec![],
            require: false,
        };
        assert_eq!(sweep_headers(&h, &off), SweepOutcome::None);
    }

    #[test]
    fn sweep_order_follows_configuration_not_arrival() {
        let t = token();
        let h = headers(&[("x-sb-api", &t), ("x-api-key", &t)]);
        let ordered = KeyInboundConfig {
            headers: vec![
                InboundHeaderConfig {
                    name: "x-sb-api".into(),
                    scheme: String::new(),
                },
                InboundHeaderConfig {
                    name: "x-api-key".into(),
                    scheme: String::new(),
                },
            ],
            require: false,
        };
        match sweep_headers(&h, &ordered) {
            SweepOutcome::Found { header, .. } => assert_eq!(header, "x-sb-api"),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn a_short_value_does_not_panic_on_the_scheme_slice() {
        // `strip_scheme` slices by the scheme's byte length; a value shorter
        // than that, or one whose boundary is mid-codepoint, must return None.
        let h = headers(&[("authorization", "Be"), ("x-api-key", "é")]);
        assert_eq!(sweep_headers(&h, &cfg()), SweepOutcome::None);
    }
}
