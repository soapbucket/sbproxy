//! Small, dependency-free helpers shared across the workspace.
//!
//! These are pure functions that were previously copy-pasted into several
//! crates and had already drifted apart (four duration parsers accepting
//! different unit sets, six UTF-8 truncations with different tight-cap
//! behavior). Consolidating them here (WOR-1705) gives each family exactly
//! one implementation. The crate is a true leaf: it depends on `std` only,
//! so any crate may depend on it without introducing a cycle.

#![deny(missing_docs)]

use std::borrow::Cow;
use std::time::Duration;

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Accepts the union of every unit set the workspace previously used:
///
/// - a bare number, interpreted as seconds (`"90"` -> 90s, `"1.5"` -> 1.5s);
/// - one or more `<number><unit>` tokens, where the number may be a decimal
///   and units are `ms`, `s`, `m`, `h`, `d`;
/// - compound forms, summed left to right (`"1h30m"` -> 5400s).
///
/// Returns `Err` on an empty string, a bad number, a missing or unknown
/// unit, a negative value, or a value large enough to overflow `Duration`
/// (the last two are rejected rather than allowed to panic
/// [`Duration::from_secs_f64`]).
///
/// ```
/// use std::time::Duration;
/// use sbproxy_util::parse_duration;
/// assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
/// assert!(parse_duration("10 hrs").is_err());
/// ```
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    // A bare number (no unit) is seconds. Accepts integer or decimal.
    if let Ok(secs) = s.parse::<f64>() {
        return duration_from_secs_f64(secs, s);
    }

    // Otherwise: one or more `<number><unit>` tokens, summed.
    let mut total_secs = 0.0f64;
    let mut rest = s;
    let mut saw_token = false;
    while !rest.is_empty() {
        let num_end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(format!("invalid duration '{s}': expected a number"));
        }
        let num: f64 = rest[..num_end]
            .parse()
            .map_err(|e| format!("invalid duration number in '{s}': {e}"))?;
        rest = &rest[num_end..];

        let unit_end = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        let mult = match unit {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            "" => {
                return Err(format!(
                    "invalid duration '{s}': number '{num}' has no unit (use ms, s, m, h, d)"
                ))
            }
            other => {
                return Err(format!(
                    "unsupported duration unit '{other}' in '{s}' (use ms, s, m, h, d)"
                ))
            }
        };
        total_secs += num * mult;
        rest = &rest[unit_end..];
        saw_token = true;
    }

    if !saw_token {
        return Err(format!("invalid duration '{s}'"));
    }
    duration_from_secs_f64(total_secs, s)
}

/// Convert seconds to a [`Duration`], rejecting the inputs that would panic
/// [`Duration::from_secs_f64`] (negative, non-finite, or overflowing).
fn duration_from_secs_f64(secs: f64, original: &str) -> Result<Duration, String> {
    if !secs.is_finite() {
        return Err(format!("invalid duration '{original}'"));
    }
    if secs < 0.0 {
        return Err(format!("negative duration '{original}'"));
    }
    if secs >= u64::MAX as f64 {
        return Err(format!("duration '{original}' is too large"));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// Match `value` against a simple prefix glob `pattern`.
///
/// A trailing `*` makes the rest a prefix (`"gh.*"` matches `"gh.search"`);
/// any other pattern must equal `value` exactly. This is the byte-identical
/// semantics of the four copies it replaces; it is deliberately not a full
/// glob (see `sbproxy-modules` `auth::cap` and `sbproxy-config` `plan` for
/// the backtracking and dot-segment matchers, which stay separate).
///
/// ```
/// use sbproxy_util::prefix_glob_match;
/// assert!(prefix_glob_match("gh.*", "gh.search"));
/// assert!(prefix_glob_match("search", "search"));
/// assert!(!prefix_glob_match("search", "search_repos"));
/// ```
pub fn prefix_glob_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

/// Truncate `s` to at most `max_bytes`, floored to a UTF-8 char boundary.
///
/// Never splits a multi-byte character and never panics: a `max_bytes`
/// smaller than the first character yields `""`. Returns a borrow of `s`.
///
/// ```
/// use sbproxy_util::truncate_utf8;
/// assert_eq!(truncate_utf8("hello", 3), "hel");
/// assert_eq!(truncate_utf8("héllo", 2), "h"); // 'é' is 2 bytes, would split
/// ```
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Truncate `s` to at most `max_bytes` total, appending `marker` when the
/// string was actually shortened.
///
/// The returned string is always at most `max_bytes` bytes: the marker's
/// length is reserved from the budget, and if the marker alone does not fit
/// a boundary-safe prefix of the marker is returned. Borrows `s` when it
/// already fits, so the common short-input case allocates nothing.
///
/// ```
/// use sbproxy_util::truncate_utf8_with_marker;
/// assert_eq!(truncate_utf8_with_marker("hello world", 8, "..."), "hello...");
/// assert_eq!(truncate_utf8_with_marker("hi", 8, "..."), "hi"); // fits, borrowed
/// ```
pub fn truncate_utf8_with_marker<'a>(s: &'a str, max_bytes: usize, marker: &str) -> Cow<'a, str> {
    if s.len() <= max_bytes {
        return Cow::Borrowed(s);
    }
    if marker.len() >= max_bytes {
        return Cow::Owned(truncate_utf8(marker, max_bytes).to_string());
    }
    let budget = max_bytes - marker.len();
    let head = truncate_utf8(s, budget);
    let mut out = String::with_capacity(head.len() + marker.len());
    out.push_str(head);
    out.push_str(marker);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_units_and_compound() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        // Decimal (previously accepted only by the peer-pricing copy).
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        // Whitespace is trimmed.
        assert_eq!(parse_duration("  30s  ").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn duration_rejects_garbage() {
        for bad in [
            "", "   ", "abc", "1h30", "10x", "m", "10 hrs", "5y", "inf", "NaN",
        ] {
            assert!(parse_duration(bad).is_err(), "expected err for {bad:?}");
        }
    }

    #[test]
    fn duration_rejects_overflow_and_negative() {
        assert!(parse_duration("-5").is_err());
        assert!(parse_duration("1e40").is_err());
    }

    #[test]
    fn glob_semantics() {
        assert!(prefix_glob_match("gh.*", "gh.search"));
        assert!(prefix_glob_match("search", "search"));
        assert!(!prefix_glob_match("gh.*", "db.query"));
        assert!(!prefix_glob_match("search", "search_repos"));
        assert!(prefix_glob_match("/a/*", "/a/"));
        assert!(prefix_glob_match("/a/*", "/a/b/c"));
        assert!(!prefix_glob_match("/a", "/a/"));
        assert!(!prefix_glob_match("/a/*", "/b"));
        // A bare "*" matches everything (prefix "").
        assert!(prefix_glob_match("*", "anything"));
    }

    #[test]
    fn truncate_keeps_utf8_boundary() {
        assert_eq!(truncate_utf8("hello", 3), "hel");
        assert_eq!(truncate_utf8("hello", 10), "hello");
        // 'é' is two bytes: a cap of 2 that would split it floors to "h".
        assert_eq!(truncate_utf8("héllo", 2), "h");
        // Cap smaller than the first char yields "".
        assert_eq!(truncate_utf8("é", 1), "");
    }

    #[test]
    fn truncate_with_marker_bounds_and_borrows() {
        // Fits: borrowed, no marker.
        assert!(matches!(
            truncate_utf8_with_marker("hi", 8, "..."),
            Cow::Borrowed("hi")
        ));
        // Truncated: ends with the marker and stays within the cap.
        let out = truncate_utf8_with_marker("hello world", 8, "...");
        assert_eq!(out, "hello...");
        assert!(out.len() <= 8);
        // Cap smaller than the marker: boundary-safe prefix of the marker.
        let out = truncate_utf8_with_marker("hello world", 2, "...");
        assert!(out.len() <= 2);
        // Multi-byte content never splits.
        let out = truncate_utf8_with_marker("héllo wörld", 6, "..");
        assert!(out.len() <= 6);
        assert!(out.is_char_boundary(out.len()));
    }
}
