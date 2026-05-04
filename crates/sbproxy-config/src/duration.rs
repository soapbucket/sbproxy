//! Permissive duration deserializer for u64-seconds fields.
//!
//! TTL fields accept humanized durations (`60s`, `5m`, `1h`) as well
//! as bare integer seconds. A naive `u64` field would silently fail
//! to parse `"60s"` and serde would drop the whole enclosing block as
//! an untagged variant, leaving the feature disabled with no error.
//!
//! This module provides [`deserialize_secs`], a serde function that
//! accepts any of:
//!
//! | Input                        | Parsed as       |
//! |------------------------------|-----------------|
//! | `60` (integer)               | 60              |
//! | `"60"` (string)              | 60              |
//! | `"60s"`                      | 60              |
//! | `"5m"`                       | 300             |
//! | `"1h"`                       | 3600            |
//! | `"1d"`                       | 86400           |
//! | `"2h30m"` (compound)         | 9000            |
//!
//! Apply via `#[serde(deserialize_with = "deserialize_secs")]` on any
//! u64 field that represents a seconds-valued duration. The field still
//! serializes as an integer (we don't override Serialize).

use serde::de::{self, Deserializer, Unexpected, Visitor};
use std::fmt;

/// Deserialize a u64 seconds value, accepting integer or humanized string.
pub fn deserialize_secs<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    d.deserialize_any(DurationSecsVisitor)
}

struct DurationSecsVisitor;

impl<'de> Visitor<'de> for DurationSecsVisitor {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a non-negative integer, or a string like \"60\", \"30s\", \"5m\", \"2h30m\"")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
        Ok(v)
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<u64, E> {
        u64::try_from(v).map_err(|_| de::Error::invalid_value(Unexpected::Other("u128"), &self))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
        if v < 0 {
            return Err(de::Error::invalid_value(
                Unexpected::Signed(v),
                &"non-negative integer seconds",
            ));
        }
        Ok(v as u64)
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<u64, E> {
        if v < 0 || v > u64::MAX as i128 {
            return Err(de::Error::invalid_value(Unexpected::Other("i128"), &self));
        }
        Ok(v as u64)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<u64, E> {
        if v.is_nan() || v.is_sign_negative() || v > u64::MAX as f64 {
            return Err(de::Error::invalid_value(Unexpected::Float(v), &self));
        }
        Ok(v as u64)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
        parse_humanized(v)
            .map_err(|msg| de::Error::invalid_value(Unexpected::Str(v), &msg.as_str()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<u64, E> {
        self.visit_str(&v)
    }
}

/// Parse a string like "60s" / "5m" / "2h30m" / "60" into seconds.
///
/// Returns `Err(message)` (human readable) on any unparseable input.
fn parse_humanized(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".into());
    }
    // Bare integer (possibly with leading/trailing whitespace).
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    // Compound format: <num><unit>[<num><unit>...] where unit ∈ {s,m,h,d,w}.
    // Accumulate seconds across components.
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    let mut saw_any = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num_buf.push(c);
        } else if c.is_whitespace() {
            continue;
        } else {
            if num_buf.is_empty() {
                return Err(format!("unit '{c}' before any number in duration '{s}'"));
            }
            let n: u64 = num_buf
                .parse()
                .map_err(|_| format!("bad number '{num_buf}' in duration '{s}'"))?;
            let mult: u64 = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3_600,
                'd' => 86_400,
                'w' => 604_800,
                other => return Err(format!("unknown duration unit '{other}' in '{s}'")),
            };
            total_secs = total_secs
                .checked_add(
                    n.checked_mul(mult)
                        .ok_or_else(|| format!("duration overflow for '{num_buf}{c}' in '{s}'"))?,
                )
                .ok_or_else(|| format!("duration overflow summing '{s}'"))?;
            num_buf.clear();
            saw_any = true;
        }
    }
    if !num_buf.is_empty() {
        return Err(format!(
            "trailing number '{num_buf}' without unit in duration '{s}' (did you mean '{num_buf}s'?)"
        ));
    }
    if !saw_any {
        return Err(format!("no recognized unit found in duration '{s}'"));
    }
    Ok(total_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Sample {
        #[serde(deserialize_with = "deserialize_secs")]
        ttl_secs: u64,
    }

    fn parse(yaml: &str) -> u64 {
        serde_yaml::from_str::<Sample>(yaml)
            .expect("parse")
            .ttl_secs
    }

    #[test]
    fn bare_integer() {
        assert_eq!(parse("ttl_secs: 60"), 60);
    }

    #[test]
    fn quoted_integer_string() {
        assert_eq!(parse("ttl_secs: \"60\""), 60);
    }

    #[test]
    fn seconds_suffix() {
        assert_eq!(parse("ttl_secs: 60s"), 60);
        assert_eq!(parse("ttl_secs: \"60s\""), 60);
    }

    #[test]
    fn minutes_suffix() {
        assert_eq!(parse("ttl_secs: 5m"), 300);
    }

    #[test]
    fn hours_suffix() {
        assert_eq!(parse("ttl_secs: 2h"), 7_200);
    }

    #[test]
    fn days_and_weeks() {
        assert_eq!(parse("ttl_secs: 1d"), 86_400);
        assert_eq!(parse("ttl_secs: 1w"), 604_800);
    }

    #[test]
    fn compound_hours_and_minutes() {
        assert_eq!(parse("ttl_secs: 2h30m"), 9_000);
        assert_eq!(parse("ttl_secs: 1h30m45s"), 5_445);
    }

    #[test]
    fn case_insensitive_units() {
        assert_eq!(parse("ttl_secs: \"60S\""), 60);
        assert_eq!(parse("ttl_secs: \"1H\""), 3_600);
    }

    #[test]
    fn whitespace_tolerant() {
        assert_eq!(parse("ttl_secs: \"60 s\""), 60);
        assert_eq!(parse("ttl_secs: \"2h 30m\""), 9_000);
    }

    #[test]
    fn default_does_not_deserialize() {
        // Field is required; nothing to test for absence here.
        let err = serde_yaml::from_str::<Sample>("other: 1").expect_err("should fail");
        assert!(err.to_string().contains("ttl_secs"));
    }

    #[test]
    fn rejects_negative_number() {
        let err = serde_yaml::from_str::<Sample>("ttl_secs: -1").expect_err("negative rejected");
        assert!(err
            .to_string()
            .to_ascii_lowercase()
            .contains("non-negative"));
    }

    #[test]
    fn rejects_unknown_unit() {
        let err = serde_yaml::from_str::<Sample>("ttl_secs: 10y").expect_err("unknown unit y");
        assert!(err.to_string().contains("y"));
    }

    #[test]
    fn rejects_trailing_bare_number() {
        let err = serde_yaml::from_str::<Sample>("ttl_secs: 10s20").expect_err("trailing number");
        assert!(err.to_string().to_ascii_lowercase().contains("trailing"));
    }

    #[test]
    fn float_rounds_down() {
        assert_eq!(parse("ttl_secs: 60.9"), 60);
    }

    #[test]
    fn zero_is_allowed() {
        assert_eq!(parse("ttl_secs: 0"), 0);
        assert_eq!(parse("ttl_secs: 0s"), 0);
    }
}
