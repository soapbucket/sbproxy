//! W3C Baggage header propagation.
//!
//! Implements parsing and formatting of the `baggage` header as defined by
//! the W3C Baggage specification (<https://www.w3.org/TR/baggage/>).
//!
//! Format: `baggage: key1=value1,key2=value2`

use std::collections::HashMap;

/// Parse a W3C `baggage` header value into a key/value map.
///
/// Each entry is a `key=value` pair separated by commas. Whitespace around
/// commas and around the `=` delimiter is trimmed. Entries that are missing
/// a `=` delimiter or have an empty key are silently skipped.
pub fn parse_baggage(header: &str) -> HashMap<String, String> {
    header
        .split(',')
        .filter_map(|pair| {
            let mut parts = pair.trim().splitn(2, '=');
            let key = parts.next()?.trim().to_string();
            let value = parts.next()?.trim().to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, value))
            }
        })
        .collect()
}

/// Format a key/value map into a W3C `baggage` header value.
///
/// Entries are joined with `,`. The output order is unspecified because
/// [`HashMap`] iteration order is non-deterministic.
pub fn format_baggage(baggage: &HashMap<String, String>) -> String {
    baggage
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // --- parse_baggage ---

    #[test]
    fn parse_single_entry() {
        let map = parse_baggage("userId=alice");
        assert_eq!(map.get("userId").map(String::as_str), Some("alice"));
    }

    #[test]
    fn parse_multiple_entries() {
        let map = parse_baggage("userId=alice,tenantId=acme");
        assert_eq!(map.get("userId").map(String::as_str), Some("alice"));
        assert_eq!(map.get("tenantId").map(String::as_str), Some("acme"));
    }

    #[test]
    fn parse_trims_whitespace() {
        let map = parse_baggage("  key1 = val1 , key2 = val2 ");
        assert_eq!(map.get("key1").map(String::as_str), Some("val1"));
        assert_eq!(map.get("key2").map(String::as_str), Some("val2"));
    }

    #[test]
    fn parse_empty_string_returns_empty_map() {
        let map = parse_baggage("");
        assert!(map.is_empty(), "empty input should produce empty map");
    }

    #[test]
    fn parse_entry_without_equals_is_skipped() {
        // "noequals" has no '=' so it should be dropped silently.
        let map = parse_baggage("noequals,key=value");
        assert!(!map.contains_key("noequals"));
        assert_eq!(map.get("key").map(String::as_str), Some("value"));
    }

    #[test]
    fn parse_empty_key_is_skipped() {
        let map = parse_baggage("=value,realkey=realval");
        assert!(!map.contains_key(""), "empty key must be skipped");
        assert_eq!(map.get("realkey").map(String::as_str), Some("realval"));
    }

    #[test]
    fn parse_value_may_contain_equals() {
        // Only splits on the first '=' so values may contain '='.
        let map = parse_baggage("token=abc=def");
        assert_eq!(map.get("token").map(String::as_str), Some("abc=def"));
    }

    // --- format_baggage ---

    #[test]
    fn format_empty_map_returns_empty_string() {
        let result = format_baggage(&HashMap::new());
        assert!(result.is_empty());
    }

    #[test]
    fn format_single_entry() {
        let mut map = HashMap::new();
        map.insert("userId".to_string(), "bob".to_string());
        let result = format_baggage(&map);
        assert_eq!(result, "userId=bob");
    }

    #[test]
    fn format_contains_all_entries() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), "1".to_string());
        map.insert("b".to_string(), "2".to_string());
        let result = format_baggage(&map);
        // Order is non-deterministic, so check that both pairs are present.
        assert!(result.contains("a=1"), "missing a=1 in: {result}");
        assert!(result.contains("b=2"), "missing b=2 in: {result}");
        assert!(result.contains(','), "entries must be comma-separated");
    }

    // --- roundtrip ---

    #[test]
    fn roundtrip_single_entry() {
        let original = "env=production";
        let parsed = parse_baggage(original);
        let formatted = format_baggage(&parsed);
        // Re-parse the formatted string and compare.
        let reparsed = parse_baggage(&formatted);
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn roundtrip_multiple_entries() {
        // Parse -> format -> parse again and check key/value equality.
        let original = "userId=alice,tenantId=acme,region=us-east-1";
        let parsed = parse_baggage(original);
        assert_eq!(parsed.len(), 3);

        let formatted = format_baggage(&parsed);
        let reparsed = parse_baggage(&formatted);
        assert_eq!(parsed, reparsed);
    }
}
