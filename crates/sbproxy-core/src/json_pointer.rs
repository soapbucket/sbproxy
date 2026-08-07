// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Resolve one RFC 6901 JSON Pointer against a request body without building
//! the document.
//!
//! Body-field routing runs on every request to an origin that declares a body
//! matcher, and it runs before the route is chosen, so it sits on the hottest
//! part of the request path. `serde_json::from_slice::<Value>` would allocate
//! the entire document to read one field out of it: for an LLM request that
//! means materializing every message in the conversation to look at `/model`.
//!
//! This module walks the pointer instead. At each level it reads keys until it
//! finds the one the pointer names and hands every other value to
//! [`serde::de::IgnoredAny`], which scans past a value without allocating it.
//! Reading `/model` out of a 60 KiB chat completion allocates the one short
//! string that `model` holds, plus the keys of the top-level object it walked
//! past on the way.
//!
//! The scan is deliberately exhaustive: each visitor drains its container
//! before returning even after it has found what it wanted. Returning early
//! would leave the parser part way through a value, and the enclosing visitor
//! would then resume reading in the middle of it. A full scan of a body that
//! is already capped at 64 KiB is much cheaper than that class of bug.

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

/// What a JSON Pointer resolved to.
///
/// The distinction matters because a container is *present* but is not
/// comparable to a configured string, so a `value:` or `prefix:` comparison
/// against one is a miss while a presence-only matcher against one is a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerTarget {
    /// A string, number, boolean, or null, rendered as text. Strings carry
    /// their unescaped contents; `true`, `false`, and `null` carry those
    /// words; numbers carry their decimal form.
    Scalar(String),
    /// An object or an array.
    Container,
}

/// Split an RFC 6901 JSON Pointer into its decoded reference tokens.
///
/// The empty pointer addresses the whole document and yields no tokens. Any
/// other pointer must start with `/`. `~1` decodes to `/` and `~0` decodes to
/// `~`, in that order, per RFC 6901 section 3.
///
/// # Errors
///
/// Returns an error when the pointer is non-empty and does not start with `/`.
pub fn compile_pointer(pointer: &str) -> anyhow::Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        anyhow::bail!(
            "JSON Pointer {pointer:?} must be empty or start with '/' (RFC 6901). \
             To address a top-level field named `model`, write `/model`."
        );
    };
    Ok(rest
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

/// Resolve `tokens` against `body`, which is expected to be a JSON document.
///
/// Returns `None` when the body is not JSON, does not parse, or does not carry
/// the addressed field. None of those is an error here: the caller treats an
/// unresolvable pointer as a matcher miss rather than a failed request.
#[must_use]
pub fn resolve(body: &[u8], tokens: &[String]) -> Option<PointerTarget> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    Seek { tokens }
        .deserialize(&mut deserializer)
        .ok()
        .flatten()
}

/// Seeks `tokens` through whatever value the deserializer is positioned on.
struct Seek<'t> {
    tokens: &'t [String],
}

impl<'de, 't> DeserializeSeed<'de> for Seek<'t> {
    type Value = Option<PointerTarget>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Seek {
            tokens: self.tokens,
        })
    }
}

impl<'de, 't> Visitor<'de> for Seek<'t> {
    type Value = Option<PointerTarget>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar(value.to_string()))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar(value.to_string()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar(value.to_string()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar(value.to_string()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar(value.to_string()))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(self.scalar("null".to_string()))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let Some((wanted, rest)) = self.tokens.split_first() else {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(Some(PointerTarget::Container));
        };
        let mut found = None;
        let mut taken = false;
        while let Some(key) = map.next_key::<String>()? {
            // First occurrence wins. A duplicate key later in the object does
            // not get a second chance to satisfy the pointer, so the answer
            // does not depend on how far the scan happens to have run.
            if !taken && key.as_str() == wanted.as_str() {
                taken = true;
                found = map.next_value_seed(Seek { tokens: rest })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let Some((wanted, rest)) = self.tokens.split_first() else {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(Some(PointerTarget::Container));
        };
        // A non-numeric token against an array cannot match. RFC 6901's `-`
        // (one past the end) has nothing to address on a read, so it lands
        // here too.
        let index = wanted.parse::<usize>().ok();
        let mut found = None;
        let mut position = 0usize;
        loop {
            if Some(position) == index {
                match seq.next_element_seed(Seek { tokens: rest })? {
                    Some(value) => found = value,
                    None => break,
                }
            } else if seq.next_element::<IgnoredAny>()?.is_none() {
                break;
            }
            position += 1;
        }
        Ok(found)
    }
}

impl Seek<'_> {
    /// A scalar satisfies the pointer only when nothing is left to walk.
    /// Tokens remaining means the pointer asked to descend into a string or a
    /// number, which no JSON document can satisfy.
    fn scalar(&self, rendered: String) -> Option<PointerTarget> {
        if self.tokens.is_empty() {
            Some(PointerTarget::Scalar(rendered))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_at(body: &str, pointer: &str) -> Option<String> {
        let tokens = compile_pointer(pointer).expect("pointer compiles");
        match resolve(body.as_bytes(), &tokens) {
            Some(PointerTarget::Scalar(text)) => Some(text),
            _ => None,
        }
    }

    #[test]
    fn a_top_level_string_field_resolves() {
        assert_eq!(
            scalar_at(r#"{"model":"gpt-4o","stream":false}"#, "/model"),
            Some("gpt-4o".to_string())
        );
    }

    #[test]
    fn a_field_after_a_large_skipped_array_still_resolves() {
        // The realistic LLM shape: `model` sits behind the whole
        // conversation. IgnoredAny has to scan past `messages` without
        // materializing it and still leave the parser on `model`.
        let messages: Vec<String> = (0..200)
            .map(|i| format!(r#"{{"role":"user","content":"turn {i}"}}"#))
            .collect();
        let body = format!(
            r#"{{"messages":[{}],"model":"claude-sonnet-4"}}"#,
            messages.join(",")
        );
        assert_eq!(
            scalar_at(&body, "/model"),
            Some("claude-sonnet-4".to_string())
        );
    }

    #[test]
    fn booleans_numbers_and_null_render_as_text() {
        let body = r#"{"stream":true,"n":3,"temperature":0.5,"seed":null}"#;
        assert_eq!(scalar_at(body, "/stream"), Some("true".to_string()));
        assert_eq!(scalar_at(body, "/n"), Some("3".to_string()));
        assert_eq!(scalar_at(body, "/temperature"), Some("0.5".to_string()));
        assert_eq!(scalar_at(body, "/seed"), Some("null".to_string()));
    }

    #[test]
    fn nested_and_indexed_tokens_walk_both_container_kinds() {
        let body = r#"{"messages":[{"role":"system"},{"role":"user"}],"a":{"b":{"c":"deep"}}}"#;
        assert_eq!(
            scalar_at(body, "/messages/1/role"),
            Some("user".to_string())
        );
        assert_eq!(scalar_at(body, "/a/b/c"), Some("deep".to_string()));
    }

    #[test]
    fn an_object_or_array_resolves_to_a_container_not_a_scalar() {
        let tokens = compile_pointer("/tools").expect("pointer compiles");
        assert_eq!(
            resolve(br#"{"tools":[{"name":"search"}]}"#, &tokens),
            Some(PointerTarget::Container)
        );
        let tokens = compile_pointer("/meta").expect("pointer compiles");
        assert_eq!(
            resolve(br#"{"meta":{"k":"v"}}"#, &tokens),
            Some(PointerTarget::Container)
        );
    }

    #[test]
    fn the_empty_pointer_addresses_the_whole_document() {
        let tokens = compile_pointer("").expect("the empty pointer compiles");
        assert!(tokens.is_empty());
        assert_eq!(
            resolve(br#"{"model":"gpt-4o"}"#, &tokens),
            Some(PointerTarget::Container)
        );
        assert_eq!(
            resolve(b"\"bare\"", &tokens),
            Some(PointerTarget::Scalar("bare".to_string()))
        );
    }

    #[test]
    fn a_missing_field_resolves_to_nothing() {
        assert_eq!(scalar_at(r#"{"model":"gpt-4o"}"#, "/provider"), None);
        assert_eq!(scalar_at(r#"{"a":{"b":1}}"#, "/a/z"), None);
        let body = r#"{"messages":[{"role":"user"}]}"#;
        assert_eq!(scalar_at(body, "/messages/9"), None);
    }

    #[test]
    fn descending_into_a_scalar_resolves_to_nothing() {
        assert_eq!(scalar_at(r#"{"model":"gpt-4o"}"#, "/model/name"), None);
    }

    #[test]
    fn a_non_numeric_token_against_an_array_resolves_to_nothing() {
        let body = r#"{"messages":[{"role":"user"}]}"#;
        assert_eq!(scalar_at(body, "/messages/first/role"), None);
        assert_eq!(scalar_at(r#"{"messages":[1,2]}"#, "/messages/-"), None);
    }

    #[test]
    fn non_json_and_malformed_bodies_resolve_to_nothing() {
        let tokens = compile_pointer("/model").expect("pointer compiles");
        assert_eq!(resolve(b"not json at all", &tokens), None);
        assert_eq!(resolve(b"", &tokens), None);
        assert_eq!(resolve(br#"{"model":"gpt-4o""#, &tokens), None);
        assert_eq!(resolve(b"<xml><model>gpt-4o</model></xml>", &tokens), None);
        assert_eq!(resolve(&[0xff, 0xfe, 0x00], &tokens), None);
    }

    #[test]
    fn the_first_occurrence_of_a_duplicate_key_wins() {
        assert_eq!(
            scalar_at(r#"{"model":"first","model":"second"}"#, "/model"),
            Some("first".to_string())
        );
    }

    #[test]
    fn escaped_tokens_decode_per_rfc_6901() {
        assert_eq!(compile_pointer("/a~1b").expect("compiles"), vec!["a/b"]);
        assert_eq!(compile_pointer("/m~0n").expect("compiles"), vec!["m~n"]);
        // `~01` decodes to `~1`, not to `/`, because the `~1` pass runs
        // first and so cannot see the `~1` that decoding `~0` produces.
        assert_eq!(compile_pointer("/~01").expect("compiles"), vec!["~1"]);
        assert_eq!(
            scalar_at(r#"{"a/b":"slashed"}"#, "/a~1b"),
            Some("slashed".to_string())
        );
    }

    #[test]
    fn a_pointer_without_a_leading_slash_is_refused() {
        let error = compile_pointer("model").expect_err("a bare field name is not a pointer");
        let message = format!("{error:#}");
        assert!(message.contains("RFC 6901"), "{message}");
        assert!(message.contains("/model"), "{message}");
    }
}
