// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Build-time coverage for configuration keys.
//!
//! The generated JSON Schema is the authoritative list of accepted key paths.
//! This module walks that schema, then looks for a production Rust field read
//! for every path. Keys consumed indirectly through generic deserialization
//! may use a reviewed stable override; deliberately inert keys use a
//! `ConfigOnly` override with an operator-facing reason.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::scan::SourceFile;
use crate::{validate_config_keys, ConfigKeyCapability, RegistryError, SupportLevel};

/// One named key reached from the root of the generated configuration schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigSchemaKey {
    /// Canonical dotted path. Dynamic map keys use `*`; array elements use
    /// `[]`, for example `origins.*.routes[].path`.
    pub path: String,
    /// Best-effort Rust field name derived from the serialized property.
    pub rust_field: String,
}

/// Walk a generated JSON Schema and return every named property reachable
/// from its root.
///
/// Local references, object maps, arrays, and schema compositions are
/// followed. Definitions are not listed on their own: a definition contributes
/// keys only when the root configuration actually references it.
pub fn schema_key_paths(schema: &Value) -> Vec<ConfigSchemaKey> {
    let mut out = BTreeSet::new();
    let mut refs = Vec::new();
    collect_schema(schema, schema, "", &mut refs, &mut out);
    out.into_iter().collect()
}

fn collect_schema(
    root: &Value,
    node: &Value,
    path: &str,
    refs: &mut Vec<String>,
    out: &mut BTreeSet<ConfigSchemaKey>,
) {
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        if refs.iter().any(|active| active == reference) {
            return;
        }
        if let Some(target) = local_ref(root, reference) {
            refs.push(reference.to_string());
            collect_schema(root, target, path, refs, out);
            refs.pop();
        }
    }

    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(parts) = node.get(keyword).and_then(Value::as_array) {
            for part in parts {
                collect_schema(root, part, path, refs, out);
            }
        }
    }
    for keyword in ["if", "then", "else", "not"] {
        if let Some(part) = node.get(keyword) {
            collect_schema(root, part, path, refs, out);
        }
    }

    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            let child_path = join_path(path, name);
            out.insert(ConfigSchemaKey {
                path: child_path.clone(),
                rust_field: rust_field_name(name),
            });
            collect_schema(root, child, &child_path, refs, out);
        }
    }

    if let Some(items) = node.get("items") {
        let item_path = format!("{path}[]");
        match items {
            Value::Array(variants) => {
                for variant in variants {
                    collect_schema(root, variant, &item_path, refs, out);
                }
            }
            _ => collect_schema(root, items, &item_path, refs, out),
        }
    }

    if let Some(additional) = node.get("additionalProperties") {
        if additional.is_object() {
            let value_path = if path.is_empty() {
                "*".to_string()
            } else {
                format!("{path}.*")
            };
            collect_schema(root, additional, &value_path, refs, out);
        }
    }

    if let Some(patterns) = node.get("patternProperties").and_then(Value::as_object) {
        let value_path = if path.is_empty() {
            "*".to_string()
        } else {
            format!("{path}.*")
        };
        for child in patterns.values() {
            collect_schema(root, child, &value_path, refs, out);
        }
    }
}

fn local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let fragment = reference.strip_prefix('#')?;
    if fragment.is_empty() {
        return Some(root);
    }
    root.pointer(fragment)
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}.{name}")
    }
}

fn rust_field_name(serialized: &str) -> String {
    serialized.replace('-', "_")
}

/// Verify that every schema key has either a production field read or a
/// reviewed override.
///
/// A stable override names an indirect consumer that source scanning cannot
/// see (for example, a serde discriminator or a flattened config handed to a
/// plugin). A `ConfigOnly` override names a deliberately inert key and owes
/// the operator a reason. Overrides are checked in both directions so a
/// removed or renamed schema path cannot leave stale policy behind.
pub fn verify_config_readers(
    keys: &[ConfigSchemaKey],
    overrides: &[ConfigKeyCapability],
    sources: &[SourceFile],
) -> Vec<RegistryError> {
    let mut errors = validate_config_keys(overrides);
    let declared: BTreeSet<&str> = keys.iter().map(|key| key.path.as_str()).collect();
    let override_index: BTreeMap<&str, &ConfigKeyCapability> =
        overrides.iter().map(|entry| (entry.path, entry)).collect();

    for entry in overrides {
        if !declared.contains(entry.path) {
            errors.push(RegistryError {
                subject: entry.path.to_string(),
                message: "has a config-reader override but is not present in the generated schema"
                    .to_string(),
            });
        }
        if entry.support == SupportLevel::ConfigOnly && entry.consumer.is_some() {
            errors.push(RegistryError {
                subject: entry.path.to_string(),
                message: "is config_only and must not name a live consumer".to_string(),
            });
        }
    }

    let cleaned: Vec<(&SourceFile, String)> = sources
        .iter()
        .map(|source| (source, production_tokens(&source.text)))
        .collect();

    for key in keys {
        if override_index
            .keys()
            .any(|root| path_is_in_subtree(&key.path, root))
        {
            continue;
        }
        if !has_field_read(&key.rust_field, &cleaned) {
            errors.push(RegistryError {
                subject: key.path.clone(),
                message: format!(
                    "is accepted by the generated schema but no non-test Rust read of `.{}` \
                     exists. Wire the key, or add a reviewed ConfigOnly override with a reason",
                    key.rust_field
                ),
            });
        }
    }

    errors
}

fn path_is_in_subtree(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('.') || suffix.starts_with("[]"))
}

fn has_field_read(field: &str, sources: &[(&SourceFile, String)]) -> bool {
    let candidates = [
        format!(".{field}"),
        format!(".r#{field}"),
        format!(".{field}_"),
    ];
    sources.iter().any(|(_, text)| {
        candidates
            .iter()
            .any(|needle| token_count(text, needle) > 0)
    })
}

fn production_tokens(source: &str) -> String {
    blank_strings(&strip_comments(source))
}

fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(source, i),
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out[i] = b' ';
                if i + 1 < out.len() {
                    out[i + 1] = b' ';
                }
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    out[i] = b' ';
                    i += 1;
                }
                if i < out.len() {
                    out[i] = b' ';
                }
                if i + 1 < out.len() {
                    out[i + 1] = b' ';
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

fn blank_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let end = skip_string(source, i);
            for byte in out.iter_mut().take(end).skip(i) {
                *byte = b' ';
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

fn skip_string(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn token_count(haystack: &str, needle: &str) -> usize {
    fn ident(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    let check_after = needle.as_bytes().last().is_some_and(|byte| ident(*byte));
    let bytes = haystack.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(found) = haystack[from..].find(needle) {
        let at = from + found;
        let end = at + needle.len();
        let after_ok = !check_after || end >= bytes.len() || !ident(bytes[end]);
        if after_ok {
            count += 1;
        }
        from = end;
    }
    count
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn source(text: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from("crates/example/src/lib.rs"),
            text: crate::scan::strip_test_regions(text),
        }
    }

    fn key(path: &str, field: &str) -> ConfigSchemaKey {
        ConfigSchemaKey {
            path: path.to_string(),
            rust_field: field.to_string(),
        }
    }

    #[test]
    fn schema_walk_follows_refs_arrays_maps_and_nested_objects() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "proxy": {"$ref": "#/definitions/Proxy"},
                "origins": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/definitions/Origin"}
                }
            },
            "definitions": {
                "Proxy": {
                    "type": "object",
                    "properties": {
                        "live-key": {"type": "boolean"},
                        "nested": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}}
                        },
                        "routes": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/Route"}
                        }
                    }
                },
                "Origin": {
                    "allOf": [{
                        "type": "object",
                        "properties": {"enabled": {"type": "boolean"}}
                    }]
                },
                "Route": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}}
                }
            }
        });

        let paths: BTreeMap<String, String> = schema_key_paths(&schema)
            .into_iter()
            .map(|key| (key.path, key.rust_field))
            .collect();

        assert_eq!(paths.get("proxy"), Some(&"proxy".to_string()));
        assert_eq!(paths.get("proxy.live-key"), Some(&"live_key".to_string()));
        assert!(paths.contains_key("proxy.nested.value"));
        assert!(paths.contains_key("proxy.routes[].path"));
        assert!(paths.contains_key("origins.*.enabled"));
    }

    #[test]
    fn unread_schema_key_fails_and_names_the_key() {
        let keys = [key("proxy.live", "live"), key("proxy.unread", "unread")];
        let sources = [source(
            r#"
pub fn production(config: &Config) {
    consume(config.live);
}

#[cfg(test)]
mod tests {
    fn only_test_reads(config: &Config) { consume(config.unread); }
}
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].subject, "proxy.unread");
        assert!(errors[0].message.contains("no non-test Rust read"));
    }

    #[test]
    fn config_only_override_with_reason_allows_an_unread_key() {
        let keys = [key("proxy.unread", "unread")];
        let override_entry = ConfigKeyCapability {
            path: "proxy.unread",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("reserved and rejected until WOR-9999"),
        };

        assert_eq!(verify_config_readers(&keys, &[override_entry], &[]), vec![]);
    }

    #[test]
    fn reviewed_parent_override_covers_its_schema_subtree() {
        let keys = [
            key("proxy.reserved", "reserved"),
            key("proxy.reserved.enabled", "enabled"),
            key("proxy.reserved.nested.value", "value"),
        ];
        let override_entry = ConfigKeyCapability {
            path: "proxy.reserved",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("reserved until WOR-9999"),
        };

        assert_eq!(verify_config_readers(&keys, &[override_entry], &[]), vec![]);
    }

    #[test]
    fn stale_override_fails_after_a_schema_key_is_removed() {
        let override_entry = ConfigKeyCapability {
            path: "proxy.removed",
            support: SupportLevel::ConfigOnly,
            consumer: None,
            note: Some("removed after WOR-9999"),
        };

        let errors = verify_config_readers(&[], &[override_entry], &[]);

        assert!(errors
            .iter()
            .any(|error| error.message.contains("not present")));
    }

    #[test]
    fn comments_and_strings_do_not_fake_a_reader() {
        let keys = [key("proxy.unread", "unread")];
        let sources = [source(
            r#"
// config.unread is intentionally absent.
const DOC: &str = "config.unread";
"#,
        )];

        let errors = verify_config_readers(&keys, &[], &sources);

        assert_eq!(errors.len(), 1, "{errors:?}");
    }
}
